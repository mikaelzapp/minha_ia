"""Histórico e reversão de escritas aprovadas; não desfaz comandos arbitrários."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictBool

from .memory import redact_secrets
from .tools import MAX_FILE, ToolError, Tools


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_HISTORY_BYTES = 64 * 1024 * 1024
MAX_HISTORY_RECORDS = 1000
_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


class HistoryError(ValueError):
    def __init__(self, message, code="developer_history_error", status_code=400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.source = "developer_history"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _redact(text):
    return redact_secrets(str(text))


class DeveloperHistory:
    """Snapshots locais privados, com transações e validação de integridade.

    execute_write só deve ser chamado após a aprovação original da escrita.
    restore só deve ser chamado após aprovação humana do preview congelado.
    """

    def __init__(self, data_dir):
        self.root = Path(os.path.abspath(data_dir)) / "developer"
        self.path = self.root / "history.sqlite3"
        with _LOCKS_GUARD:
            self.lock = _LOCKS.setdefault(os.path.normcase(str(self.path)), threading.RLock())
        with self.lock:
            self._guard()
            self.root.mkdir(parents=True, exist_ok=True)
            self._guard()
            with self.connection() as db:
                db.execute("""CREATE TABLE IF NOT EXISTS changes (
                    id TEXT PRIMARY KEY, root_id TEXT, root_key TEXT NOT NULL, path TEXT NOT NULL,
                    before_data BLOB NOT NULL, after_data BLOB NOT NULL,
                    before_sha256 TEXT NOT NULL, after_sha256 TEXT NOT NULL,
                    before_exists INTEGER NOT NULL, after_exists INTEGER NOT NULL,
                    status TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL,
                    applied_at TEXT, restored_at TEXT, restore_of TEXT)""")

    @staticmethod
    def _link(path):
        try:
            return Tools._is_link(path)
        except FileNotFoundError:
            return False

    def _guard(self):
        for path in (self.root, *self.root.parents):
            if self._link(path):
                raise HistoryError("O histórico precisa de uma pasta local sem links ou junctions.", "history_storage_unsafe")
        for path in (self.path, *(Path(str(self.path) + suffix) for suffix in ("-journal", "-wal", "-shm"))):
            if self._link(path):
                raise HistoryError("Links e hardlinks no histórico não são permitidos.", "history_storage_unsafe")
            if path.exists() and (not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > MAX_HISTORY_BYTES + 16 * 1024 * 1024):
                raise HistoryError("Arquivo de histórico inválido ou grande demais.", "history_storage_unsafe")

    @contextmanager
    def connection(self):
        with self.lock:
            self._guard()
            db = sqlite3.connect(self.path, timeout=15)
            db.row_factory = sqlite3.Row
            try:
                db.execute("PRAGMA trusted_schema=OFF")
                with db:
                    yield db
            finally:
                db.close()

    @staticmethod
    def _root_key(tools):
        if not isinstance(tools, Tools):
            raise HistoryError("O executor deve fornecer uma raiz de arquivos validada.", "history_executor_invalid")
        for parent in (tools.root, *tools.root.parents):
            if Tools._is_link(parent):
                raise HistoryError("A raiz autorizada mudou ou contém um link.", "history_root_changed", 409)
        return _sha(os.path.normcase(str(tools.root)).encode("utf-8"))

    @staticmethod
    def _snapshot(tools, relative):
        target = tools._path(relative, exists=False)
        if not target.exists():
            return target, False, b""
        before = target.stat()
        content = tools._read_bytes(target)
        after = target.stat()
        if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1 or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise HistoryError("O arquivo mudou durante a leitura do snapshot.", "history_file_changed", 409)
        if b"\x00" in content:
            raise HistoryError("Histórico de escrita aceita somente texto UTF-8.")
        try:
            content.decode("utf-8")
        except UnicodeError as exc:
            raise HistoryError("O snapshot precisa ser texto UTF-8.") from exc
        return target, True, content

    def _prepare(self, tools, relative, before, after, before_exists, after_exists, root_id, restore_of=None):
        if root_id is not None and (not isinstance(root_id, str) or not re.fullmatch(r"[a-f0-9]{16}", root_id)):
            raise HistoryError("Identificador de pasta autorizada inválido.")
        root_key = self._root_key(tools)
        identity = uuid.uuid4().hex
        now = _now()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            count, size = db.execute("SELECT count(*), coalesce(sum(length(before_data)+length(after_data)),0) FROM changes").fetchone()
            if count >= MAX_HISTORY_RECORDS or size + len(before) + len(after) > MAX_HISTORY_BYTES:
                raise HistoryError("Histórico atingiu o limite local. Nenhum arquivo foi alterado.", "history_storage_limit", 409)
            db.execute("INSERT INTO changes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', '', ?, NULL, NULL, ?)",
                       (identity, root_id, root_key, relative, before, after, _sha(before), _sha(after),
                        int(before_exists), int(after_exists), now, restore_of))
        return identity

    def _finish(self, identity, status, note=""):
        with self.connection() as db:
            db.execute("UPDATE changes SET status=?, note=?, applied_at=? WHERE id=? AND status='prepared'",
                       (status, _redact(note)[:1000], _now() if status == "applied" else None, identity))

    def execute_write(self, tools, args, root_id=None):
        """Captura antes de chamar write_file; não fecha o executor pertencente ao chat."""
        identity = None
        try:
            with self.lock:
                arguments = tools._arguments("write_file", args)
                relative = arguments["path"]
                # O mesmo validador da escrita verifica conteúdo, caminho e CAS.
                tools._prepare_write(**arguments)
                _, before_exists, before = self._snapshot(tools, relative)
                if arguments.get("expected_sha256") is not None and arguments["expected_sha256"] != _sha(before):
                    raise HistoryError("O arquivo mudou após o diff aprovado. Revise uma nova proposta.", "history_file_changed", 409)
                after = arguments["content"].encode("utf-8")
                identity = self._prepare(tools, relative, before, after, before_exists, True, root_id)
                arguments["expected_sha256"] = _sha(before)
                result = tools.execute("write_file", arguments)
                if result.get("ok"):
                    _, exists, actual = self._snapshot(tools, relative)
                    if not exists or actual != after:
                        raise HistoryError("A escrita retornou sucesso, mas o conteúdo mudou antes da conferência.", "history_file_changed", 409)
                    self._finish(identity, "applied")
                else:
                    self._finish(identity, "failed", result.get("error", "A ferramenta não confirmou a escrita."))
                return {**result, "change_id": identity}
        except (ValueError, OSError, sqlite3.DatabaseError) as exc:
            if identity:
                try:
                    self._finish(identity, "failed", str(exc))
                except (ValueError, OSError, sqlite3.DatabaseError):
                    pass  # Um registro prepared continua indicando estado incerto.
            return {"ok": False, "error": _redact(str(exc))[:1000], "code": getattr(exc, "code", "history_write_failed"),
                    "source": "developer_history", **({"change_id": identity} if identity else {})}

    @staticmethod
    def _metadata(row):
        return {key: row[key] for key in ("id", "root_id", "path", "before_sha256", "after_sha256", "before_exists", "after_exists",
                "status", "note", "created_at", "applied_at", "restored_at", "restore_of")} | {
                "before_bytes": len(row["before_data"]), "after_bytes": len(row["after_data"])}

    def list(self):
        with self.connection() as db:
            return [self._metadata(row) for row in db.execute("SELECT * FROM changes ORDER BY created_at DESC, id DESC LIMIT 100")]

    def _get(self, identity):
        if not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9]{32}", identity):
            raise HistoryError("Identificador de alteração inválido.")
        with self.connection() as db:
            row = db.execute("SELECT * FROM changes WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise HistoryError("Alteração não encontrada.", "history_not_found", 404)
        row = dict(row)
        for key in ("before", "after"):
            if not isinstance(row[key + "_data"], bytes) or len(row[key + "_data"]) > MAX_FILE or _sha(row[key + "_data"]) != row[key + "_sha256"]:
                raise HistoryError("Snapshot do histórico inválido ou com hash divergente.", "history_snapshot_invalid", 409)
        return row

    def _prepare_restore(self, identity, tools):
        row = self._get(identity)
        if row["status"] != "applied" or row["restored_at"]:
            raise HistoryError("Só alterações aplicadas e ainda não revertidas podem ser desfeitas.", "history_not_restorable", 409)
        if self._root_key(tools) != row["root_key"]:
            raise HistoryError("A pasta autorizada foi alterada; a reversão foi cancelada.", "history_root_changed", 409)
        target, exists, current = self._snapshot(tools, row["path"])
        if exists != bool(row["after_exists"]) or _sha(current) != row["after_sha256"]:
            raise HistoryError("O arquivo mudou desde a escrita. A reversão não substituirá alterações posteriores.", "history_file_changed", 409)
        before_text = row["before_data"].decode("utf-8")
        current_text = current.decode("utf-8")
        diff = "".join(difflib.unified_diff(current_text.splitlines(keepends=True), before_text.splitlines(keepends=True),
                       fromfile=row["path"], tofile=row["path"] if row["before_exists"] else "/dev/null", n=3))
        if len(diff) > 100_000:
            raise HistoryError("Diff de reversão grande demais para revisão completa. Restaure manualmente com o backup.", "history_diff_too_large")
        preview = {"action": "restore_file" if row["before_exists"] else "remove_created_file", "change_id": identity,
                   "path": row["path"], "root_id": row["root_id"], "diff": _redact(diff),
                   "current_sha256": _sha(current), "restored_sha256": row["before_sha256"],
                   "current_exists": exists, "restores_missing": not exists and bool(row["before_exists"]),
                   "removes_created_file": not bool(row["before_exists"]), "diff_redacted": _redact(diff) != diff,
                   "reason": "Reverter somente esta escrita. Se o arquivo foi criado pela operação, sua reversão exclui esse arquivo."}
        return row, target, current, preview

    def preview(self, identity, tools_factory):
        row = self._get(identity)
        tools = tools_factory(row["root_id"])
        try:
            with self.lock:
                return self._prepare_restore(identity, tools)[3]
        finally:
            tools.close()

    @staticmethod
    def _delete_current(tools, relative, expected_sha256):
        """Remove só o arquivo aprovado. No Windows, o handle impede substituição."""
        target, exists, content = DeveloperHistory._snapshot(tools, relative)
        if not exists or _sha(content) != expected_sha256:
            raise HistoryError("O arquivo mudou antes da exclusão da reversão.", "history_file_changed", 409)
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            import msvcrt
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            create = kernel.CreateFileW
            create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                               wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
            create.restype = wintypes.HANDLE
            # GENERIC_READ | DELETE; only share-read: no writer or replacement
            # can change the approved bytes between validation and disposition.
            handle = create(str(target), 0x80000000 | 0x10000, 0x1, None, 3, 0x00200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise HistoryError("Não foi possível bloquear o arquivo para reversão segura.", "history_file_locked", 409)
            try:
                fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
            except Exception:
                kernel.CloseHandle(handle)
                raise
            with os.fdopen(fd, "rb") as stream:
                descriptor = os.fstat(stream.fileno())
                actual = stream.read(MAX_FILE + 1)
                checked = tools._path(relative)
                path_info = checked.stat()
                if (not stat.S_ISREG(descriptor.st_mode) or descriptor.st_nlink != 1 or len(actual) > MAX_FILE or
                    _sha(actual) != expected_sha256 or (descriptor.st_dev, descriptor.st_ino) != (path_info.st_dev, path_info.st_ino)):
                    raise HistoryError("O arquivo mudou antes da reversão.", "history_file_changed", 409)
                class Disposition(ctypes.Structure):
                    _fields_ = [("DeleteFile", wintypes.BOOL)]
                disposition = Disposition(True)
                dispose = kernel.SetFileInformationByHandle
                dispose.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
                dispose.restype = wintypes.BOOL
                if not dispose(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                    raise HistoryError("O Windows recusou a exclusão segura. O arquivo foi preservado.", "history_file_locked", 409)
            return
        # A aplicação instalada é Windows. Outros sistemas mantêm as mesmas
        # verificações de caminho e hash, sem alegar bloqueio de outro processo.
        checked, exists, actual = DeveloperHistory._snapshot(tools, relative)
        if not exists or checked != tools._path(relative) or _sha(actual) != expected_sha256:
            raise HistoryError("O arquivo mudou antes da reversão.", "history_file_changed", 409)
        checked.unlink()

    def restore(self, identity, tools_factory, expected_sha256):
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise HistoryError("Hash da aprovação de reversão inválido.")
        original = self._get(identity)
        tools = tools_factory(original["root_id"])
        inverse_id = None
        try:
            with self.lock:
                row, target, current, preview = self._prepare_restore(identity, tools)
                if preview["current_sha256"] != expected_sha256:
                    raise HistoryError("A aprovação está desatualizada. Revise um novo diff.", "history_file_changed", 409)
                inverse_id = self._prepare(tools, row["path"], current, row["before_data"], bool(row["after_exists"]),
                                           bool(row["before_exists"]), row["root_id"], identity)
                if row["before_exists"]:
                    result = tools.execute("write_file", {"path": row["path"], "content": row["before_data"].decode("utf-8"),
                                                         "expected_sha256": expected_sha256})
                    if not result.get("ok"):
                        raise HistoryError(result.get("error", "A escrita de reversão falhou."), "history_restore_failed", 409)
                else:
                    self._delete_current(tools, row["path"], expected_sha256)
                _, exists, actual = self._snapshot(tools, row["path"])
                if exists != bool(row["before_exists"]) or actual != row["before_data"]:
                    raise HistoryError("O estado final da reversão não pôde ser confirmado.", "history_file_changed", 409)
                with self.connection() as db:
                    db.execute("BEGIN IMMEDIATE")
                    now = _now()
                    db.execute("UPDATE changes SET status='applied', applied_at=? WHERE id=? AND status='prepared'", (now, inverse_id))
                    db.execute("UPDATE changes SET restored_at=? WHERE id=? AND restored_at IS NULL", (now, identity))
                return {"ok": True, "change_id": inverse_id, "restored_change_id": identity, "path": row["path"],
                        "root_id": row["root_id"], "exists": exists, "sha256": _sha(actual), "removed_created_file": not exists}
        except (ValueError, OSError, sqlite3.DatabaseError) as exc:
            if inverse_id:
                try:
                    self._finish(inverse_id, "failed", str(exc))
                except (ValueError, OSError, sqlite3.DatabaseError):
                    pass
            raise
        finally:
            tools.close()


class RestoreDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved: StrictBool


def install_developer_routes(app, factory, tools_factory, blocking, inference, activity):
    """Operações humanas locais, com aprovação de uma única reversão por cinco minutos."""
    router = APIRouter(prefix="/api/developer/changes")
    pending = {}

    def failure(exc):
        return JSONResponse({"ok": False, "error": _redact(str(exc))[:1000], "code": getattr(exc, "code", "developer_history_error"),
                             "source": "developer_history"}, status_code=getattr(exc, "status_code", 400))

    def digest(item):
        return _sha(json.dumps({"change_id": item["change_id"], "preview": item["preview"]}, sort_keys=True, ensure_ascii=False).encode("utf-8"))

    @router.get("")
    async def changes():
        try:
            return {"changes": await blocking(factory().list)}
        except (ValueError, OSError, sqlite3.DatabaseError) as exc:
            return failure(exc)

    @router.post("/{identity}/preview")
    async def preview_restore(identity: str):
        try:
            async with inference():
                preview = await blocking(factory().preview, identity, tools_factory)
        except (ValueError, OSError, sqlite3.DatabaseError) as exc:
            return failure(exc)
        now = time.monotonic()
        for key in [key for key, value in pending.items() if value["deadline"] < now]:
            pending.pop(key, None)
        if len(pending) >= 32:
            raise HTTPException(429, "Resolva as reversões pendentes antes de criar novas aprovações.")
        approval_id = uuid.uuid4().hex
        item = {"change_id": identity, "preview": preview, "deadline": now + 300}
        item["digest"] = digest(item)
        pending[approval_id] = item
        activity().add("developer_restore_requested", {"approval_id": approval_id, "change_id": identity, "path": preview["path"], "root_id": preview["root_id"]})
        return {"ok": True, "requires_approval": True, "approval_id": approval_id, "preview": preview}

    @router.post("/{approval_id}/decision")
    async def decide_restore(approval_id: str, value: RestoreDecision):
        item = pending.pop(approval_id, None)
        if item is None or item["deadline"] < time.monotonic():
            raise HTTPException(404, "Aprovação inexistente, já consumida ou expirada.")
        if not value.approved:
            activity().add("developer_restore_denied", {"approval_id": approval_id, "change_id": item["change_id"]})
            return {"ok": True, "executed": False, "code": "approval_denied", "source": "permission"}
        if item["digest"] != digest(item):
            raise HTTPException(409, "O pedido de reversão mudou. Revise um novo diff.")
        activity().add("developer_restore_approved", {"approval_id": approval_id, "change_id": item["change_id"]})
        try:
            async with inference():
                result = await blocking(factory().restore, item["change_id"], tools_factory, item["preview"]["current_sha256"])
        except (ValueError, OSError, sqlite3.DatabaseError) as exc:
            activity().add("developer_restore_finished", {"change_id": item["change_id"], "ok": False, "code": getattr(exc, "code", "developer_history_error")})
            return failure(exc)
        activity().add("developer_restore_finished", {"change_id": item["change_id"], "ok": result["ok"], "inverse_id": result["change_id"]})
        return result

    app.include_router(router)
    return pending
