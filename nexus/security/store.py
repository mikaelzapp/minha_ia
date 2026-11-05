"""Escopos, amostras inertes e relatórios separados da memória de conversa."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import uuid

from .common import SecurityError, redact_secrets, safe_file, sha256_file, utcnow
from ..tools import Tools

MAX_SAMPLE = 10 * 1024 * 1024


def _linked(path):
    try:
        return Tools._is_link(path)
    except FileNotFoundError:
        return False


class SecurityStore:
    def __init__(self, data_dir):
        self.root = Path(data_dir) / "security"
        self.samples_dir = self.root / "samples"
        if any(_linked(parent) for parent in (self.root, *self.root.parents)):
            raise SecurityError("O armazenamento de segurança não pode atravessar links ou junctions.", "unsafe_store")
        for folder in (self.root, self.samples_dir):
            if folder.exists() and Tools._is_link(folder):
                raise SecurityError("O armazenamento de segurança não pode ser um link.", "unsafe_store")
            folder.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "security.sqlite3"
        if self.path.exists() and (Tools._is_link(self.path) or self.path.stat().st_nlink > 1):
            raise SecurityError("Banco de segurança inválido.", "unsafe_store")
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS scopes(id TEXT PRIMARY KEY, document TEXT NOT NULL,
                    revision INTEGER NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS samples(id TEXT PRIMARY KEY, original_name TEXT NOT NULL,
                    sha256 TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, operation TEXT NOT NULL,
                    result TEXT NOT NULL, created_at TEXT NOT NULL);
            """)

    @contextmanager
    def connection(self):
        if (any(_linked(parent) for parent in (self.root, *self.root.parents)) or
                any(_linked(path) or path.exists() and (not path.is_file() or path.stat().st_nlink > 1)
                    for path in (self.path, *(Path(str(self.path) + suffix) for suffix in ("-wal", "-shm", "-journal"))))):
            raise SecurityError("Armazenamento de segurança alterado.", "unsafe_store")
        db = sqlite3.connect(self.path, timeout=15)
        try:
            db.row_factory = sqlite3.Row
            with db:
                yield db
        finally:
            db.close()

    def create_scope(self, payload):
        from .network import normalize_scope
        document = redact_secrets(normalize_scope(payload))
        identity, now = uuid.uuid4().hex, utcnow()
        with self.connection() as db:
            db.execute("INSERT INTO scopes VALUES(?,?,?,?,?)", (identity, json.dumps(document, ensure_ascii=False), 1, 1, now))
        return self.get_scope(identity)

    def list_scopes(self):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM scopes ORDER BY created_at DESC").fetchall()
        return [{**json.loads(row["document"]), "id": row["id"], "revision": row["revision"],
                 "enabled": bool(row["enabled"]), "created_at": row["created_at"]} for row in rows]

    def get_scope(self, identity, revision=None):
        scope = next((row for row in self.list_scopes() if row["id"] == identity), None)
        if not scope or not scope["enabled"]:
            raise SecurityError("Escopo inexistente ou revogado.", "scope_revoked", "permission")
        if revision is not None and revision != scope["revision"]:
            raise SecurityError("O escopo mudou desde a preparação; prepare a operação novamente.", "scope_changed", "permission")
        return scope

    def revoke_scope(self, identity):
        with self.connection() as db:
            cursor = db.execute("UPDATE scopes SET enabled=0,revision=revision+1 WHERE id=?", (identity,))
            if cursor.rowcount == 0:
                raise SecurityError("Escopo não encontrado.", "scope_not_found")
        return {"ok": True, "id": identity, "enabled": False}

    def ingest(self, name, content):
        if (not isinstance(name, str) or not name.strip() or name in {".", ".."} or len(name) > 200 or
                any(ord(c) < 32 or ord(c) == 127 or c in "/\\:" for c in name)
                or Tools._sensitive(name)):
            raise SecurityError("Use o nome simples de um arquivo de análise, sem credenciais.", "invalid_sample_name")
        if not content or len(content) > MAX_SAMPLE:
            raise SecurityError("A amostra deve conter de 1 byte a 10 MiB.", "sample_size")
        identity = uuid.uuid4().hex
        destination = self.samples_dir / (identity + ".bin")
        if Tools._is_link(self.samples_dir):
            raise SecurityError("Armazenamento de amostras alterado.", "unsafe_store")
        handle = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(content)
            digest = sha256_file(safe_file(destination))
            with self.connection() as db:
                db.execute("INSERT INTO samples VALUES(?,?,?,?,?)", (identity, name, digest, len(content), utcnow()))
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return next(item for item in self.list_samples() if item["id"] == identity)

    def list_samples(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM samples ORDER BY created_at DESC LIMIT 100")]

    def sample(self, identity):
        if not isinstance(identity, str) or len(identity) != 32 or any(c not in "0123456789abcdef" for c in identity):
            raise SecurityError("Identificador de amostra inválido.", "sample_not_found")
        with self.connection() as db:
            row = db.execute("SELECT * FROM samples WHERE id=?", (identity,)).fetchone()
        if not row:
            raise SecurityError("Amostra não encontrada.", "sample_not_found")
        path = safe_file(self.samples_dir / (identity + ".bin"), maximum=MAX_SAMPLE)
        if sha256_file(path) != row["sha256"]:
            raise SecurityError("O hash da amostra mudou. Reenvie o arquivo antes da análise.", "sample_changed")
        return path, dict(row)

    def save_report(self, operation, result):
        identity, now = uuid.uuid4().hex, utcnow()
        if len(json.dumps(result, ensure_ascii=False, default=str).encode("utf-8")) > 2 * 1024 * 1024:
            raise SecurityError("Relatório excede 2 MiB; reduza a operação.", "report_size")
        safe = redact_secrets(result)
        text = json.dumps(safe, ensure_ascii=False, default=str)
        if len(text.encode("utf-8")) > 2 * 1024 * 1024:
            raise SecurityError("Relatório excede 2 MiB; reduza a operação.", "report_size")
        with self.connection() as db:
            db.execute("INSERT INTO reports VALUES(?,?,?,?)", (identity, operation, text, now))
        return {"id": identity, "operation": operation, "created_at": now, "result": safe}

    def reports(self):
        with self.connection() as db:
            rows = db.execute("""SELECT id,operation,created_at,json_extract(result,'$.ok') AS ok,
                COALESCE(json_array_length(result,'$.findings'),0) AS findings_count
                FROM reports ORDER BY created_at DESC LIMIT 100""").fetchall()
        return [{"id": row["id"], "operation": row["operation"], "created_at": row["created_at"],
                 "ok": bool(row["ok"]), "findings_count": row["findings_count"]} for row in rows]

    def report(self, identity):
        with self.connection() as db:
            row = db.execute("SELECT * FROM reports WHERE id=?", (identity,)).fetchone()
        if not row:
            raise SecurityError("Relatório não encontrado.", "report_not_found")
        return {"id": row["id"], "operation": row["operation"], "created_at": row["created_at"], "result": json.loads(row["result"])}
