"""Especialistas configuráveis como dados; nunca concedem autorizações ao executor."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import uuid

from ..tools import Tools


MAX_AGENTS = 200
MAX_DOCUMENT = 64 * 1024
MAX_DATABASE = 20 * 1024 * 1024
WORKSPACE_MODES = {"chat", "search", "tor", "pentest", "developer", "security"}
EDITABLE = {"name", "description", "icon", "workspace_mode", "prompt", "default_model",
            "tool_allowlist", "memory", "permissions", "search"}
_LOCKS = {}
_LOCKS_GUARD = threading.Lock()
_IDENTITY = re.compile(r"(?:custom_[0-9a-f]{32}|[a-z][a-z0-9_-]{0,63})\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?\Z")


class AgentLibraryError(ValueError):
    def __init__(self, message, code="agent_configuration_invalid", status_code=400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.source = "agent_library"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(value, label, maximum, *, empty=True, strip=True):
    if not isinstance(value, str):
        raise AgentLibraryError(f"{label} deve ser texto.")
    result = value.strip() if strip else value
    try:
        size = len(result.encode("utf-8"))
    except UnicodeError as exc:
        raise AgentLibraryError(f"{label} contém caracteres inválidos.") from exc
    if size > maximum or (not empty and not result.strip()):
        raise AgentLibraryError(f"{label} deve conter {'1 a ' if not empty else 'até '}{maximum} bytes UTF-8.")
    if any(ord(char) < 32 and char not in "\n\t\r" for char in result):
        raise AgentLibraryError(f"{label} contém caracteres de controle.")
    return result


def _object(value, allowed, label):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise AgentLibraryError(f"{label} inválido; campos aceitos: {', '.join(sorted(allowed))}.")
    return value


def _boolean_fields(value, defaults, label):
    value = _object(value, defaults, label)
    result = {**defaults, **value}
    if not all(type(item) is bool for item in result.values()):
        raise AgentLibraryError(f"{label} aceita apenas valores true/false.")
    return result


class AgentLibrary:
    """Biblioteca independente de memória, perfis e permissões existentes.

    Os callbacks são consultados a cada operação. Isso permite validar ferramentas
    contra o registro real e preservar os especialistas internos como somente leitura.
    """

    def __init__(self, data_dir, builtins, tools, modes):
        self.root = Path(os.path.abspath(data_dir)) / "library"
        self.path = self.root / "agents.sqlite3"
        self._builtins = builtins
        self._tools = tools
        self._modes = modes
        with _LOCKS_GUARD:
            self.lock = _LOCKS.setdefault(os.path.normcase(str(self.path)), threading.RLock())
        with self.lock:
            self._guard()
            self.root.mkdir(parents=True, exist_ok=True)
            self._guard()
            with self.connection() as db:
                db.execute("CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, document TEXT NOT NULL, revision INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")

    def _guard(self):
        for path in (self.root, *self.root.parents):
            if self._is_link(path):
                raise AgentLibraryError("A biblioteca deve estar em uma pasta local sem links ou junctions.", "agent_storage_unsafe")
        for path in (self.path, *(Path(str(self.path) + suffix) for suffix in ("-journal", "-wal", "-shm"))):
            if self._is_link(path):
                raise AgentLibraryError("O banco da biblioteca não pode usar links.", "agent_storage_unsafe")
            if path.exists():
                stat = path.stat()
                if not path.is_file() or stat.st_nlink != 1 or stat.st_size > MAX_DATABASE:
                    raise AgentLibraryError("Arquivo de biblioteca inválido, compartilhado por hardlink ou grande demais.", "agent_storage_unsafe")

    @staticmethod
    def _is_link(path):
        try:
            return Tools._is_link(path)
        except FileNotFoundError:
            return False

    @contextmanager
    def connection(self):
        with self.lock:
            self._guard()
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                db.execute("PRAGMA trusted_schema=OFF")
                with db:
                    yield db
            finally:
                db.close()

    def tools(self):
        result = {}
        for row in self._tools():
            if not isinstance(row, dict):
                continue
            entry = row.get("function", row)
            name = entry.get("name")
            if isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", name):
                result[name] = {"name": name, "description": str(entry.get("description", ""))[:1500]}
                for key in ("available", "reason"):
                    if key in row:
                        result[name][key] = row[key]
        return sorted(result.values(), key=lambda row: row["name"])

    def modes(self):
        result = []
        for row in self._modes():
            item = {"id": row, "name": row} if isinstance(row, str) else deepcopy(row)
            if isinstance(item, dict) and item.get("id") in WORKSPACE_MODES:
                result.append(item)
        return result

    def validate(self, payload, *, allow_empty_prompt=False):
        _object(payload, EDITABLE, "Configuração do agente")
        known_modes = {row["id"] for row in self.modes()}
        mode = payload.get("workspace_mode", "chat")
        if not isinstance(mode, str) or mode not in known_modes:
            raise AgentLibraryError("Modo associado desconhecido.")
        tools = payload.get("tool_allowlist", [])
        known_tools = {row["name"] for row in self.tools()}
        if not isinstance(tools, list) or len(tools) > 160 or any(not isinstance(name, str) for name in tools):
            raise AgentLibraryError("Ferramentas permitidas deve ser uma lista de até 160 nomes.")
        unknown = set(tools) - known_tools
        if unknown:
            raise AgentLibraryError("Ferramentas não registradas: " + ", ".join(sorted(unknown))[:600])
        model = _text(payload.get("default_model", ""), "Modelo padrão", 200)
        if model and (not _MODEL.fullmatch(model) or any(part in {"", ".", ".."} for part in model.split("/") ) or ":cloud" in model.casefold() or model.casefold().endswith("-cloud")):
            raise AgentLibraryError("Use o nome e a tag de um modelo local; URLs e caminhos não são aceitos.")
        memory = _object(payload.get("memory", {}), {"read", "write", "scope"}, "Memória")
        memory_flags = _boolean_fields({key: memory[key] for key in ("read", "write") if key in memory}, {"read": True, "write": False}, "Memória")
        scope = memory.get("scope", "project")
        if not isinstance(scope, str) or scope not in {"project", "conversation"}:
            raise AgentLibraryError("A memória deve ser limitada ao projeto ou à conversa.")
        permissions = _boolean_fields(payload.get("permissions", {}),
            {"file_read": True, "file_write": False, "terminal": False, "external_network": False}, "Permissões operacionais")
        search = _object(payload.get("search", {}), {"provider", "max_results", "tor_enabled"}, "Pesquisa")
        provider = search.get("provider", "auto")
        maximum = search.get("max_results", 5)
        tor = search.get("tor_enabled", False)
        if not isinstance(provider, str) or provider not in {"auto", "duckduckgo", "searxng"} or type(maximum) is not int or not 1 <= maximum <= 10 or type(tor) is not bool:
            raise AgentLibraryError("Pesquisa requer provider auto/duckduckgo/searxng, max_results entre 1 e 10 e tor_enabled booleano.")
        result = {"name": _text(payload.get("name", ""), "Nome", 120, empty=False),
                  "description": _text(payload.get("description", ""), "Descrição", 2000),
                  "icon": _text(payload.get("icon", "◈"), "Ícone", 64, empty=False),
                  "workspace_mode": mode,
                  "prompt": _text(payload.get("prompt", ""), "Prompt", 24_000, empty=allow_empty_prompt, strip=False),
                  "default_model": model, "tool_allowlist": sorted(set(tools)),
                  "memory": {**memory_flags, "scope": scope}, "permissions": permissions,
                  "search": {"provider": provider, "max_results": maximum, "tor_enabled": tor}}
        if "<" in result["icon"] or ">" in result["icon"] or any(char in result["icon"] for char in "\n\r\t"):
            raise AgentLibraryError("O ícone deve ser texto curto ou emoji, sem marcação HTML.")
        self._encode(result)
        return result

    @staticmethod
    def _encode(document):
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(raw.encode("utf-8")) > MAX_DOCUMENT:
            raise AgentLibraryError("Configuração do agente excede 64 KiB.")
        return raw

    def _builtin_rows(self):
        result = []
        seen = set()
        for source in self._builtins():
            identity = source.get("id")
            if not isinstance(identity, str) or not _IDENTITY.fullmatch(identity) or identity.startswith("custom_") or identity in seen:
                raise AgentLibraryError("Registro interno de agentes inválido.", "agent_registry_invalid")
            seen.add(identity)
            document = self.validate({key: deepcopy(value) for key, value in source.items() if key in EDITABLE}, allow_empty_prompt=True)
            result.append({**document, "id": identity, "builtin": True, "revision": 0, "created_at": None, "updated_at": None})
        return result

    @staticmethod
    def _row(row):
        try:
            document = json.loads(row["document"])
        except (ValueError, TypeError) as exc:
            raise AgentLibraryError("Registro de agente corrompido; restaure o backup.", "agent_storage_invalid") from exc
        if not isinstance(document, dict):
            raise AgentLibraryError("Registro de agente corrompido; restaure o backup.", "agent_storage_invalid")
        return {**document, "id": row["id"], "builtin": False, "revision": row["revision"],
                "created_at": row["created_at"], "updated_at": row["updated_at"]}

    def list(self):
        builtin = self._builtin_rows()
        with self.connection() as db:
            custom = [self._row(row) for row in db.execute("SELECT * FROM agents ORDER BY created_at, id")]
        return builtin + custom

    def get(self, identity):
        if not isinstance(identity, str) or not _IDENTITY.fullmatch(identity):
            raise AgentLibraryError("Identificador de agente inválido.")
        for row in self._builtin_rows():
            if row["id"] == identity:
                return row
        with self.connection() as db:
            row = db.execute("SELECT * FROM agents WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise AgentLibraryError("Agente não encontrado.", "agent_not_found", 404)
        return self._row(row)

    def resolve(self, identity):
        """Valida novamente antes de ativar; não consulta nem baixa modelos."""
        row = self.get(identity)
        configuration = self.validate({key: row[key] for key in EDITABLE}, allow_empty_prompt=row["builtin"])
        return {**row, **configuration}

    def catalog(self):
        return {"agents": self.list(), "modes": self.modes(), "tools": self.tools(),
                "limits": {"custom_agents": MAX_AGENTS, "document_bytes": MAX_DOCUMENT, "prompt_bytes": 24_000},
                "permission_notice": "As permissões do agente apenas reduzem as ferramentas. Pastas, rede, Tor, escopos e aprovações continuam controlados pelo gerenciador operacional."}

    def create(self, payload):
        document = self.validate(payload)
        identity = "custom_" + uuid.uuid4().hex
        now = _now()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM agents").fetchone()[0] >= MAX_AGENTS:
                raise AgentLibraryError("Limite de 200 agentes personalizados atingido.", "agent_limit_reached", 409)
            db.execute("INSERT INTO agents VALUES (?, ?, 1, ?, ?)", (identity, self._encode(document), now, now))
        return self.get(identity)

    @staticmethod
    def _revision(value):
        if type(value) is not int or value < 1:
            raise AgentLibraryError("Informe a revisão atual do agente para evitar sobrescrever outra edição.", "agent_revision_required")
        return value

    def _mutable(self, identity):
        row = self.get(identity)
        if row["builtin"]:
            raise AgentLibraryError("Especialistas internos são somente leitura. Duplique para personalizar.", "agent_builtin_readonly", 409)
        return row

    def update(self, identity, payload, revision):
        self._revision(revision)
        self._mutable(identity)
        document = self.validate(payload)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE agents SET document=?, revision=revision+1, updated_at=? WHERE id=? AND revision=?",
                                 (self._encode(document), _now(), identity, revision))
            if changed.rowcount != 1:
                raise AgentLibraryError("O agente mudou ou foi excluído. Atualize a biblioteca antes de salvar.", "agent_revision_conflict", 409)
        return self.get(identity)

    def delete(self, identity, revision):
        self._revision(revision)
        self._mutable(identity)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            deleted = db.execute("DELETE FROM agents WHERE id=? AND revision=?", (identity, revision))
            if deleted.rowcount != 1:
                raise AgentLibraryError("O agente mudou. Atualize a biblioteca antes de excluir.", "agent_revision_conflict", 409)
        return {"ok": True, "id": identity, "deleted": True}

    def duplicate(self, identity, payload=None):
        payload = _object({} if payload is None else payload, {"name"}, "Duplicação")
        row = self.resolve(identity)
        document = {key: deepcopy(row[key]) for key in EDITABLE}
        document["name"] = payload.get("name", row["name"][:65] + " · cópia")
        # O roteador automático não é uma especialidade, mas sua cópia deve ter
        # um prompt explícito antes de se tornar um agente independente.
        if not document["prompt"].strip():
            document["prompt"] = "Responda com precisão e use somente as ferramentas autorizadas para a tarefa."
        return self.create(document)

    def export(self, identity):
        row = self.get(identity)
        return {"format": "nexus-agent", "version": 1, "agent": {key: deepcopy(row[key]) for key in EDITABLE}}

    def import_agent(self, envelope):
        _object(envelope, {"format", "version", "agent"}, "Arquivo de agente")
        try:
            self._encode(envelope)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AgentLibraryError("Arquivo de agente inválido ou grande demais.") from exc
        if envelope.get("format") != "nexus-agent" or type(envelope.get("version")) is not int or envelope["version"] != 1:
            raise AgentLibraryError("Formato esperado: nexus-agent versão 1.")
        return self.create(envelope.get("agent"))
