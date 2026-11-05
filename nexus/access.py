"""Autorizações de pasta concedidas apenas por ações diretas da interface."""
import json
import os
import tempfile
import threading
from pathlib import Path

from .computer import Computer

_LOCKS = {}
_LOCKS_GUARD = threading.Lock()

class Access:
    def __init__(self, data_dir, workspace_root):
        self.data_dir = Path(data_dir)
        self.workspace_root = Path(workspace_root)
        self.path = self.data_dir / "computer-access.json"
        with _LOCKS_GUARD:
            self.lock = _LOCKS.setdefault(os.path.normcase(str(self.path.resolve())), threading.RLock())

    def paths(self):
        with self.lock:
            if not self.path.exists():
                return []
            stored = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(stored, list):
                raise ValueError("Arquivo de autorizações inválido.")
            return stored

    def computer(self):
        # Uma pasta removida/restrita não torna o painel inteiro indisponível.
        valid = []
        for path in self.paths():
            try:
                valid.extend(row["path"] for row in Computer(self.data_dir, self.workspace_root, [path]).roots())
            except (ValueError, OSError):
                continue
        return Computer(self.data_dir, self.workspace_root, valid)

    def save(self, paths):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".computer-access-", suffix=".tmp", dir=self.data_dir, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(paths, handle, ensure_ascii=False, indent=2)
        try:
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def grant(self, path):
        with self.lock:
            validated = Computer.validate_roots([path])[0]
            paths = Computer.validate_roots([*[row["path"] for row in self.computer().roots()], validated])
            Computer(self.data_dir, self.workspace_root, paths)
            self.save(paths)
            return next(row for row in self.computer().roots() if row["path"] == validated)

    def revoke(self, root_id):
        with self.lock:
            computer = self.computer()
            retained = [row["path"] for row in computer.roots() if row["id"] != root_id]
            if len(retained) == len(computer.roots()):
                raise ValueError("Autorização não encontrada.")
            self.save(retained)

class AgentTools:
    def __init__(self, base, access, enabled, coding=None, security=None, research=None, history=None):
        self.base = base
        self.access = access
        self.enabled = enabled
        self.coding = coding
        self.security = security
        self.research = research
        self.history = history

    @staticmethod
    def is_pc(name):
        return name in {"computer_info", "search_apps", "list_apps", "app_details", "install_app"} or name.startswith("pc_")

    def schemas(self, mode):
        schemas = self.base.schemas(mode) + (self.access.computer().schemas(mode) if self.enabled() else [])
        if self.coding is not None and mode.upper() in {"PLAN", "CODE", "AGENT", "REVIEW"}:
            schemas.append(self.coding().schema())
        if self.security is not None:
            schemas.extend(self.security().schemas(mode.upper()))
        if self.research is not None:
            schemas.extend(self.research.schemas(mode.upper()))
        return schemas

    def approval(self, name, args):
        if self.research is not None and name in self.research_names:
            return self.research.approval(name, args)
        if name.startswith("security_") and self.security is not None:
            return self.security().approval(name, args)
        if name == "consult_coder" and self.coding is not None:
            return None
        if not self.is_pc(name):
            return self.base.approval(name, args)
        if not self.enabled():
            raise ValueError("Acesso ao computador desativado pelo usuário.")
        return self.access.computer().approval(name, args)

    def execute(self, name, args):
        if self.research is not None and name in self.research_names:
            return self.research.execute(name, args)
        if self.history is not None and name == "write_file":
            return self.history().execute_write(self.base, args)
        if self.history is not None and name == "pc_write_file":
            if not self.enabled():
                return {"ok": False, "error": "Acesso ao computador foi desativado."}
            parameters = dict(args)
            root_id = parameters.pop("root_id")
            tools, root = self.access.computer()._root_tools(root_id)
            try:
                return {**self.history().execute_write(tools, parameters, root_id=root_id), "root_id": root_id, "authorized_root": root["path"]}
            finally:
                tools.close()
        if name.startswith("security_") and self.security is not None:
            return self.security().execute(name, args)
        if name == "consult_coder" and self.coding is not None:
            return self.coding().execute(args)
        if not self.is_pc(name):
            return self.base.execute(name, args)
        if not self.enabled():
            return {"ok": False, "error": "Acesso ao computador foi desativado. Operação cancelada."}
        # Instância nova lê as permissões atuais; uma decisão pendente não restaura grant revogado.
        return self.access.computer().execute(name, args)

    def close(self):
        if self.research is not None:
            self.research.close()
        self.base.close()

    @property
    def research_names(self):
        from .research import DEFINITIONS
        return set(DEFINITIONS)
