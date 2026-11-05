"""Explicit PC grants and reviewed WinGet installations for the orchestrator.

Contract: schemas(mode) controls model visibility; the caller must recheck mode
and current grants, obtain a human decision for approval(name, args), preserve
the exact arguments, and only then call execute(name, args). A tool result never
constitutes consent. Commands run with the user's privileges, without an OS
sandbox. Grants restrict the file APIs and command working directory, not what
an approved executable itself can do.

Root IDs derive from normalized absolute paths. Rebuild Computer after changing
authorized_roots, so pending requests cannot inherit a different root by index.
WinGet verifies the official "winget" source URL and uses exact package IDs and
a pinned version. It never accepts source agreements, elevates itself or bypasses hashes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from .tools import READ_MODES, ToolError, Tools, _definition


STR = {"type": "string"}
INT = {"type": "integer"}
BOOL = {"type": "boolean"}
ROOT = {"root_id": STR}
PC_TOOLS = {"pc_list_files": "list_files", "pc_read_file": "read_file",
            "pc_write_file": "write_file", "pc_run_command": "run_command"}
DEFINITIONS = {
    "computer_info": _definition("computer_info", "Mostra SO, CPU, RAM, disco e pastas autorizadas, sem ler segredos.", {}),
    "search_apps": _definition("search_apps", "Busca aplicativos no catálogo WinGet. Não instala nem aceita termos da fonte.",
        {"query": STR, "max_results": INT}, ("query",)),
    "list_apps": _definition("list_apps", "Consulta aplicativos instalados reconhecidos pelo WinGet, opcionalmente pelo ID exato. Retorna a saída real; não instala nem presume que um aplicativo está instalado.",
        {"package_id": STR}),
    "app_details": _definition("app_details", "Consulta versão, editor, licença e URL de aplicativo WinGet antes de propor instalação. Não executa o instalador.",
        {"package_id": STR, "version": STR, "scope": {"type": "string", "enum": ["user", "machine"]}}, ("package_id",)),
    "install_app": _definition("install_app", "Propõe instalar versão exata de um aplicativo WinGet. O usuário revisa editor, licença, escopo e comando antes de aprovar.",
        {"package_id": STR, "version": STR, "scope": {"type": "string", "enum": ["user", "machine"]}},
        ("package_id", "version")),
    "pc_list_files": _definition("pc_list_files", "Lista arquivos de uma pasta do PC explicitamente autorizada pelo usuário. Descubra root_id em computer_info.",
        {**ROOT, "path": STR, "recursive": BOOL, "max_results": INT}, ("root_id",)),
    "pc_read_file": _definition("pc_read_file", "Lê texto UTF-8 de uma pasta autorizada, omitindo segredos e links.",
        {**ROOT, "path": STR, "start_line": INT, "max_lines": INT}, ("root_id", "path")),
    "pc_write_file": _definition("pc_write_file", "Propõe criação/alteração de texto em pasta autorizada; exige aprovação humana do diff.",
        {**ROOT, "path": STR, "content": STR, "expected_sha256": STR}, ("root_id", "path", "content")),
    "pc_run_command": _definition("pc_run_command", "Propõe executar argv em pasta autorizada após aprovação. O programa tem os privilégios do usuário, sem sandbox de SO.",
        {**ROOT, "args": {"type": "array", "items": STR}, "cwd": STR, "timeout": INT}, ("root_id", "args")),
}


class Computer:
    def __init__(self, data_dir: Path, workspace_root: Path,
                 authorized_roots: list[str] | None = None):
        self.data_dir = Path(data_dir).resolve()
        self.workspace_root = Path(workspace_root).resolve()
        self._roots = self.validate_roots([] if authorized_roots is None else authorized_roots)
        for root in self._roots:
            folder = Path(root)
            if folder == self.data_dir or folder in self.data_dir.parents or self.data_dir in folder.parents:
                raise ToolError("Escolha uma pasta de projeto que não inclua configurações ou dados internos do NEXUS.")

    @classmethod
    def validate_roots(cls, roots: list[str]) -> list[str]:
        """Validate persisted grants without creating folders or following links."""
        if not isinstance(roots, list) or len(roots) > 16:
            raise ToolError("Autorize no máximo 16 pastas de projetos específicas.")
        valid: list[str] = []
        seen: set[str] = set()
        for raw in roots:
            if not isinstance(raw, str) or not raw.strip() or len(raw) > 1024 or "\x00" in raw:
                raise ToolError("Pasta autorizada inválida.")
            path = Path(raw)
            if not path.is_absolute() or not path.is_dir():
                raise ToolError("Autorize uma pasta existente usando o caminho absoluto.")
            if ".." in path.parts or any(Tools._sensitive(part) for part in path.parts):
                raise ToolError("Pastas protegidas ou com segredos não podem ser autorizadas.")
            # Check every ancestor before resolve(), including root junctions.
            for parent in [path, *path.parents]:
                if Tools._is_link(parent):
                    raise ToolError("Links, junctions e reparse points não podem ser autorizados.")
            path = path.resolve()
            home = Path.home().resolve()
            if path == Path(path.anchor) or path == home or path in home.parents:
                raise ToolError("Autorize uma pasta de projeto; raiz do disco e perfil inteiro são bloqueados.")
            protected = [home / "AppData"]
            for variable in ("WINDIR", "SYSTEMROOT", "PROGRAMFILES", "PROGRAMFILES(X86)",
                             "PROGRAMW6432", "PROGRAMDATA"):
                if os.environ.get(variable):
                    protected.append(Path(os.environ[variable]).resolve())
            if os.name == "nt":
                protected += [Path(path.anchor) / name for name in
                              ("Windows", "Program Files", "Program Files (x86)", "ProgramData", "$Recycle.Bin", "System Volume Information")]
            for location in protected:
                if path == location or location in path.parents:
                    raise ToolError("Pastas do sistema, programas e dados privados não podem ser autorizados.")
            key = os.path.normcase(str(path))
            if key not in seen:
                seen.add(key)
                valid.append(str(path))
        return valid

    @staticmethod
    def _root_id(path: str) -> str:
        return hashlib.sha256(os.path.normcase(str(Path(path).resolve())).encode("utf-8")).hexdigest()[:16]

    def roots(self) -> list[dict]:
        return [{"id": self._root_id(path), "name": Path(path).name, "path": path} for path in self._roots]

    def schemas(self, mode: str) -> list[dict]:
        mode = str(mode).upper()
        names: list[str] = []
        if mode in READ_MODES:
            names += ["computer_info", "search_apps", "app_details", "list_apps"]
            if self._roots:
                names += ["pc_list_files", "pc_read_file"]
        if mode in {"CODE", "AGENT"} and self._roots:
            names += ["pc_write_file", "pc_run_command"]
        if mode == "AGENT":
            names += ["install_app"]
        return json.loads(json.dumps([DEFINITIONS[name] for name in names]))

    @staticmethod
    def _arguments(name: str, args: dict | str) -> dict:
        if name not in DEFINITIONS:
            raise ToolError("Ferramenta do PC desconhecida.")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError as exc:
                raise ToolError("Argumentos precisam ser um objeto JSON válido.") from exc
        if not isinstance(args, dict):
            raise ToolError("Argumentos precisam ser um objeto JSON.")
        schema = DEFINITIONS[name]["function"]["parameters"]
        if set(args) - set(schema["properties"]) or any(key not in args for key in schema["required"]):
            raise ToolError("Argumentos ausentes ou não reconhecidos para esta ferramenta.")
        for key, value in args.items():
            spec = schema["properties"][key]
            expected = {"string": str, "integer": int, "boolean": bool, "array": list}[spec["type"]]
            if not isinstance(value, expected) or spec["type"] == "integer" and isinstance(value, bool):
                raise ToolError(f"Tipo inválido para {key}.")
            if "enum" in spec and value not in spec["enum"]:
                raise ToolError(f"Valor inválido para {key}.")
        return dict(args)

    def _root_tools(self, root_id: str) -> tuple[Tools, dict]:
        # Revalidate paths at every operation, so a replaced root/parent fails.
        current = self.validate_roots(self._roots)
        match = next((row for row in self.roots() if row["id"] == root_id and row["path"] in current), None)
        if not match:
            raise ToolError("Pasta não autorizada ou autorização revogada. Consulte computer_info.")
        return Tools(Path(match["path"]), self.data_dir), match

    def approval(self, name: str, args: dict | str) -> dict | None:
        args = self._arguments(name, args)
        if name in PC_TOOLS:
            if name == "pc_run_command":
                self._check_pc_command(args["args"])
            tools, root = self._root_tools(args.pop("root_id"))
            try:
                preview = tools.approval(PC_TOOLS[name], args)
            finally:
                tools.close()
            if preview is not None:
                return {**preview, "action": name, "root_id": root["id"], "authorized_root": root["path"]}
            return None
        if name == "install_app":
            package_id, version, scope = self._install_arguments(**args)
            details = self._catalog(["show", "--exact", "--id", package_id, "--version", version,
                                    "--scope", scope, "--source", "winget", "--disable-interactivity"], timeout=45)
            if details["exit_code"] != 0 or details["truncated"]:
                raise ToolError("Não foi possível revisar o pacote WinGet. " + details["output"][:1500])
            metadata = self._metadata(details["output"])
            return {"action": name, "reason": "Instalar o pacote e aceitar os termos/licença exibidos. "
                    "O instalador pode alterar o PC e acessar arquivos com os privilégios do usuário. "
                    "Escopo machine pode solicitar UAC; o NEXUS não aprova nem contorna essa tela. "
                    "Termos da fonte WinGet não serão aceitos automaticamente.",
                    "package_id": package_id, "version": version, "scope": scope,
                    "source": "winget", "package_details": details["output"], **metadata,
                    "args": [self._winget_exe(), *self._install_argv(package_id, version, scope)],
                    "timeout": 600, "accept_package_agreements": True,
                    "accept_source_agreements": False}
        return None

    def execute(self, name: str, args: dict | str) -> dict:
        """Execute only after the caller has checked mode and human approval."""
        try:
            args = self._arguments(name, args)
            if name in PC_TOOLS:
                if name == "pc_run_command":
                    self._check_pc_command(args["args"])
                tools, root = self._root_tools(args.pop("root_id"))
                try:
                    result = tools.execute(PC_TOOLS[name], args)
                finally:
                    tools.close()
                return {**result, "root_id": root["id"], "authorized_root": root["path"]}
            result = getattr(self, "_" + name)(**args)
            ok = result.get("exit_code", 0) == 0
            if not ok:
                result["error"] = f"WinGet retornou código {result['exit_code']}. Verifique a saída; a operação não foi confirmada."
            return {"ok": ok, **result}
        except ToolError as exc:
            return {"ok": False, "error": str(exc)}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "Tempo limite do WinGet excedido. Verifique o estado do aplicativo antes de tentar novamente."}
        except Exception as exc:
            return {"ok": False, "error": f"Falha na ferramenta do PC: {type(exc).__name__}."}

    def _computer_info(self) -> dict:
        import psutil
        ram = psutil.virtual_memory()
        drive = self.workspace_root.anchor or str(self.workspace_root)
        disk = psutil.disk_usage(drive)
        return {"system": platform.system(), "release": platform.release(),
                "architecture": platform.machine(), "cpu_logical": psutil.cpu_count(),
                "cpu_physical": psutil.cpu_count(logical=False),
                "ram_total_bytes": ram.total, "ram_available_bytes": ram.available,
                "disk_total_bytes": disk.total, "disk_free_bytes": disk.free,
                "workspace": str(self.workspace_root), "authorized_roots": self.roots(),
                "winget_available": bool(shutil.which("winget")),
                "command_sandbox": False}

    @staticmethod
    def _check_pc_command(args: list[str]):
        if not args or not isinstance(args[0], str):
            raise ToolError("args precisa ser uma lista de argumentos de texto.")
        exe = Path(args[0]).name.casefold()
        if exe.removesuffix(".exe") in {"winget", "msiexec", "choco", "chocolatey", "scoop", "ninite"} or exe.endswith(".msi"):
            raise ToolError("Use install_app para revisar versão, editor, licença e escopo antes de instalar aplicativos.")

    @staticmethod
    def _winget_exe() -> str:
        executable = shutil.which("winget")
        if not executable:
            raise ToolError("WinGet não foi encontrado. Instale/atualize o Instalador de Aplicativo pela Microsoft Store.")
        return executable

    def _winget(self, argv: list[str], *, timeout: int) -> dict:
        # No shell, stdin, elevation, source agreement acceptance or overrides.
        result = subprocess.run([self._winget_exe(), *argv], shell=False,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        output = result.stdout + result.stderr
        text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
        # Escape control sequences before returning untrusted catalog output.
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        text = "".join(ch for ch in text if ch in "\n\r\t" or ord(ch) >= 32)
        return {"exit_code": result.returncode, "output": text[:40_000], "truncated": len(text) > 40_000}

    def _catalog(self, argv: list[str], *, timeout: int) -> dict:
        source = self._winget(["source", "export", "--name", "winget", "--disable-interactivity"], timeout=15)
        try:
            exported = json.loads(source["output"].strip().lstrip("\ufeff"))
        except (ValueError, TypeError) as exc:
            raise ToolError("Não foi possível confirmar a origem oficial do catálogo WinGet.") from exc
        if (source["exit_code"] != 0 or source["truncated"] or not isinstance(exported, dict)
                or exported.get("Name") != "winget"
                or not isinstance(exported.get("Arg"), str)
                or exported["Arg"].rstrip("/") != "https://cdn.winget.microsoft.com/cache"
                or exported.get("Type") != "Microsoft.PreIndexed.Package"):
            raise ToolError("A fonte winget precisa usar o catálogo oficial https://cdn.winget.microsoft.com/cache. Configuração não alterada.")
        return self._winget(argv, timeout=timeout)

    def _search_apps(self, query: str, max_results: int = 15) -> dict:
        query = query.strip()
        if not query or len(query) > 200 or query.startswith("-") or any(ord(c) < 32 for c in query):
            raise ToolError("Pesquisa deve conter de 1 a 200 caracteres, sem opções de comando.")
        return {**self._catalog(["search", "--query", query, "--source", "winget", "--count",
                str(max(1, min(max_results, 50))), "--disable-interactivity"], timeout=45),
                "source": "winget", "query": query}

    def _app_details(self, package_id: str, version: str | None = None, scope: str = "user") -> dict:
        self._install_arguments(package_id, version if version is not None else "0", scope)
        argv = ["show", "--exact", "--id", package_id, "--source", "winget", "--scope", scope,
                "--disable-interactivity"]
        if version is not None:
            argv += ["--version", version]
        result = self._catalog(argv, timeout=45)
        return {**result, "package_id": package_id, "scope": scope,
                "source": "winget", **self._metadata(result["output"])}

    def _list_apps(self, package_id: str | None = None) -> dict:
        argv = ["list", "--source", "winget", "--disable-interactivity"]
        if package_id is not None:
            self._install_arguments(package_id, "0")
            argv += ["--exact", "--id", package_id]
        return {**self._catalog(argv, timeout=45), "source": "winget",
                **({"package_id": package_id} if package_id is not None else {})}

    @staticmethod
    def _install_arguments(package_id: str, version: str, scope: str = "user") -> tuple[str, str, str]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+", package_id) or len(package_id) > 200:
            raise ToolError("Use o ID exato WinGet, por exemplo Microsoft.VisualStudioCode.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+()-]{0,99}", version) or version.casefold() in {"latest", "unknown"}:
            raise ToolError("Use a versão exata exibida pela pesquisa WinGet.")
        if scope not in {"user", "machine"}:
            raise ToolError("Escopo precisa ser user ou machine.")
        return package_id, version, scope

    @staticmethod
    def _install_argv(package_id: str, version: str, scope: str) -> list[str]:
        return ["install", "--exact", "--id", package_id, "--version", version,
                "--source", "winget", "--scope", scope, "--disable-interactivity",
                "--no-upgrade", "--accept-package-agreements"]

    def _install_app(self, package_id: str, version: str, scope: str = "user") -> dict:
        package_id, version, scope = self._install_arguments(package_id, version, scope)
        return {**self._catalog(self._install_argv(package_id, version, scope), timeout=600),
                "package_id": package_id, "version": version, "scope": scope,
                "source": "winget", "message": "Confira o código de saída e a saída do instalador; aprovação não significa instalação concluída."}

    @staticmethod
    def _metadata(output: str) -> dict:
        # Localized WinGet fields vary; the full plain text always remains in the
        # preview so no missing parser field can hide license/publisher details.
        aliases = {"publisher": ("publisher", "publicador", "editor", "fornecedor"),
                   "publisher_url": ("publisher url", "url do publicador", "url do editor", "url do fornecedor"),
                   "license": ("license", "licença"),
                   "license_url": ("license url", "url da licença"),
                   "installer_url": ("installer url", "url do instalador")}
        fields: dict[str, str] = {}
        for line in output.splitlines():
            key, sep, value = line.strip().partition(":")
            if not sep:
                continue
            for field, names in aliases.items():
                if key.casefold() in names:
                    fields[field] = value.strip()[:2000]
        return fields

    def close(self):
        """No subprocesses or persistent browser resources are kept open."""
