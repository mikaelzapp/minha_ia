"""Bounded local tools. Mutating calls require approval by the orchestrator.

Filesystem tools enforce a workspace boundary. Approved command execution is NOT
an operating-system sandbox: programs inherit the user's filesystem privileges.
"""
from __future__ import annotations

import base64
import concurrent.futures
import difflib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlsplit, urlunsplit
import uuid
import xml.etree.ElementTree as ET


class ToolError(ValueError):
    """An expected failure safe to show to the local user."""


MAX_FILE = 256_000
MAX_RESPONSE = 2_000_000
MAX_OUTPUT = 1_000_000
MAX_TEXT = 40_000
READ_MODES = {"PLAN", "CODE", "AGENT", "REVIEW"}
WEB_MODES = {"RESEARCH", "CODE", "AGENT"}
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".browsers"}
SENSITIVE_DIRS = {".ssh", ".aws", ".azure", ".gnupg", ".codex", ".agents", ".kube", ".docker"}


def _definition(name: str, description: str, properties: dict, required: tuple = ()) -> dict:
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties,
                           "required": list(required), "additionalProperties": False}}}


STR = {"type": "string"}
INT = {"type": "integer"}
BOOL = {"type": "boolean"}
DEFINITIONS = {
    "list_files": _definition("list_files", "Lista arquivos do workspace, omitindo segredos e links.",
        {"path": STR, "recursive": BOOL, "max_results": INT}),
    "read_file": _definition("read_file", "Lê texto de arquivo permitido no workspace.",
        {"path": STR, "start_line": INT, "max_lines": INT}, ("path",)),
    "grep_files": _definition("grep_files", "Busca texto literal, sem regex, em arquivos do workspace.",
        {"query": STR, "path": STR, "case_sensitive": BOOL, "max_results": INT}, ("query",)),
    "write_file": _definition("write_file", "Propõe criar/alterar arquivo. Chame para o executor mostrar o diff e obter aprovação humana antes da escrita.",
        {"path": STR, "content": STR, "expected_sha256": STR}, ("path", "content")),
    "run_command": _definition("run_command", "Propõe executar argv sem shell. Chame para o executor obter aprovação humana. Não é sandbox de SO.",
        {"args": {"type": "array", "items": STR}, "cwd": STR, "timeout": INT}, ("args",)),
    "search_web": _definition("search_web", "Pesquisa fontes reais; datas só são retornadas quando fornecidas pela fonte.",
        {"query": STR, "max_results": INT}, ("query",)),
    "fetch_page": _definition("fetch_page", "Lê página HTTP/HTTPS pública, sem acesso a IPs internos.",
        {"url": STR}, ("url",)),
    "download_file": _definition("download_file", "Propõe download público no workspace. Executor obtém aprovação antes de baixar.",
        {"url": STR, "path": STR}, ("url", "path")),
    "browser_open": _definition("browser_open", "Renderiza página pública em perfil isolado, somente leitura e sem downloads.",
        {"url": STR}, ("url",)),
    "browser_interact": _definition("browser_interact", "Propõe clicar/preencher na última página; executor obtém aprovação, limitado ao domínio autorizado.",
        {"action": {"type": "string", "enum": ["click", "fill"]}, "selector": STR,
         "value": STR, "page_url": STR}, ("action", "selector", "page_url")),
    "tor_check": _definition("tor_check", "Verifica se o proxy Tor habilitado usa a rede Tor.", {}),
    "tor_fetch": _definition("tor_fetch", "Lê endereço onion v3 válido apenas via Tor verificado, sem fallback direto.",
        {"url": STR}, ("url",)),
}


class Tools:
    def __init__(self, workspace_root: Path, data_dir: Path,
                 ollama_url: str = "http://127.0.0.1:11434", searxng_url: str = "",
                 tor_enabled: bool = False, tor_proxy: str = "socks5h://127.0.0.1:9050"):
        workspace_root = Path(workspace_root).absolute()
        if workspace_root.exists() and self._is_link(workspace_root):
            raise ToolError("A raiz do workspace não pode ser link/junction.")
        self.root = workspace_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.ollama_url = ollama_url
        self.searxng_url = searxng_url.strip().rstrip("/")
        self.search_provider = "auto"
        self.tor_enabled = tor_enabled
        self.tor_proxy = tor_proxy
        self._browser_pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._browser_lock = threading.Lock()
        self._playwright = self._context = self._page = None
        self._browser_host: str | None = None
        self._browser_write = False
        self._browser_errors: list[dict] = []

    def schemas(self, mode: str) -> list[dict]:
        mode = str(mode).upper()
        names: list[str] = []
        if mode in READ_MODES:
            names += ["list_files", "read_file", "grep_files"]
        if mode in {"CODE", "AGENT"}:
            names += ["write_file", "run_command", "download_file"]
        if mode in WEB_MODES:
            names += ["search_web", "fetch_page", "browser_open"]
        if mode == "AGENT":
            names += ["browser_interact"]
        if mode in WEB_MODES and self.tor_enabled:
            names += ["tor_check", "tor_fetch"]
        # Do not let callers mutate the registry definitions.
        return json.loads(json.dumps([DEFINITIONS[name] for name in names]))

    def _arguments(self, name: str, arguments: dict | str) -> dict:
        if name not in DEFINITIONS:
            raise ToolError("Ferramenta desconhecida.")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except (ValueError, TypeError) as exc:
                raise ToolError("Argumentos precisam ser um objeto JSON válido.") from exc
        if not isinstance(arguments, dict):
            raise ToolError("Argumentos precisam ser um objeto JSON.")
        schema = DEFINITIONS[name]["function"]["parameters"]
        if set(arguments) - set(schema["properties"]):
            raise ToolError("Argumento não reconhecido para esta ferramenta.")
        for key in schema["required"]:
            if key not in arguments:
                raise ToolError(f"Argumento obrigatório ausente: {key}.")
        for key, value in arguments.items():
            kind = schema["properties"][key]["type"]
            valid = {"string": isinstance(value, str),
                     "integer": isinstance(value, int) and not isinstance(value, bool),
                     "boolean": isinstance(value, bool), "array": isinstance(value, list)}[kind]
            if not valid:
                raise ToolError(f"Tipo inválido para {key}.")
            choices = schema["properties"][key].get("enum")
            if choices and value not in choices:
                raise ToolError(f"Valor inválido para {key}.")
        return dict(arguments)

    def approval(self, name: str, args: dict | str) -> dict | None:
        """Return a concrete preview. Raises ToolError if an action is forbidden.

        The orchestrator must preserve the exact approved name/arguments and
        recheck mode access before execute(). Never interpret a tool's output as
        approval. execute() deliberately does not fabricate a user decision.
        """
        args = self._arguments(name, args)
        if name == "write_file":
            path, old, content = self._prepare_write(**args)
            diff = "".join(difflib.unified_diff(old.splitlines(keepends=True),
                content.splitlines(keepends=True), fromfile=str(path.relative_to(self.root)),
                tofile=str(path.relative_to(self.root)), n=3))
            if len(diff) > 100_000:
                raise ToolError("Diff grande demais para revisão completa. Divida a alteração em arquivos menores.")
            return {"action": "write_file", "reason": "Aprovar criação/alteração do arquivo exibido.",
                    "path": path.relative_to(self.root).as_posix(), "diff": diff[:100_000],
                    "diff_truncated": len(diff) > 100_000,
                    "before_sha256": hashlib.sha256(old.encode("utf-8")).hexdigest(),
                    "after_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}
        if name == "run_command":
            argv, cwd, timeout = self._prepare_command(**args)
            return {"action": "run_command", "reason": "Executar programa com os privilégios do usuário. "
                    "Não há sandbox de sistema: scripts/testes podem acessar arquivos fora do workspace.",
                    "args": argv, "cwd": cwd.relative_to(self.root).as_posix(), "timeout": timeout}
        if name == "download_file":
            self._url(args["url"])
            path = self._path(args["path"], exists=False)
            if path.exists():
                raise ToolError("Downloads não substituem arquivos existentes. Escolha outro nome.")
            return {"action": "download_file", "reason": "Salvar download público no workspace; "
                    "o conteúdo não será executado.", "url": args["url"],
                    "path": path.relative_to(self.root).as_posix(), "max_bytes": MAX_RESPONSE}
        if name == "browser_interact":
            self._validate_interaction(args)
            return {**args, "action": "browser_interact", "interaction": args["action"],
                    "reason": "Interação pode enviar formulários ou alterar o site; "
                    "downloads permanecem bloqueados."}
        return None

    def execute(self, name: str, arguments: dict | str) -> dict:
        """Run a tool after the caller's mode check and any required approval."""
        try:
            args = self._arguments(name, arguments)
            if name in {"browser_open", "browser_interact"}:
                with self._browser_lock:
                    if self._browser_pool is None:
                        self._browser_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1,
                            thread_name_prefix="nexus-browser")
                    future = self._browser_pool.submit(getattr(self, "_" + name), **args)
                    return {"ok": True, **future.result(timeout=90)}
            return {"ok": True, **getattr(self, "_" + name)(**args)}
        except ToolError as exc:
            return {"ok": False, "error": str(exc),
                    **({"browser_errors": self._browser_errors[-10:]} if name.startswith("browser_") else {})}
        except concurrent.futures.TimeoutError:
            return {"ok": False, "error": "Tempo limite do navegador excedido."}
        except Exception as exc:
            # Exception text from HTTP clients can include URLs/query secrets.
            return {"ok": False, "error": f"Falha em {name}: {type(exc).__name__}. "
                    "Confira dependências, caminho e disponibilidade do serviço."}

    @staticmethod
    def _is_link(path: Path) -> bool:
        info = path.lstat()
        return (stat.S_ISLNK(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink > 1)
                or bool(getattr(info, "st_file_attributes", 0) &
                                                 getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))

    @staticmethod
    def _sensitive(name: str) -> bool:
        name = name.casefold()
        return (name in SENSITIVE_DIRS or name == ".env" or name.startswith(".env.") or
                name in {".npmrc", ".pypirc", ".netrc", ".git-credentials", "authorized_keys", "known_hosts"} or
                name.startswith("id_rsa") or name.startswith("id_ed25519") or
                any(word in name for word in ("secret", "credential", "password", "apikey", "api_key")) or
                name in {"key", "keys", "token", "tokens", "key.json", "keys.json", "token.json", "tokens.json"} or
                name.endswith((".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore")))

    def _path(self, path: str = ".", *, directory: bool = False, exists: bool = True) -> Path:
        if not isinstance(path, str) or not path or len(path) > 1024 or "\x00" in path:
            raise ToolError("Caminho inválido.")
        supplied = Path(path)
        if supplied.is_absolute() or supplied.drive or path.startswith(("/", "\\")):
            raise ToolError("Use um caminho relativo ao workspace.")
        parts = re.split(r"[\\/]", path)
        if any(p == ".." or ":" in p or p.endswith((" ", ".")) and p not in {".", ""} for p in parts):
            raise ToolError("Travessia de diretório/fluxos alternativos não são permitidos.")
        if any(re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p) for p in parts):
            raise ToolError("Nomes de dispositivos Windows não são permitidos.")
        if any(self._sensitive(p) or p.casefold() in SKIP_DIRS for p in parts):
            raise ToolError("Arquivo/diretório protegido ou potencialmente contém segredos.")
        candidate = self.root
        for part in supplied.parts:
            if part == ".":
                continue
            candidate = candidate / part
            if candidate.exists() or candidate.is_symlink():
                if self._is_link(candidate):
                    raise ToolError("Links, junctions e reparse points não são permitidos.")
        try:
            candidate.resolve(strict=False).relative_to(self.root)
        except (ValueError, OSError) as exc:
            raise ToolError("O caminho precisa permanecer dentro do workspace.") from exc
        if exists and not candidate.exists():
            raise ToolError("Caminho não encontrado no workspace.")
        if candidate.exists() and directory != candidate.is_dir():
            raise ToolError("Era esperado um diretório." if directory else "Era esperado um arquivo.")
        return candidate

    def _walk(self, start: Path, recursive: bool):
        count = 0
        stack = [start]
        while stack and count < 5000:
            current = stack.pop()
            try:
                entries = sorted(current.iterdir(), key=lambda p: p.name.casefold())
            except OSError:
                continue
            for entry in entries:
                count += 1
                if count > 5000:
                    return
                if self._sensitive(entry.name) or entry.name.casefold() in SKIP_DIRS:
                    continue
                try:
                    if self._is_link(entry):
                        continue
                    checked = self._path(entry.relative_to(self.root).as_posix(), directory=entry.is_dir())
                except (ToolError, OSError, ValueError):
                    continue
                yield checked
                if recursive and checked.is_dir():
                    stack.append(checked)

    def _list_files(self, path: str = ".", recursive: bool = False, max_results: int = 200) -> dict:
        start = self._path(path, directory=True)
        limit = max(1, min(max_results, 500))
        entries = []
        for item in self._walk(start, recursive):
            entries.append({"path": item.relative_to(self.root).as_posix(),
                            "type": "directory" if item.is_dir() else "file"})
            if len(entries) >= limit:
                return {"entries": entries, "truncated": True}
        return {"entries": entries, "truncated": False}

    def _read_bytes(self, path: Path) -> bytes:
        # Revalidate immediately before opening, and reject special files.
        path = self._path(path.relative_to(self.root).as_posix())
        if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > MAX_FILE:
            raise ToolError(f"Somente arquivos regulares de até {MAX_FILE} bytes são aceitos.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ToolError("Arquivo especial não permitido.")
            data = handle.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ToolError("Arquivo excede o limite de leitura.")
        return data

    def _read_text(self, path: Path) -> str:
        data = self._read_bytes(path)
        if b"\x00" in data:
            raise ToolError("Arquivo binário não é legível por esta ferramenta.")
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ToolError("O arquivo precisa ser texto UTF-8.") from exc

    def _read_file(self, path: str, start_line: int = 1, max_lines: int = 300) -> dict:
        target = self._path(path)
        raw = self._read_bytes(target)
        if b"\x00" in raw:
            raise ToolError("Arquivo binário não é legível por esta ferramenta.")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ToolError("O arquivo precisa ser texto UTF-8.") from exc
        lines = text.splitlines()
        first, limit = max(1, start_line), max(1, min(max_lines, 1000))
        selection = "\n".join(lines[first - 1:first - 1 + limit])
        return {"path": target.relative_to(self.root).as_posix(), "content": selection[:MAX_TEXT],
                "start_line": first, "total_lines": len(lines),
                "truncated": first - 1 + limit < len(lines) or len(selection) > MAX_TEXT,
                "sha256": hashlib.sha256(raw).hexdigest()}

    def _grep_files(self, query: str, path: str = ".", case_sensitive: bool = False,
                    max_results: int = 100) -> dict:
        if not query or len(query) > 1000:
            raise ToolError("Consulta deve conter de 1 a 1000 caracteres.")
        start = self._path(path, directory=True)
        needle = query if case_sensitive else query.casefold()
        matches, scanned = [], 0
        limit = max(1, min(max_results, 200))
        for item in self._walk(start, True):
            if not item.is_file():
                continue
            scanned += 1
            if scanned > 1000:
                break
            try:
                text = self._read_text(item)
            except (ToolError, OSError):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if needle in (line if case_sensitive else line.casefold()):
                    matches.append({"path": item.relative_to(self.root).as_posix(),
                                    "line": number, "text": line[:500]})
                    if len(matches) >= limit:
                        return {"matches": matches, "truncated": True, "scanned": scanned}
        return {"matches": matches, "truncated": scanned > 1000, "scanned": min(scanned, 1000)}

    def _prepare_write(self, path: str, content: str, expected_sha256: str | None = None):
        target = self._path(path, exists=False)
        if len(content.encode("utf-8")) > MAX_FILE or "\x00" in content:
            raise ToolError("Conteúdo deve ser texto e respeitar o limite de tamanho.")
        old = self._read_text(target) if target.exists() else ""
        if expected_sha256 is not None:
            actual = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else hashlib.sha256(b"").hexdigest()
            if expected_sha256 != actual:
                raise ToolError("O arquivo mudou desde a leitura. Leia novamente e aprove um novo diff.")
        return target, old, content

    def _write_file(self, path: str, content: str, expected_sha256: str | None = None) -> dict:
        target, old, content = self._prepare_write(path, content, expected_sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        self._path(path, exists=False)
        fd, temp = tempfile.mkstemp(prefix=".nexus-", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            # Recheck expected version and all parents before atomic replacement.
            self._prepare_write(path, content, expected_sha256)
            os.replace(temp, target)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        return {"path": target.relative_to(self.root).as_posix(), "bytes": len(content.encode("utf-8")),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(), "created": old == ""}

    def _prepare_command(self, args: list[str], cwd: str = ".", timeout: int = 30):
        if not args or len(args) > 80 or any(not isinstance(a, str) or not a or len(a) > 8000 or
                                                "\x00" in a for a in args):
            raise ToolError("args precisa ser uma lista limitada de argumentos de texto não vazios.")
        directory = self._path(cwd, directory=True)
        exe = Path(args[0]).name.casefold()
        stem = exe.removesuffix(".exe").removesuffix(".com")
        forbidden = {"cmd", "powershell", "pwsh", "bash", "sh", "zsh", "wsl", "sudo", "su", "runas",
            "rm", "del", "erase", "rmdir", "rd", "remove-item", "move-item", "move", "mv", "robocopy",
            "format", "diskpart", "shutdown", "bcdedit", "reg", "regedit", "net", "net1", "sc", "schtasks",
            "vssadmin", "takeown", "icacls", "cipher", "wmic", "cscript", "wscript", "mshta", "rundll32"}
        if stem in forbidden or exe.endswith((".bat", ".cmd", ".ps1")):
            raise ToolError("Shell, elevação administrativa ou comando destrutivo bloqueado pela política.")
        joined = " ".join(args[1:]).casefold()
        if any(token in joined for token in ("shutil.rmtree", "os.remove(", "os.unlink(", "os.rmdir(",
                    "remove-item", "format-volume", "start-process -verb runas", "--no-preserve-root")):
            raise ToolError("Operação destrutiva/administrativa explícita bloqueada.")
        if stem == "git" and any(a.casefold() in {"clean", "reset", "restore"} for a in args[1:]):
            raise ToolError("Comandos Git que descartam alterações estão bloqueados.")
        # Absolute executable locations may refer to an installed interpreter;
        # explicit path-like arguments must still not escape the workspace.
        for arg in args[1:]:
            if "../" in arg or "..\\" in arg or re.match(r"^[a-zA-Z]:[\\/]", arg) or arg.startswith("\\\\"):
                raise ToolError("Argumentos com caminhos externos/travessia são bloqueados.")
        resolved_exe = shutil.which(args[0])
        if not resolved_exe:
            raise ToolError("Executável não encontrado no PATH.")
        return [resolved_exe, *args[1:]], directory, max(1, min(timeout, 120))

    @staticmethod
    def _kill_tree(process: subprocess.Popen):
        try:
            import psutil
            parent = psutil.Process(process.pid)
            children = parent.children(recursive=True)
            for child in reversed(children):
                try:
                    child.kill()
                except psutil.Error:
                    pass
            try:
                parent.kill()
            except psutil.Error:
                pass
            psutil.wait_procs(children, timeout=2)
        except (ImportError, OSError):
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               capture_output=True, timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else:
                process.kill()
        except Exception:
            process.kill()

    def _run_command(self, args: list[str], cwd: str = ".", timeout: int = 30) -> dict:
        argv, directory, timeout = self._prepare_command(args, cwd, timeout)
        started = time.monotonic()
        timed_out = output_limited = False
        with tempfile.TemporaryFile(mode="w+b", dir=self.data_dir) as output:
            process = subprocess.Popen(argv, cwd=directory, shell=False, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0) |
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)))
            try:
                while process.poll() is None:
                    timed_out = time.monotonic() - started > timeout
                    output_limited = os.fstat(output.fileno()).st_size > MAX_OUTPUT
                    if timed_out or output_limited:
                        self._kill_tree(process)
                        break
                    time.sleep(0.05)
                process.wait(timeout=5)
            finally:
                if process.poll() is None:
                    self._kill_tree(process)
            output_limited = output_limited or os.fstat(output.fileno()).st_size > MAX_OUTPUT
            output.seek(0)
            text = output.read(MAX_OUTPUT).decode("utf-8", errors="replace")
        return {"exit_code": process.returncode, "output": text, "timed_out": timed_out,
                "truncated": output_limited, "duration_seconds": round(time.monotonic() - started, 2)}

    @staticmethod
    def _url(url: str, *, onion: bool = False):
        if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
            raise ToolError("URL inválida.")
        try:
            parsed = urlsplit(url)
            port = parsed.port
            host = parsed.hostname
        except ValueError as exc:
            raise ToolError("URL/porta inválida.") from exc
        if parsed.scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
            raise ToolError("Somente URLs HTTP/HTTPS sem credenciais são permitidas.")
        if port == 0:
            raise ToolError("Porta zero não é válida para esta ferramenta.")
        if host.endswith("."):
            host = host[:-1]
        try:
            host = host.encode("idna").decode("ascii").casefold()
        except UnicodeError as exc:
            raise ToolError("Hostname inválido.") from exc
        if not onion and (host.endswith((".onion", ".local", ".localhost", ".internal", ".test", ".invalid")) or host == "localhost"):
            raise ToolError("Destino local/privado não permitido. Use a ferramenta Tor para onion.")
        return parsed, host, port or (443 if parsed.scheme == "https" else 80)

    @staticmethod
    def _public_ip(address: str) -> bool:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return ip.ipv4_mapped.is_global
        return ip.is_global and not (ip.is_multicast or ip.is_unspecified or ip.is_reserved)

    def _resolve(self, host: str, port: int, *, local: bool = False) -> str:
        try:
            addresses = {row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ToolError("Não foi possível resolver o domínio.") from exc
        if not addresses:
            raise ToolError("Domínio sem endereço de rede.")
        for address in addresses:
            if not self._public_ip(address) and not (local and ipaddress.ip_address(address).is_loopback):
                raise ToolError("Acesso a IP interno, reservado ou loopback bloqueado.")
        # Pin the connection to one of the addresses just checked: a second DNS
        # lookup by the HTTP client must not permit DNS rebinding.
        return sorted(addresses, key=lambda address: ":" in address)[0]

    def _fetch_response(self, url: str, *, max_bytes: int = MAX_RESPONSE,
                        redirects: int = 4, local: bool = False, method: str = "GET",
                        headers: dict | None = None, body: bytes | None = None,
                        allowed_host: str | None = None) -> dict:
        import httpx
        current = url
        started = time.monotonic()
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=httpx.Timeout(12, connect=8)) as client:
            for hop in range(redirects + 1):
                # Explicitly configured local SearXNG is the only public-tool exception.
                if local:
                    parsed = urlsplit(current)
                    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or not parsed.hostname:
                        raise ToolError("URL SearXNG inválida.")
                    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
                else:
                    parsed, host, port = self._url(current)
                if allowed_host and host != allowed_host:
                    raise ToolError("Navegação para outro domínio bloqueada.")
                if port not in {80, 443} and not local:
                    raise ToolError("Somente portas HTTP/HTTPS padrão são permitidas para páginas públicas.")
                address = self._resolve(host, port, local=local)
                endpoint = f"[{address}]" if ":" in address else address
                pinned = urlunsplit((parsed.scheme, f"{endpoint}:{port}", parsed.path or "/", parsed.query, ""))
                request_headers = {"User-Agent": "NEXUS-Local/1.0", "Accept": "text/html,text/plain,application/json;q=0.9,*/*;q=0.5"}
                if headers:
                    request_headers.update({k: v for k, v in headers.items()
                        if k.casefold() not in {"host", "connection", "content-length", "accept-encoding", "proxy-authorization"}})
                authority = f"[{host}]" if ":" in host else host
                default_port = 443 if parsed.scheme == "https" else 80
                request_headers["Host"] = authority + (f":{port}" if port != default_port else "")
                try:
                    with client.stream(method, pinned, headers=request_headers, content=body,
                                       extensions={"sni_hostname": host}) as response:
                        if response.status_code in {301, 302, 303, 307, 308} and redirects:
                            if hop >= redirects:
                                raise ToolError("Limite de redirecionamentos excedido.")
                            location = response.headers.get("location")
                            if not location:
                                raise ToolError("Redirecionamento sem destino.")
                            current = urljoin(current, location)
                            if response.status_code == 303:
                                method, body = "GET", None
                            continue
                        chunks, size = [], 0
                        for chunk in response.iter_bytes():
                            size += len(chunk)
                            if size > max_bytes:
                                raise ToolError("Resposta excede o limite de bytes.")
                            if time.monotonic() - started > 30:
                                raise ToolError("Tempo total de leitura excedido.")
                            chunks.append(chunk)
                        return {"url": current, "status": response.status_code,
                                "headers": dict(response.headers), "body": b"".join(chunks)}
                except httpx.HTTPError as exc:
                    raise ToolError("Não foi possível carregar a página pública (rede/TLS/timeout).") from exc
        raise ToolError("Página não retornou uma resposta válida.")

    @staticmethod
    def _html_details(soup, url: str) -> dict:
        """Extract source HTML, without fetching any linked destination."""
        links, seen = [], set()
        for anchor in soup.find_all("a", href=True, limit=300):
            target = urljoin(url, str(anchor.get("href", "")))
            try:
                _, host, _ = Tools._url(target)
                try:
                    if not Tools._public_ip(host):
                        continue
                except ValueError:
                    pass  # A DNS name is checked only if later fetched.
            except ToolError:
                continue
            if target in seen:
                continue
            seen.add(target)
            links.append({"text": anchor.get_text(" ", strip=True)[:200], "url": target})
            if len(links) == 60:
                break
        tables = []
        for table in soup.find_all("table", limit=3):
            caption = table.find("caption")
            rows = [[cell.get_text(" ", strip=True)[:200] for cell in row.find_all(["th", "td"], recursive=False)[:8]]
                    for row in table.find_all("tr", limit=12)]
            tables.append({"caption": caption.get_text(" ", strip=True)[:200] if caption else "",
                           "rows": [row for row in rows if row],
                           "truncated": len(table.find_all("tr", limit=13)) > 12})
        return {"links": links, "tables": tables}

    @staticmethod
    def _page_text(response: dict) -> dict:
        from bs4 import BeautifulSoup
        if not 200 <= response["status"] < 300:
            raise ToolError(f"A página retornou HTTP {response['status']}; leitura não concluída.")
        content_type = response["headers"].get("content-type", "").casefold()
        if content_type and not any(kind in content_type for kind in ("text/", "json", "xml", "xhtml")):
            raise ToolError("Tipo de conteúdo não textual bloqueado; downloads não são automáticos.")
        text = response["body"].decode("utf-8", errors="replace")
        soup = BeautifulSoup(text, "html.parser")
        title = soup.title.get_text(" ", strip=True)[:300] if soup.title else ""
        for tag in soup(["script", "style", "noscript", "template", "svg"]):
            tag.decompose()
        details = Tools._html_details(soup, response["url"])
        content = soup.get_text("\n", strip=True)
        date = None
        for name in ("article:published_time", "datePublished", "date", "pubdate"):
            meta = soup.find("meta", attrs={"property": name}) or soup.find("meta", attrs={"name": name})
            if meta and meta.get("content"):
                date = str(meta["content"])[:100]
                break
        return {"url": response["url"], "status": response["status"], "title": title,
                "text": content[:MAX_TEXT], "truncated": len(content) > MAX_TEXT,
                "published_date": date, **details}

    def _fetch_page(self, url: str) -> dict:
        return self._page_text(self._fetch_response(url))

    def _download_file(self, url: str, path: str) -> dict:
        target = self._path(path, exists=False)
        if target.exists():
            raise ToolError("Downloads não substituem arquivos existentes.")
        response = self._fetch_response(url)
        if not 200 <= response["status"] < 300:
            raise ToolError(f"Download retornou HTTP {response['status']}.")
        target.parent.mkdir(parents=True, exist_ok=True)
        self._path(path, exists=False)
        # Exclusive creation refuses to overwrite a file created since approval.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(response["body"])
        return {"path": target.relative_to(self.root).as_posix(), "url": response["url"],
                "bytes": len(response["body"]), "sha256": hashlib.sha256(response["body"]).hexdigest()}

    @staticmethod
    def _search_query(query: str):
        if not query.strip() or len(query) > 600:
            raise ToolError("Pesquisa deve conter de 1 a 600 caracteres.")
        patterns = (r"[\r\n]", r"(?i)\bbearer\s+\S+", r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|token)\s*[:=]\s*\S+",
                    r"(?i)(?:sk-|ghp_|github_pat_|AKIA|AIza)[a-zA-Z0-9_\-]{12,}",
                    r"(?i)[a-z]:[\\/]", r"(?i)/(?:users|home|root)/", r"(?i)-----BEGIN .*PRIVATE KEY-----",
                    r"(?i)\b(?:ssh-rsa|ssh-ed25519)\s+[A-Za-z0-9+/]{20,}",
                    r"[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}",
                    r"(?i)(?:def |class |function |import |const |let |var ).{0,100}[{};]",
                    r"(?i)https?://[^\s/@]+:[^\s/@]+@")
        if any(re.search(pattern, query) for pattern in patterns):
            raise ToolError("A pesquisa parece conter credenciais, código ou caminho privado. "
                            "Reformule apenas como palavras-chave públicas.")

    def _search_web(self, query: str, max_results: int = 5) -> dict:
        self._search_query(query)
        limit = max(1, min(max_results, 10))
        query_used, sites = self._search_scope(query)
        if self.searxng_url:
            url = self.searxng_url + "/search?" + urlencode({"q": query_used, "format": "json"})
            result = self._fetch_response(url, local=True, redirects=0)
            if result["status"] != 200:
                raise ToolError("SearXNG configurado indisponível ou API JSON desabilitada.")
            try:
                rows = json.loads(result["body"]).get("results", [])
            except (ValueError, AttributeError) as exc:
                raise ToolError("SearXNG não retornou JSON de resultados válido.") from exc
            results = self._search_rows(rows, limit, sites)
            if not results:
                raise ToolError("SearXNG não retornou fontes que correspondam à pesquisa.")
            return {"provider": "searxng", "query": query, "query_used": query_used, "results": results}
        # Do not use DDGS' default mixed-engine selection: its actual backend and
        # wall-clock timeout can differ from the requested engine. Every request
        # here uses the same bounded, IP-pinned transport as fetch_page.
        attempts = []
        providers = [("duckduckgo/html", "https://html.duckduckgo.com/html/?"),
                     ("duckduckgo/lite", "https://lite.duckduckgo.com/lite/?"),
                     ("bing/rss", "https://www.bing.com/search?format=rss&")]
        if self.search_provider == "duckduckgo":
            providers = [item for item in providers if item[0].startswith("duckduckgo/")]
        for provider, base in providers:
            url = base + urlencode({"q": query_used})
            try:
                response = self._fetch_response(url)
                if response["status"] != 200:
                    raise ToolError(f"HTTP {response['status']}")
                if provider == "bing/rss":
                    rows = self._parse_search_rss(response["body"])
                else:
                    rows = self._parse_duckduckgo(response)
                results = self._search_rows(rows, limit, sites)
                if results:
                    return {"provider": provider, "query": query, "query_used": query_used,
                            "results": results, "fallback_attempts": attempts}
                attempts.append({"provider": provider, "error": "Sem resultados pertinentes/verificáveis."})
            except ToolError as exc:
                attempts.append({"provider": provider, "error": str(exc)[:250]})
        # A query can itself name an exact source (site:host/path). If engines
        # return no usable results, verify that user-supplied URL directly. This
        # is explicitly labelled and never presented as an engine search hit.
        verified = []
        for site in sites[:3]:
            if not site["path"]:
                continue
            try:
                page = self._fetch_page(site["url"])
                verified.append({"title": page["title"] or site["url"], "url": page["url"],
                    "snippet": page["text"][:1000], "published_date": page["published_date"],
                    "source_date": None, "verification": "explicit_url_loaded"})
            except ToolError as exc:
                attempts.append({"provider": "direct/url-verification", "error": str(exc)[:250]})
        if verified:
            return {"provider": "direct/url-verification", "query": query, "query_used": query_used,
                    "results": verified[:limit], "fallback_attempts": attempts,
                    "notice": "Buscadores não retornaram fontes pertinentes. URL explícita da consulta "
                              "foi carregada e verificada diretamente; não é um resultado de motor de busca."}
        raise ToolError("Nenhum provedor retornou fontes verificáveis. " +
                        "; ".join(f"{attempt['provider']}: {attempt['error']}" for attempt in attempts))

    @staticmethod
    def _search_scope(query: str) -> tuple[str, list[dict]]:
        sites = []
        def normalize(match):
            value = match.group(1).strip('"\'')
            try:
                _, host, _ = Tools._url(value if "://" in value else "https://" + value)
            except ToolError:
                return match.group(0)
            parsed = urlsplit(value if "://" in value else "https://" + value)
            path = unquote(parsed.path).rstrip("/")
            sites.append({"host": host, "path": path,
                          "url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))})
            # Search engines interpret site:hostname reliably; URL paths can
            # suppress all results. Preserve the original path as a result
            # filter, and expose the normalized query to the caller.
            words = [re.sub(r"\.(?:html?|php|aspx?)$", "", segment, flags=re.I)
                     for segment in path.split("/") if segment]
            words = [word for word in words if len(word) > 2 and not word.isdigit()]
            return "site:" + host + (" " + " ".join(words[-2:]) if words else "")
        used = re.sub(r"(?<![-\w])site:([^\s]+)", normalize, query, flags=re.I)
        return used, sites

    @staticmethod
    def _parse_search_rss(body: bytes) -> list[dict]:
        if b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
            raise ToolError("RSS com entidades externas não é permitido.")
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise ToolError("O provedor não retornou RSS válido; pode haver desafio/bloqueio.") from exc
        if root.tag != "rss":
            raise ToolError("Resposta não corresponde a resultados RSS.")
        return [{"title": item.findtext("title", ""), "url": item.findtext("link", ""),
                 "content": item.findtext("description", ""), "source_date": item.findtext("pubDate")}
                for item in root.findall("./channel/item")[:30]]

    @staticmethod
    def _parse_duckduckgo(response: dict) -> list[dict]:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response["body"], "html.parser")
        if soup.select_one("#challenge-form, .anomaly-modal, form[action*='anomaly']"):
            raise ToolError("Desafio/CAPTCHA do provedor; nenhum resultado foi fabricado.")
        rows = []
        for anchor in soup.select("a.result__a, a.result-link"):
            href = urljoin(response["url"], anchor.get("href", ""))
            params = parse_qs(urlsplit(href).query)
            href = params.get("uddg", [href])[0]
            parent = anchor.find_parent(class_="result")
            snippet = parent.select_one(".result__snippet") if parent else None
            if snippet is None:
                row = anchor.find_parent("tr")
                if row:
                    for sibling in row.find_next_siblings("tr", limit=3):
                        if sibling.select_one("a.result-link"):
                            break
                        snippet = sibling.select_one(".result-snippet")
                        if snippet:
                            break
            rows.append({"title": anchor.get_text(" ", strip=True), "url": href,
                         "content": snippet.get_text(" ", strip=True) if snippet else ""})
        return rows

    def _search_rows(self, rows: list, limit: int, sites: list[dict] | None = None) -> list:
        results = []
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = row.get("url") or row.get("href") or ""
            try:
                parsed, host, _ = self._url(url)
            except ToolError:
                continue
            if sites and not any((host == site["host"] or host.endswith("." + site["host"])) and
                                 (not site["path"] or unquote(parsed.path).startswith(site["path"])) for site in sites):
                continue
            if url in seen:
                continue
            seen.add(url)
            date = row.get("publishedDate") or row.get("published_date") or row.get("date")
            results.append({"title": str(row.get("title", ""))[:300], "url": url,
                "snippet": str(row.get("content") or row.get("body") or "")[:1000],
                "published_date": str(date)[:100] if date else None,
                "source_date": str(row["source_date"])[:100] if row.get("source_date") else None})
            if len(results) >= limit:
                break
        return results

    def _start_browser(self):
        if self._context is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise ToolError("Playwright não instalado. Instale as dependências do projeto.") from exc
        browser_home = Path(__file__).resolve().parents[1] / ".browsers"
        if browser_home.is_dir():
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browser_home)
        self._playwright = sync_playwright().start()
        profile = self.data_dir / "browser" / uuid.uuid4().hex
        profile.mkdir(parents=True, exist_ok=True)
        options = {"user_data_dir": str(profile), "headless": True, "accept_downloads": False,
                   "service_workers": "block", "permissions": [],
                   # All permitted HTTP is fulfilled by our IP-pinned Python
                   # transport. A dead proxy prevents accidental direct traffic.
                   "proxy": {"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
                   "args": ["--disable-background-networking", "--disable-component-update", "--disable-sync",
                            "--no-first-run", "--disable-extensions", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]}
        executables = []
        # Inspect installation directories, never personal browser profiles.
        cache = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright"
        if cache.is_dir():
            for pattern in ("chromium_headless_shell-*/chrome-headless-shell-win64/chrome-headless-shell.exe",
                            "chromium_headless_shell-*/chrome-win/headless_shell.exe",
                            "chromium-*/chrome-win64/chrome.exe", "chromium-*/chrome-win/chrome.exe"):
                executables.extend(sorted(cache.glob(pattern), reverse=True))
        candidates = [{}] + [{"executable_path": str(path)} for path in executables] + [{"channel": "msedge"}]
        for candidate in candidates:
            try:
                self._context = self._playwright.chromium.launch_persistent_context(
                    **options, **candidate)
                break
            except Exception:
                pass
        if self._context is None:
            self._playwright.stop()
            self._playwright = None
            raise ToolError("Nenhum navegador encontrado. Instale Chromium do Playwright no projeto ou use Edge instalado.")
        if not hasattr(self._context, "route_web_socket"):
            self._context.close()
            self._context = None
            self._playwright.stop()
            self._playwright = None
            raise ToolError("Atualize Playwright: bloqueio de WebSocket é necessário para navegação protegida.")
        self._context.route_web_socket("**/*", lambda ws: ws.close())
        self._context.route("**/*", self._browser_route)
        self._context.on("page", self._new_page)
        self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
        self._new_page(self._page)
        self._page.set_default_timeout(12_000)
        self._page.set_default_navigation_timeout(25_000)

    def _record_browser_error(self, kind: str, message: str):
        self._browser_errors.append({"type": kind, "message": str(message)[:500]})
        del self._browser_errors[:-30]

    def _new_page(self, page):
        page.on("download", lambda download: download.cancel())
        page.on("dialog", lambda dialog: dialog.dismiss())
        page.on("pageerror", lambda error: self._record_browser_error("javascript", str(error)))
        page.on("console", lambda msg: self._record_browser_error("console", msg.text) if msg.type == "error" else None)
        page.on("requestfailed", lambda request: self._record_browser_error("request_failed",
            f"{request.method} {request.url[:250]}: {request.failure}"))

    def _browser_route(self, route):
        request = route.request
        try:
            parsed, host, _ = self._url(request.url)
            if host != self._browser_host:
                self._record_browser_error("blocked_domain", host)
                route.abort("blockedbyclient")
                return
            if request.method not in {"GET", "HEAD"} and not self._browser_write:
                self._record_browser_error("blocked_write", request.method)
                route.abort("blockedbyclient")
                return
            post = request.post_data_buffer
            if post and len(post) > 256_000:
                route.abort("blockedbyclient")
                return
            result = self._fetch_response(request.url, redirects=0, method=request.method,
                headers=request.headers, body=post, allowed_host=self._browser_host)
            if result["status"] >= 400:
                self._record_browser_error("http", f"HTTP {result['status']}: {request.url[:250]}")
            headers = {key: value for key, value in result["headers"].items()
                       if key.casefold() not in {"content-encoding", "content-length", "transfer-encoding", "connection"}}
            if "attachment" in headers.get("content-disposition", "").casefold():
                route.abort("blockedbyclient")
                return
            route.fulfill(status=result["status"], headers=headers, body=result["body"])
        except Exception as exc:
            self._record_browser_error("blocked_request", str(exc) if isinstance(exc, ToolError) else type(exc).__name__)
            route.abort("blockedbyclient")

    def _snapshot(self) -> dict:
        parsed, host, _ = self._url(self._page.url)
        if host != self._browser_host:
            raise ToolError("A página saiu do domínio autorizado.")
        screenshot = Path("screenshots") / (uuid.uuid4().hex + ".png")
        target = self.data_dir / screenshot
        target.parent.mkdir(parents=True, exist_ok=True)
        self._page.screenshot(path=str(target), full_page=False)
        text = self._page.locator("body").inner_text(timeout=5000)
        from bs4 import BeautifulSoup
        html = self._page.content()
        details = self._html_details(BeautifulSoup(html[:MAX_RESPONSE], "html.parser"), self._page.url)
        return {"url": self._page.url, "title": self._page.title()[:300], "text": text[:MAX_TEXT],
                "truncated": len(text) > MAX_TEXT, "screenshot": screenshot.as_posix(),
                "browser_errors": self._browser_errors[-10:], **details,
                "notice": "Perfil isolado; conexões limitadas ao domínio da página; downloads bloqueados."}

    def _browser_open(self, url: str) -> dict:
        parsed, host, port = self._url(url)
        if port not in {80, 443}:
            raise ToolError("Porta pública não permitida.")
        self._resolve(host, port)
        self._start_browser()
        self._browser_host = host
        self._browser_write = False
        self._browser_errors.clear()
        response = self._page.goto(url, wait_until="domcontentloaded")
        if response is None or not 200 <= response.status < 300:
            raise ToolError(f"Navegação retornou HTTP {response.status if response else 'sem resposta'}.")
        return self._snapshot()

    def _validate_interaction(self, args: dict):
        self._url(args["page_url"])
        if not args["selector"] or len(args["selector"]) > 1000 or len(args.get("value", "")) > 20_000:
            raise ToolError("Seletor/valor da interação excede os limites.")
        if args["action"] == "fill" and "value" not in args:
            raise ToolError("Preenchimento exige um valor.")

    def _browser_interact(self, action: str, selector: str, page_url: str, value: str = "") -> dict:
        args = {"action": action, "selector": selector, "page_url": page_url, "value": value}
        self._validate_interaction(args)
        if self._page is None or self._page.url != page_url:
            raise ToolError("A página mudou ou não está aberta. Abra novamente e aprove outra interação.")
        _, host, _ = self._url(page_url)
        if host != self._browser_host:
            raise ToolError("Domínio não autorizado.")
        self._browser_write = True
        try:
            locator = self._page.locator(selector)
            if locator.count() != 1:
                raise ToolError("O seletor precisa identificar exatamente um elemento.")
            if action == "fill":
                locator.fill(value)
            else:
                locator.click()
            self._page.wait_for_timeout(300)
            return self._snapshot()
        finally:
            self._browser_write = False

    def _validate_tor_proxy(self):
        if not self.tor_enabled:
            raise ToolError("Tor está desativado. Habilite explicitamente nas configurações.")
        try:
            proxy = urlsplit(self.tor_proxy)
            if (proxy.scheme != "socks5h" or proxy.hostname not in {"127.0.0.1", "::1", "localhost"}
                    or not proxy.port or proxy.username is not None or proxy.password is not None
                    or proxy.path not in {"", "/"} or proxy.query or proxy.fragment):
                raise ValueError()
        except ValueError as exc:
            raise ToolError("Proxy Tor deve ser SOCKS5H em loopback, com porta explícita e sem credenciais.") from exc

    def _tor_request(self, url: str) -> dict:
        import requests
        self._validate_tor_proxy()
        started = time.monotonic()
        proxies = {"http": self.tor_proxy, "https": self.tor_proxy}
        try:
            with requests.Session() as session:
                session.trust_env = False
                with session.get(url, proxies=proxies, timeout=(8, 20), allow_redirects=False,
                                 stream=True, headers={"User-Agent": "NEXUS-Local/1.0"}) as response:
                    chunks, size = [], 0
                    for chunk in response.iter_content(chunk_size=16_384):
                        size += len(chunk)
                        if size > MAX_RESPONSE or time.monotonic() - started > 30:
                            raise ToolError("Resposta Tor excedeu limite de tamanho/tempo.")
                        chunks.append(chunk)
                    return {"url": url, "status": response.status_code,
                            "headers": {k.casefold(): v for k, v in response.headers.items()}, "body": b"".join(chunks)}
        except requests.RequestException as exc:
            raise ToolError("Conexão Tor falhou; nenhuma conexão direta foi tentada.") from exc

    def _tor_check(self) -> dict:
        self._validate_tor_proxy()
        response = self._tor_request("https://check.torproject.org/api/ip")
        try:
            data = json.loads(response["body"])
        except (TypeError, ValueError) as exc:
            raise ToolError("Não foi possível confirmar a rede Tor.") from exc
        if response["status"] != 200 or data.get("IsTor") is not True:
            raise ToolError("O proxy não foi confirmado como Tor. Operação cancelada.")
        return {"is_tor": True, "ip": str(data.get("IP", ""))[:100], "proxy": self.tor_proxy}

    def _onion_url(self, url: str):
        parsed, host, port = self._url(url, onion=True)
        if not re.fullmatch(r"[a-z2-7]{56}\.onion", host):
            raise ToolError("Somente endereços onion v3 válidos são permitidos.")
        try:
            decoded = base64.b32decode(host[:-6].upper())
        except ValueError as exc:
            raise ToolError("Endereço onion v3 inválido.") from exc
        if len(decoded) != 35 or decoded[-1] != 3:
            raise ToolError("Versão do endereço onion inválida.")
        checksum = hashlib.sha3_256(b".onion checksum" + decoded[:32] + decoded[-1:]).digest()[:2]
        if decoded[32:34] != checksum:
            raise ToolError("Checksum do endereço onion v3 inválido.")
        return parsed

    def _tor_fetch(self, url: str) -> dict:
        self._validate_tor_proxy()
        self._onion_url(url)
        self._tor_check()
        current = url
        for hop in range(5):
            self._onion_url(current)  # No local DNS resolution, including redirects.
            response = self._tor_request(current)
            if response["status"] in {301, 302, 303, 307, 308}:
                if hop == 4 or not response["headers"].get("location"):
                    raise ToolError("Redirecionamento onion inválido ou excessivo.")
                current = urljoin(current, response["headers"]["location"])
                continue
            return {**self._page_text(response), "via_tor": True}
        raise ToolError("A página onion não respondeu.")

    def close(self):
        """Release the isolated browser from the same worker that created it."""
        def close_browser():
            if self._context is not None:
                self._context.close()
                self._context = self._page = None
            if self._playwright is not None:
                self._playwright.stop()
                self._playwright = None
        with self._browser_lock:
            if self._browser_pool is not None:
                try:
                    self._browser_pool.submit(close_browser).result(timeout=10)
                finally:
                    self._browser_pool.shutdown(wait=False, cancel_futures=True)
                    self._browser_pool = None
