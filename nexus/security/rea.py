"""Local REA 6.8.x MCP adapter, restricted to static inspection.

No npx, installation, shell, target execution, attach, debugging or runtime tools.
The existing npm cache is reused; each bounded session has a private workspace.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time

import psutil

from .common import redact_secrets


MAX_OUTPUT = 512 * 1024
MAX_INPUT = 32 * 1024 * 1024
TIMEOUT = 45
SUPPORTED_VERSION = "6.8.0"
STATIC_TOOLS = frozenset({"binary_session", "open_binary", "inspect_artifact", "close_binary",
                          "inspect_pe_imports", "inspect_native_exports", "inspect_managed_artifact"})


class REAError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _package() -> dict:
    """Read known npm cache locations only; never follow a project-local bin."""
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    caches = [local / "npm-cache/_npx", Path.home() / ".npm/_npx"]
    for cache in caches:
        if not cache.is_dir() or cache.is_symlink():
            continue
        try:
            candidates = sorted(cache.iterdir(), key=lambda p: p.name)[:128]
        except OSError:
            continue
        for folder in candidates:
            root = folder / "node_modules/rea-agents"
            manifest = root / "package.json"
            try:
                if not manifest.is_file() or manifest.stat().st_size > 128 * 1024:
                    continue
                data = json.loads(manifest.read_text(encoding="utf-8"))
                repository = data.get("repository", {})
                url = repository.get("url", "") if isinstance(repository, dict) else repository
                if (data.get("name") != "rea-agents" or data.get("version") != SUPPORTED_VERSION
                        or url not in {"git+https://github.com/morluto/rea.git", "https://github.com/morluto/rea.git"}):
                    continue
                entry = root / "scripts/rea.mjs"
                if not entry.is_file() or not (root / "dist/mcp/main.js").is_file():
                    continue
                if any(item.is_symlink() or getattr(item, "is_junction", lambda: False)()
                       for item in (folder, root, root.parent, entry, manifest)):
                    continue
                return {"available": True, "version": data["version"], "entry": str(entry.resolve()),
                        "package_path": str(root.resolve()), "repository": url,
                        "entry_sha256": hashlib.sha256(entry.read_bytes()).hexdigest(),
                        "signature_verified": False,
                        "provenance_note": "Metadados e hash do cache local; não equivalem à verificação criptográfica da distribuição npm."}
            except (OSError, ValueError, TypeError):
                continue
    return {"available": False, "code": "rea_package_unavailable", "expected_version": SUPPORTED_VERSION,
            "error": "REA 6.8.0 não encontrado no cache npm conhecido. Não foi baixado ou instalado automaticamente."}


class _Stdio:
    def __init__(self, node: str, entry: str, workdir: Path):
        self.deadline = time.monotonic() + TIMEOUT
        self.counter = 0
        self.responses: queue.Queue = queue.Queue(maxsize=64)
        self.stderr = bytearray()
        self.stdout_bytes = 0
        self.failure = None
        # Exclude credentials, NODE_OPTIONS from the host and provider commands.
        env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "LANG") if key in os.environ}
        for folder in (workdir / "tmp", workdir / "profile", workdir / "cache", workdir / "appdata"):
            folder.mkdir(parents=True, exist_ok=True)
        env.update(NODE_OPTIONS="--max-old-space-size=384", USERPROFILE=str(workdir / "profile"),
                   TMP=str(workdir / "tmp"), TEMP=str(workdir / "tmp"), TMPDIR=str(workdir / "tmp"),
                   XDG_CACHE_HOME=str(workdir / "cache"), XDG_CONFIG_HOME=str(workdir / "profile"),
                   APPDATA=str(workdir / "appdata"), LOCALAPPDATA=str(workdir / "appdata"),
                   REA_MCP_INPUT_SCHEMA_PROFILE="compact", NO_COLOR="1")
        self.process = subprocess.Popen([node, entry, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, cwd=str(workdir), env=env, shell=False,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._read_errors, daemon=True).start()
        try:
            self.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "nexus-security-static", "version": "1.0"}})
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except Exception:
            self.close()
            raise

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(MAX_OUTPUT + 1)
                if not line:
                    self.failure = REAError("rea_connection_closed", "O processo REA encerrou a conexão.")
                    return
                self.stdout_bytes += len(line)
                if len(line) > MAX_OUTPUT or self.stdout_bytes > MAX_OUTPUT:
                    self.failure = REAError("output_limit", "Resposta REA excedeu 512 KiB; não foi aceita como evidência completa.")
                    return
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeError):
                    self.failure = REAError("invalid_tool_output", "REA retornou uma linha MCP inválida.")
                    return
                try:
                    self.responses.put_nowait(value)
                except queue.Full:
                    self.failure = REAError("output_limit", "Quantidade excessiva de mensagens MCP.")
                    return
        except (OSError, ValueError):
            self.failure = REAError("rea_connection_closed", "Não foi possível ler a conexão REA.")

    def _read_errors(self):
        try:
            while chunk := self.process.stderr.read(4096):
                if len(self.stderr) < 32768:
                    self.stderr.extend(chunk[:32768 - len(self.stderr)])
        except (OSError, ValueError):
            pass

    def _send(self, value):
        try:
            self.process.stdin.write(json.dumps(value, ensure_ascii=True).encode("utf-8") + b"\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            raise REAError("rea_connection_closed", "Não foi possível enviar a solicitação ao REA.") from None

    def request(self, method, params):
        self.counter += 1
        request_id = self.counter
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise REAError("tool_timeout", "Sessão REA excedeu 45 segundos. Nenhuma repetição automática foi feita.")
            try:
                response = self.responses.get(timeout=min(0.2, remaining))
            except queue.Empty:
                if self.failure:
                    raise self.failure
                continue
            if not isinstance(response, dict):
                raise REAError("invalid_tool_output", "Envelope MCP inválido.")
            if response.get("id") != request_id:
                if "id" in response and "method" in response:
                    self._send({"jsonrpc": "2.0", "id": response["id"], "error": {"code": -32601, "message": "Client requests unsupported"}})
                continue
            if "error" in response:
                raise REAError("rea_rpc_error", json.dumps(response["error"], ensure_ascii=False)[:2000])
            return response.get("result", {})

    def tool(self, name: str, arguments: dict):
        if name not in STATIC_TOOLS:
            raise REAError("tool_not_allowed", "Esta integração expõe somente inspeção estática.")
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if not isinstance(result, dict):
            raise REAError("invalid_tool_output", "Resultado REA inválido.")
        if result.get("isError"):
            raise REAError("rea_analysis_failed", json.dumps(result, ensure_ascii=False)[:4000])
        return result

    def close(self):
        if not getattr(self, "process", None):
            return
        try:
            descendants = psutil.Process(self.process.pid).children(recursive=True)
        except psutil.Error:
            descendants = []
        try:
            self.process.stdin.close()
            self.process.wait(timeout=1)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait(timeout=3)
        for child in reversed(descendants):
            try:
                child.kill()
            except psutil.Error:
                pass
        for stream in (self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass


class REA:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir).resolve()
        self.workdir = self.data_dir / "security/rea"

    def _session(self):
        package = _package()
        node = shutil.which("node.exe" if os.name == "nt" else "node")
        if not package.get("available") or not node:
            raise REAError("rea_unavailable", "Node ou pacote REA cached 6.8.0 indisponível; nenhuma instalação automática.")
        if any(p.is_symlink() or getattr(p, "is_junction", lambda: False)() for p in (self.workdir, *self.workdir.parents)):
            raise REAError("unsafe_runtime_path", "Diretório de trabalho REA não pode conter links ou junctions.")
        self.workdir.mkdir(parents=True, exist_ok=True)
        return _Stdio(node, package["entry"], self.workdir)

    def inventory(self) -> dict:
        package = _package()
        result = {"ok": False, "available": False, "code": "rea_unavailable", "package": package,
                  "node_available": bool(shutil.which("node.exe" if os.name == "nt" else "node")),
                  "static_tools": sorted(STATIC_TOOLS), "target_execution": False, "dynamic_analysis": False,
                  "limitations": ["REA disponível não implica Ghidra, Hopper, IDA ou pseudocódigo disponíveis.",
                                  "Sessões privadas não reutilizam alvos nem configurações do servidor Codex.",
                                  "Heap Node limitado a 384 MiB; não é limite de memória do sistema operacional."]}
        session = None
        try:
            session = self._session()
            state = session.tool("binary_session", {})
            payload = state.get("structuredContent")
            if not isinstance(payload, dict):
                payload = next((json.loads(item["text"]) for item in state.get("content", [])
                                if item.get("type") == "text"), {})
            payload = payload.get("result", payload)
            providers = [{"id": item.get("provider", {}).get("id"),
                          "name": item.get("provider", {}).get("name"),
                          "version": item.get("provider", {}).get("version"),
                          "availability": {key: item.get("availability", {}).get(key)
                                           for key in ("status", "code", "reason")}}
                         for item in payload.get("analysis_provider_candidates", [])]
            groups = payload.get("tool_availability", {}).get("groups", [])
            allowed = [{"names": [name for name in group.get("names", []) if name in STATIC_TOOLS],
                        "available": group.get("available"), "reason": group.get("reason")}
                       for group in groups if any(name in STATIC_TOOLS for name in group.get("names", []))]
            result.update(ok=True, available=True, code="ok", mcp={"connected": True,
                          "server_identity": payload.get("server_identity"), "static_tool_groups": allowed},
                          providers=providers)
        except (REAError, OSError, ValueError, TypeError) as exc:
            result.update(code=getattr(exc, "code", "rea_start_failed"), error=str(exc)[:4000])
        finally:
            if session:
                session.close()
        return redact_secrets(result)

    def analyze(self, path: Path) -> dict:
        session = None
        opened = False
        try:
            source = Path(path)
            # Only inert samples already stored by the security upload/store layer.
            sample_root = self.data_dir / "security"
            if not source.is_absolute() or not source.is_file():
                raise REAError("invalid_artifact", "Amostra local inexistente ou caminho não absoluto.")
            if any(p.is_symlink() or getattr(p, "is_junction", lambda: False)() for p in (source, *source.parents)):
                raise REAError("unsafe_artifact_path", "Links e junctions não são aceitos.")
            resolved = source.resolve()
            if not resolved.is_relative_to(sample_root.resolve()) or resolved.is_relative_to(self.workdir):
                raise REAError("outside_sample_store", "REA aceita somente amostras isoladas no armazenamento Security Center.")
            stat = resolved.stat()
            if stat.st_nlink > 1 or stat.st_size > MAX_INPUT:
                raise REAError("artifact_limit", "Amostra deve ser arquivo regular, sem hardlinks, de até 32 MiB.")
            with resolved.open("rb") as stream:
                header = stream.read(4)
                stream.seek(0)
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if not (header[:2] in {b"MZ", b"PK"} or header == b"\x7fELF"):
                raise REAError("unsupported_static_format", "Este adaptador REA cobre PE, ELF e ZIP. Use a inspeção estática local para outros formatos.")
            session = self._session()
            evidence = []
            if header[:2] == b"MZ":
                evidence.append(session.tool("inspect_pe_imports", {"path": str(resolved), "max_file_bytes": MAX_INPUT, "max_dlls": 128, "max_functions": 2048}))
                evidence.append(session.tool("inspect_managed_artifact", {"path": str(resolved), "detail": "summary"}))
            elif header == b"\x7fELF":
                evidence.append(session.tool("inspect_native_exports", {"path": str(resolved), "detail": "summary", "max_file_bytes": MAX_INPUT}))
            elif header[:2] == b"PK":
                evidence.append(session.tool("open_binary", {"path": str(resolved)}))
                opened = True
                evidence.append(session.tool("inspect_artifact", {"detail": "summary"}))
            else:
                raise REAError("unsupported_static_format", "Este adaptador REA cobre PE, ELF e ZIP. Use a inspeção estática local para outros formatos.")
            current = resolved.stat()
            if current.st_size != stat.st_size or current.st_mtime_ns != stat.st_mtime_ns:
                raise REAError("artifact_changed", "Amostra mudou durante a análise; evidência descartada.")
            return redact_secrets({"ok": True, "code": "ok", "provider": "REA MCP", "version": SUPPORTED_VERSION,
                                   "sha256": digest, "size_bytes": stat.st_size, "target_executed": False,
                                   "evidence": evidence, "untrusted_content": True,
                                   "limitations": ["Análise estática; não comprova comportamento em execução nem ausência de malware.",
                                                   "Sem decompilador profundo habilitado neste adaptador; não produz pseudocódigo nativo."]})
        except (REAError, OSError, ValueError) as exc:
            return redact_secrets({"ok": False, "code": getattr(exc, "code", "rea_io_error"),
                                   "error": str(exc)[:4000], "target_executed": False,
                                   "fallback": "Use a análise estática local incorporada; nenhum resultado de decompilação foi simulado."})
        finally:
            if session:
                if opened and time.monotonic() < session.deadline - 1:
                    try:
                        session.tool("close_binary", {})
                    except (REAError, OSError):
                        pass
                session.close()
