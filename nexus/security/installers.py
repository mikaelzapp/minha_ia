"""Human-approved, pinned portable Nuclei installer. Never executes a tool.

The HTTP API owns human approval and the shared heavy-operation semaphore. This
module has no URL arguments, shell, PATH writes, update discovery or subprocess.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import secrets
import threading
import time
from urllib.parse import urljoin, urlsplit
import zipfile

import httpx

from .common import SecurityError, safe_file, sha256_file, utcnow
from ..tools import Tools


VERSION = "3.11.1"
ARCHIVE_URL = "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip"
ARCHIVE_BYTES = 46_067_128
ARCHIVE_SHA256 = "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2"
RELEASE_URL = "https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1"
MAX_UNPACKED = 200 * 1024 * 1024
MAX_RATIO = 100
DEADLINE_SECONDS = 180
ALLOWED_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"})
_INSTALL_LOCK = threading.Lock()


def _supported():
    return platform.system() == "Windows" and platform.machine().casefold() in {"amd64", "x86_64"}


def _safe_ancestry(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or item.exists() and Tools._is_link(item):
            raise SecurityError("Caminho de instalação contém link ou junction.", "unsafe_install_path")
    return path


def _directory(path):
    path = _safe_ancestry(path)
    path.mkdir(parents=True, exist_ok=True)
    _safe_ancestry(path)
    if not path.is_dir() or path.resolve() != path:
        raise SecurityError("Diretório de instalação inválido.", "unsafe_install_path")
    return path


def _check_url(url):
    try:
        value = urlsplit(url)
        if (value.scheme != "https" or value.hostname not in ALLOWED_HOSTS or value.port not in {None, 443}
                or value.username is not None or value.password is not None or value.fragment or "\\" in url
                or any(ord(char) < 32 for char in url)):
            raise ValueError()
    except (TypeError, ValueError) as exc:
        raise SecurityError("Redirecionamento do download fora das origens HTTPS oficiais permitidas.", "download_redirect_denied") from exc
    return value.hostname


def _check(cancel, deadline):
    if cancel is not None and cancel.is_set():
        raise SecurityError("Instalação cancelada; nenhum executável foi iniciado.", "cancelled")
    if time.monotonic() > deadline:
        raise SecurityError("Download/instalação excedeu o tempo limite.", "install_timeout")


def _event(emit, event):
    if emit:
        emit(event)


def _cleanup_owned(path, parent):
    """Only remove the exact temporary directory created by this invocation."""
    path, parent = _safe_ancestry(path), _safe_ancestry(parent)
    if path.parent != parent or not path.name.startswith(".nexus-install-") or not path.resolve().is_relative_to(parent.resolve()):
        raise SecurityError("Limpeza recusada: temporário fora da pasta de instalação.", "unsafe_install_cleanup")
    if path.exists():
        shutil.rmtree(path)


class NucleiInstaller:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir).absolute()
        self.parent = self.data_dir / "security" / "tools" / "nuclei"
        self.destination = self.parent / VERSION
        self.executable = self.destination / "nuclei.exe"
        self.manifest = self.destination / "installation.json"

    def inventory(self):
        result = {"tool": "nuclei", "version": VERSION, "version_verified": False, "executed": False,
                  "supported_platform": _supported(), "installed": False, "available": False,
                  "path": str(self.executable), "source_url": ARCHIVE_URL, "release_url": RELEASE_URL,
                  "manual_installation": {"zap": True, "ghidra": True, "java_jdk": True}}
        try:
            _safe_ancestry(self.destination)
            if not self.destination.exists():
                return {**result, "ok": True, "code": "not_installed"}
            executable = safe_file(self.executable, maximum=MAX_UNPACKED)
            manifest = safe_file(self.manifest, maximum=16 * 1024)
            record = json.loads(manifest.read_text(encoding="utf-8"))
            if (not isinstance(record, dict) or record.get("schema") != "nexus-portable-tool/1" or
                    record.get("tool") != "nuclei" or record.get("version") != VERSION or record.get("archive_sha256") != ARCHIVE_SHA256 or
                    record.get("archive_bytes") != ARCHIVE_BYTES or record.get("source_url") != ARCHIVE_URL or
                    record.get("exe_sha256") != sha256_file(executable) or record.get("exe_bytes") != executable.stat().st_size):
                raise SecurityError("Instalação local não coincide com a proveniência registrada.", "installation_conflict")
            with executable.open("rb") as stream:
                if stream.read(2) != b"MZ":
                    raise SecurityError("Arquivo local não possui cabeçalho PE esperado.", "installation_conflict")
            return {**result, "ok": True, "code": "installed", "installed": True,
                    "available": _supported(), "sha256": record["exe_sha256"], "provenance": record,
                    "note": "Release identificada pelo download verificado; versão do processo ainda não foi executada."}
        except (ValueError, OSError) as exc:
            return {**result, "ok": False, "code": "unsafe_install_path" if getattr(exc, "code", "") == "unsafe_install_path" else "installation_conflict",
                    "error": "Arquivo existente, integridade ou caminho impedem esta instalação; nada foi sobrescrito."}

    def preview(self):
        state = self.inventory()
        if not _supported():
            raise SecurityError("Instalação automática inicial suporta somente Windows AMD64; demais mecanismos têm configuração manual.", "unsupported_install_platform")
        if not state["ok"]:
            raise SecurityError(state["error"], state["code"])
        existing = _safe_ancestry(self.parent)
        while not existing.exists():
            existing = existing.parent
        required = ARCHIVE_BYTES + MAX_UNPACKED + 64 * 1024 * 1024
        free = shutil.disk_usage(existing).free
        if free < required:
            raise SecurityError("Espaço livre insuficiente para download e extração temporária verificados.", "install_disk_budget")
        return {"tool": "nuclei", "version": VERSION, "platform": "windows_amd64", "source_url": ARCHIVE_URL,
                "release_url": RELEASE_URL, "download_bytes": ARCHIVE_BYTES, "archive_sha256": ARCHIVE_SHA256,
                "destination": str(self.executable), "installed": state["installed"], "free_disk_bytes": free,
                "required_free_disk_bytes": required, "requires_approval": True, "executes_tool": False,
                "impact": ["Baixar exclusivamente a release oficial fixada, verificar tamanho/SHA-256 e extrair somente nuclei.exe.",
                           "Gravar somente pasta portátil do NEXUS; não altera PATH nem instala serviço.",
                           "Executar/configurar o scanner é uma permissão operacional separada."],
                "limitations": ["Hash não é assinatura digital; cabeçalho MZ não valida execução nem versão do processo.",
                                "ZAP, Ghidra e JDK permanecem com instalação/configuração manual."]}

    def _download(self, archive, cancel, deadline, emit):
        cache = self.data_dir / "security/tools/downloads/nuclei_3.11.1_windows_amd64.zip"
        if cache.exists() or cache.is_symlink():
            cache = safe_file(cache, maximum=ARCHIVE_BYTES)
            count, digest = 0, hashlib.sha256()
            with cache.open("rb") as source, archive.open("xb") as target:
                while chunk := source.read(128 * 1024):
                    _check(cancel, deadline)
                    count += len(chunk)
                    if count > ARCHIVE_BYTES:
                        raise SecurityError("Cache excede o tamanho fixado da release.", "download_size_mismatch")
                    target.write(chunk)
                    digest.update(chunk)
                target.flush()
                os.fsync(target.fileno())
            if count != ARCHIVE_BYTES or digest.hexdigest() != ARCHIVE_SHA256:
                raise SecurityError("Cache local não corresponde ao checksum oficial aprovado.", "download_hash_mismatch")
            _event(emit, {"stage": "archive_verified", "downloaded_bytes": count, "total_bytes": ARCHIVE_BYTES,
                          "archive_sha256": digest.hexdigest(), "source": "verified_local_cache"})
            return {"redirect_hosts": [], "archive_bytes": count, "archive_sha256": digest.hexdigest(), "archive_source": "verified_local_cache"}
        url, hosts = ARCHIVE_URL, []
        timeout = httpx.Timeout(connect=10, read=10, write=10, pool=10)
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout,
                          headers={"User-Agent": "NEXUS-PortableInstaller/2.0", "Accept-Encoding": "identity"}) as client:
            for hop in range(6):
                _check(cancel, deadline)
                host = _check_url(url)
                hosts.append(host)
                with client.stream("GET", url) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location or hop == 5:
                            raise SecurityError("Redirecionamento ausente ou excessivo no download oficial.", "download_redirect_denied")
                        url = urljoin(url, location)
                        _check_url(url)
                        continue
                    if response.status_code != 200:
                        raise SecurityError("Fonte oficial não disponibilizou o arquivo esperado.", "download_http_error")
                    content_length = response.headers.get("content-length")
                    if content_length is not None and content_length != str(ARCHIVE_BYTES):
                        raise SecurityError("Tamanho HTTP diverge da release aprovada.", "download_size_mismatch")
                    if response.headers.get("content-encoding", "identity").casefold() not in {"", "identity"}:
                        raise SecurityError("Download comprimido no transporte não é permitido.", "download_encoding")
                    digest, count, last_event = hashlib.sha256(), 0, 0.0
                    with archive.open("xb") as stream:
                        for chunk in response.iter_bytes(chunk_size=128 * 1024):
                            _check(cancel, deadline)
                            if count + len(chunk) > ARCHIVE_BYTES:
                                raise SecurityError("Download excede o tamanho fixado da release.", "download_size_mismatch")
                            stream.write(chunk)
                            count += len(chunk)
                            digest.update(chunk)
                            if time.monotonic() - last_event >= 0.2:
                                _event(emit, {"stage": "download", "downloaded_bytes": count, "total_bytes": ARCHIVE_BYTES,
                                              "total_source": "official_pinned_release_metadata"})
                                last_event = time.monotonic()
                        stream.flush()
                        os.fsync(stream.fileno())
                    _check(cancel, deadline)
                    if count != ARCHIVE_BYTES:
                        raise SecurityError("Download incompleto; arquivo não será instalado.", "download_size_mismatch")
                    if digest.hexdigest() != ARCHIVE_SHA256:
                        raise SecurityError("SHA-256 do download diverge da referência oficial aprovada.", "download_hash_mismatch")
                    _event(emit, {"stage": "archive_verified", "downloaded_bytes": count, "total_bytes": ARCHIVE_BYTES,
                                  "archive_sha256": digest.hexdigest()})
                    return {"redirect_hosts": hosts, "archive_bytes": count, "archive_sha256": digest.hexdigest()}
        raise SecurityError("Fonte oficial não retornou arquivo final.", "download_http_error")

    def _unpack(self, archive, stage, cancel, deadline, emit):
        with zipfile.ZipFile(archive) as container:
            entries = container.infolist()
            if not 1 <= len(entries) <= 16:
                raise SecurityError("Quantidade de entradas ZIP fora do contrato.", "unsafe_tool_archive")
            names, total, selected = set(), 0, None
            docs = {"LICENSE", "LICENSE.md", "LICENSE.txt", "README", "README.md", "README.txt", "CHANGELOG.md",
                    "README_CN.md", "README_ES.md", "README_ID.md", "README_JP.md", "README_KR.md", "README_PT-BR.md", "README_TR.md"}
            for entry in entries:
                _check(cancel, deadline)
                mode = entry.external_attr >> 16
                if (entry.filename in names or entry.filename not in docs | {"nuclei.exe"} or
                        entry.is_dir() or "/" in entry.filename or "\\" in entry.filename or ":" in entry.filename or
                        entry.flag_bits & 1 or entry.external_attr & 0x400 or stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in {0, stat.S_IFREG} or
                        entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED} or
                        entry.file_size < 0 or entry.file_size > MAX_UNPACKED or
                        entry.file_size > max(1, entry.compress_size) * MAX_RATIO):
                    raise SecurityError("ZIP contém entrada, link, formato ou proporção não permitidos.", "unsafe_tool_archive")
                names.add(entry.filename)
                total += entry.file_size
                if total > MAX_UNPACKED:
                    raise SecurityError("ZIP excede orçamento de 200 MiB descomprimidos.", "unsafe_tool_archive")
                if entry.filename == "nuclei.exe":
                    selected = entry
            if selected is None or selected.file_size < 2:
                raise SecurityError("ZIP não contém exatamente nuclei.exe regular.", "unsafe_tool_archive")
            executable = stage / "nuclei.exe"
            count, digest, last_event = 0, hashlib.sha256(), 0.0
            with container.open(selected) as source, executable.open("xb") as target:
                first = source.read(2)
                if first != b"MZ":
                    raise SecurityError("Executável não possui cabeçalho PE esperado; não será iniciado.", "invalid_tool_header")
                target.write(first)
                digest.update(first)
                count = len(first)
                while True:
                    _check(cancel, deadline)
                    chunk = source.read(128 * 1024)
                    if not chunk:
                        break
                    if count + len(chunk) > selected.file_size or count + len(chunk) > MAX_UNPACKED:
                        raise SecurityError("Extração excede orçamento ou tamanho declarado.", "unsafe_tool_archive")
                    target.write(chunk)
                    digest.update(chunk)
                    count += len(chunk)
                    if time.monotonic() - last_event >= 0.2:
                        _event(emit, {"stage": "extract", "written_bytes": count, "total_bytes": selected.file_size})
                        last_event = time.monotonic()
                target.flush()
                os.fsync(target.fileno())
            if count != selected.file_size:
                raise SecurityError("Extração incompleta.", "unsafe_tool_archive")
            _event(emit, {"stage": "extracted", "written_bytes": count, "total_bytes": selected.file_size})
            return {"exe_sha256": digest.hexdigest(), "exe_bytes": count}

    def run(self, cancel=None, emit=None):
        temporary, acquired = None, False
        try:
            _check(cancel, time.monotonic() + DEADLINE_SECONDS)
            preview = self.preview()
            if preview["installed"]:
                return {**self.inventory(), "executed": False, "code": "already_installed", "requires_configuration_approval": True}
            acquired = _INSTALL_LOCK.acquire(blocking=False)
            if not acquired:
                raise SecurityError("Outra instalação portátil está em andamento.", "installer_busy")
            parent = _directory(self.parent)
            if self.destination.exists():
                raise SecurityError("Destino já existe; instalação não sobrescreve arquivos.", "installation_conflict")
            # Inherit the destination ACL. Windows mkdtemp(mode=0700) can bind
            # files to the installing token and deny the normal NEXUS process.
            temporary = parent / (".nexus-install-" + secrets.token_hex(16))
            temporary.mkdir(exist_ok=False)
            _safe_ancestry(temporary)
            stage = _directory(temporary / "payload")
            deadline = time.monotonic() + DEADLINE_SECONDS
            download = self._download(temporary / "release.zip", cancel, deadline, emit)
            extracted = self._unpack(temporary / "release.zip", stage, cancel, deadline, emit)
            _check(cancel, deadline)
            record = {"schema": "nexus-portable-tool/1", "tool": "nuclei", "version": VERSION,
                      "version_source": "pinned_official_release", "version_verified_by_execution": False,
                      "source_url": ARCHIVE_URL, "release_url": RELEASE_URL, "installed_at": utcnow(),
                      **download, **extracted, "signature_verified": False, "executed": False}
            with (stage / "installation.json").open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(record, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            _safe_ancestry(self.destination)
            if self.destination.exists():
                raise SecurityError("Destino surgiu durante o download; nada foi sobrescrito.", "installation_conflict")
            _check(cancel, deadline)
            # Windows os.rename fails if the destination exists. The installer
            # supports only Windows AMD64; no replace/overwrite flag is used.
            os.rename(stage, self.destination)
            result = {"ok": True, "installed": True, "code": "installed", "tool": "nuclei", "version": VERSION,
                      "version_verified": False, "path": str(self.executable), "sha256": record["exe_sha256"],
                      "provenance": record, "executed": False, "requires_configuration_approval": True}
            # The installation is already committed; a UI event cannot undo it
            # or cause the result to claim failure after files were installed.
            try:
                _event(emit, {"stage": "installed", "path": str(self.executable), "exe_sha256": record["exe_sha256"],
                              "version": VERSION, "version_verified": False})
            except Exception:
                result["progress_note"] = "Instalação concluída; consumidor de progresso indisponível."
            return result
        except (ValueError, OSError, httpx.HTTPError, zipfile.BadZipFile, RuntimeError) as exc:
            return {"ok": False, "installed": False, "executed": False, "tool": "nuclei",
                    "code": getattr(exc, "code", "installer_failed"),
                    "error": str(exc)[:500] if isinstance(exc, SecurityError) else "Falha de transporte, arquivo ou instalação; nenhuma ferramenta foi executada."}
        finally:
            try:
                if temporary is not None:
                    _cleanup_owned(temporary, self.parent)
            finally:
                if acquired:
                    _INSTALL_LOCK.release()
