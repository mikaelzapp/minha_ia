"""Pinned portable JDK/Ghidra/ZAP acquisition; no processes or global writes.

Default is an offline preview. --install --authorized-download is an explicit
operator action. Nuclei uses the existing human-approved NEXUS installer API.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import sys
import time
from urllib.parse import urljoin, urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from nexus.tools import Tools

MIB = 1024 * 1024
HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"})
MANIFEST = "nexus-installation.json"
CHUNK = 128 * 1024


@dataclass(frozen=True)
class Package:
    tool: str
    version: str
    url: str
    archive_bytes: int
    sha256: str
    source: str
    archive_root: str
    max_unpacked: int
    required: tuple[str, ...]


PACKAGES = {
    "java": Package("java", "25.0.5+8",
        "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.zip",
        141285173, "636bdc13dc649ddc7d5921c5c7d23cca6e44fd19d662b45cc9c02135a6c96c42",
        "https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8",
        "jdk-25.0.5+8", 700 * MIB, ("bin/java.exe", "bin/javac.exe", "release")),
    "ghidra": Package("ghidra", "12.2",
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip",
        569712708, "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67",
        "https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build",
        "ghidra_12.2_PUBLIC", 2300 * MIB,
        ("Ghidra/application.properties", "Ghidra/Framework/Utility/lib/Utility.jar", "support/analyzeHeadless.bat")),
    "zap": Package("zap", "2.17.0",
        "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip",
        286652857, "94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0",
        "https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0",
        "ZAP_2.17.0", 1000 * MIB, ("zap-2.17.0.jar",)),
}


def safe(path: Path) -> Path:
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or item.exists() and Tools._is_link(item):
            raise ValueError("Install path contains a link/junction: " + str(item))
    if path.exists() and path.is_file() and path.stat().st_nlink != 1:
        raise ValueError("Install file has hardlinks: " + str(path))
    return path


def destination(package: Package, base: Path | None = None) -> Path:
    parent = safe(base if base is not None else ROOT / "data/security/tools")
    target = safe(parent / package.tool / package.version)
    if not target.is_relative_to(parent):
        raise ValueError("Installation escaped the fixed portable directory")
    return target


def checked_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.port not in {None, 443}
                or parsed.username is not None or parsed.password is not None or parsed.fragment
                or "\\" in url or any(ord(c) < 32 for c in url)):
            raise ValueError()
    except (ValueError, TypeError) as exc:
        raise ValueError("Download redirected outside the official HTTPS allowlist") from exc
    return parsed.hostname


def event(**value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


def check(deadline, cancel=None):
    if cancel is not None and cancel.is_set():
        raise ValueError("Installation cancelled")
    if time.monotonic() >= deadline:
        raise ValueError("Installation exceeded its deadline")


def digest_file(path):
    digest = hashlib.sha256()
    with safe(path).open("rb") as source:
        for block in iter(lambda: source.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def download(package, archive, *, deadline, emit=event, cancel=None):
    url, hosts = package.url, []
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=httpx.Timeout(30, connect=15),
                      headers={"User-Agent": "NEXUS-PortableRuntime/2.0", "Accept-Encoding": "identity"}) as client:
        for hop in range(6):
            check(deadline, cancel)
            hosts.append(checked_url(url))
            with client.stream("GET", url) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location or hop == 5:
                        raise ValueError("Missing or excessive official download redirects")
                    url = urljoin(url, location)
                    checked_url(url)
                    continue
                if response.status_code != 200:
                    raise ValueError("Official download returned HTTP " + str(response.status_code))
                length = response.headers.get("content-length")
                if length is not None and length != str(package.archive_bytes):
                    raise ValueError("HTTP download size differs from approved release")
                if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                    raise ValueError("Compressed HTTP transfer is not permitted")
                count, digest, last = 0, hashlib.sha256(), 0.0
                with safe(archive).open("xb") as target:
                    for block in response.iter_bytes(CHUNK):
                        check(deadline, cancel)
                        count += len(block)
                        if count > package.archive_bytes:
                            raise ValueError("Download exceeded approved release size")
                        target.write(block)
                        digest.update(block)
                        if time.monotonic() - last >= 2:
                            emit(tool=package.tool, stage="download", downloaded_bytes=count, total_bytes=package.archive_bytes)
                            last = time.monotonic()
                    target.flush()
                    os.fsync(target.fileno())
                if count != package.archive_bytes or digest.hexdigest() != package.sha256:
                    raise ValueError("Official archive size or SHA-256 mismatch; nothing installed")
                emit(tool=package.tool, stage="archive_verified", archive_bytes=count, sha256=digest.hexdigest())
                return {"redirect_hosts": hosts, "archive_sha256": digest.hexdigest(), "archive_bytes": count}
    raise ValueError("Official download did not return an archive")


def relative_name(name: str, root: str) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or len(name) > 1024 or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError("Unsafe archive member path")
    components = name.rstrip("/").split("/")
    if components[0] != root:
        raise ValueError("Archive member is outside the pinned distribution root")
    for part in components:
        if (not part or part in {".", ".."} or part != part.rstrip(" .") or any(ord(c) < 32 or c in '<>"|?*' for c in part)
                or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)):
            raise ValueError("Unsafe Windows archive member name")
    return tuple(components[1:])


def unpack(package, archive, stage, *, deadline, emit=event, cancel=None):
    """Validate the entire ZIP before creating any member; never extractall."""
    stage = safe(stage)
    with zipfile.ZipFile(safe(archive)) as container:
        entries = container.infolist()
        if not 1 <= len(entries) <= 40000:
            raise ValueError("Archive entry count exceeds limit")
        names, files, total, selected = set(), set(), 0, []
        for entry in entries:
            check(deadline, cancel)
            # ZipInfo.filename normalizes native backslashes on Windows and
            # truncates NUL. Inspect the original central-directory name first.
            parts = relative_name(entry.orig_filename, package.archive_root)
            key = "/".join(parts).casefold()
            mode = entry.external_attr >> 16
            directory = entry.is_dir()
            if key in names:
                raise ValueError("Duplicate or case-colliding archive member")
            names.add(key)
            if (entry.flag_bits & 1 or entry.external_attr & 0x400 or stat.S_ISLNK(mode)
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or bool(stat.S_IFMT(mode) == stat.S_IFDIR) != directory and stat.S_IFMT(mode) != 0
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or entry.file_size > 512 * MIB or entry.file_size < 0
                    or entry.file_size > max(1, entry.compress_size) * 1000):
                raise ValueError("Archive contains a link, device, encryption or excessive size/ratio")
            if not directory:
                if not parts or key == MANIFEST.casefold():
                    raise ValueError("Archive conflicts with installation metadata")
                files.add(key)
                total += entry.file_size
            if total > package.max_unpacked:
                raise ValueError("Archive unpacked size exceeds budget")
            selected.append((entry, parts))
        for key in names:
            pieces = key.split("/")
            if any("/".join(pieces[:n]) in files for n in range(1, len(pieces))):
                raise ValueError("Archive file shadows a directory")
        if any(name.casefold() not in files for name in package.required):
            raise ValueError("Archive lacks a required pinned runtime component")
        stage.mkdir(exist_ok=False)
        records, extracted, last = [], 0, 0.0
        for entry, parts in selected:
            check(deadline, cancel)
            if not parts:
                continue
            path = safe(stage.joinpath(*parts))
            if not path.is_relative_to(stage):
                raise ValueError("Extraction escaped its staging directory")
            if entry.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            safe(path.parent)
            count, digest = 0, hashlib.sha256()
            with container.open(entry) as source, path.open("xb") as target:
                while block := source.read(CHUNK):
                    check(deadline, cancel)
                    count += len(block)
                    extracted += len(block)
                    if count > entry.file_size or extracted > package.max_unpacked:
                        raise ValueError("Extracted data exceeded declared size")
                    target.write(block)
                    digest.update(block)
                target.flush()
            if count != entry.file_size:
                raise ValueError("Extracted member size mismatch")
            records.append({"path": "/".join(parts), "bytes": count, "sha256": digest.hexdigest()})
            if time.monotonic() - last >= 2:
                emit(tool=package.tool, stage="extract", extracted_bytes=extracted, total_bytes=total)
                last = time.monotonic()
        return records


def inventory(package, base=None):
    target = destination(package, base)
    if not target.exists():
        return {"installed": False, "path": str(target)}
    manifest = safe(target / MANIFEST)
    if not target.is_dir() or not manifest.is_file() or manifest.stat().st_size > 16 * MIB:
        raise ValueError("Existing destination has no valid installation provenance; no overwrite")
    record = json.loads(manifest.read_text(encoding="utf-8"))
    if (record.get("schema") != "nexus-portable-runtime/1" or record.get("tool") != package.tool
            or record.get("version") != package.version or record.get("archive_sha256") != package.sha256
            or record.get("archive_bytes") != package.archive_bytes or record.get("source_url") != package.url
            or not isinstance(record.get("files"), list) or not 1 <= len(record["files"]) <= 40000):
        raise ValueError("Existing runtime provenance differs from the pinned package")
    expected = set()
    for entry in record["files"]:
        parts = relative_name(package.archive_root + "/" + entry["path"], package.archive_root)
        key = "/".join(parts).casefold()
        if not parts or key in expected or key == MANIFEST.casefold():
            raise ValueError("Invalid runtime file manifest")
        expected.add(key)
        path = safe(target.joinpath(*parts))
        if (not path.is_file() or path.stat().st_size != entry["bytes"]
                or digest_file(path) != entry["sha256"]):
            raise ValueError("Existing runtime file differs from its installation hash")
    actual = set()
    for parent, dirs, files in os.walk(target, followlinks=False):
        for name in dirs + files:
            item = safe(Path(parent) / name)
            if item.is_file() and item != manifest:
                actual.add(item.relative_to(target).as_posix().casefold())
    if actual != expected:
        raise ValueError("Runtime contains untracked or missing files")
    return {"installed": True, "path": str(target), "files_verified": len(expected), "archive_sha256": package.sha256,
            "executed": False, "version_verified_by_execution": False}


def cleanup_owned(path, parent):
    path, parent = safe(path), safe(parent)
    if path.parent != parent or not path.name.startswith(".nexus-runtime-") or not path.is_relative_to(parent):
        raise ValueError("Refusing cleanup outside the exact owned installation temporary")
    if path.exists():
        for directory, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                safe(Path(directory) / name)
        shutil.rmtree(path)


def install(package, *, base=None, emit=event, cancel=None):
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("These pinned runtimes support Windows AMD64 only")
    target = destination(package, base)
    state = inventory(package, base)
    if state["installed"]:
        return {"ok": True, "code": "already_installed", **state}
    parent = safe(target.parent)
    parent.mkdir(parents=True, exist_ok=True)
    safe(parent)
    if shutil.disk_usage(parent).free < package.archive_bytes + package.max_unpacked + 128 * MIB:
        raise ValueError("Not enough disk for verified archive and bounded extraction")
    lock_path = parent / ".nexus-runtime-install.lock"
    lock_fd = os.open(safe(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    temporary = None
    try:
        os.write(lock_fd, str(os.getpid()).encode("ascii"))
        # Python's mkdtemp(mode=0700) installs a special DACL on recent Windows
        # builds. Moving that directory would retain an administrator-only ACL
        # after an elevated acquisition. Inherit the portable parent ACL using
        # a cryptographically random, exclusively created normal directory.
        temporary = parent / (".nexus-runtime-" + secrets.token_hex(16))
        temporary.mkdir(exist_ok=False)
        safe(temporary)
        deadline = time.monotonic() + 1800
        provenance = download(package, temporary / "archive.zip", deadline=deadline, emit=emit, cancel=cancel)
        stage = temporary / "runtime"
        records = unpack(package, temporary / "archive.zip", stage, deadline=deadline, emit=emit, cancel=cancel)
        record = {"schema": "nexus-portable-runtime/1", "tool": package.tool, "version": package.version,
                  "source_url": package.url, "release_url": package.source, **provenance,
                  "files": records, "executed": False, "version_verified_by_execution": False,
                  "signature_verified": False, "global_environment_changed": False}
        (stage / MANIFEST).write_text(json.dumps(record, ensure_ascii=True, indent=2), encoding="utf-8")
        check(deadline, cancel)
        safe(target)
        if target.exists():
            raise ValueError("Destination appeared during installation; no overwrite")
        stage.rename(target)
        emit(tool=package.tool, stage="installed", path=str(target), files=len(records), executed=False)
        return {"ok": True, "code": "installed", "installed": True, "path": str(target), "files": len(records),
                "archive_sha256": package.sha256, "executed": False, "global_environment_changed": False}
    finally:
        os.close(lock_fd)
        if temporary is not None:
            cleanup_owned(temporary, parent)
        safe(lock_path).unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", choices=list(PACKAGES), nargs="+", help="Fixed portable packages; installed sequentially")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--authorized-download", action="store_true", help="Operator confirms existing download authorization")
    args = parser.parse_args()
    if args.install and not args.authorized_download:
        parser.error("--install requires --authorized-download after explicit user authorization")
    results = []
    for tool in args.tools:
        package = PACKAGES[tool]
        if args.install:
            result = install(package)
        else:
            result = {"tool": tool, "package": asdict(package), **inventory(package), "preview_only": True,
                      "executes_tool": False, "changes_global_java": False}
        results.append(result)
        event(**result)
    return results


if __name__ == "__main__":
    main()
