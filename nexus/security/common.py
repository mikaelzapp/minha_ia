"""Contratos e utilitários sem classificação temática de solicitações."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile
import time

from ..memory import redact_secrets as _redact
from ..tools import Tools


class SecurityError(ValueError):
    def __init__(self, message, code="security_error", source="security"):
        super().__init__(message)
        self.code, self.source = code, source


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def redact_secrets(value):
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, dict):
        return {str(key): redact_secrets(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item) for item in value]
    if isinstance(value, bytes):
        return "[dados binários locais]"
    return value


def safe_file(path, *, maximum=20 * 1024 * 1024):
    path = Path(path).absolute()
    if any(Tools._is_link(parent) for parent in (path, *path.parents)):
        raise SecurityError("Links e junctions não são permitidos na análise.", "unsafe_file")
    if not path.is_file() or path.stat().st_nlink > 1:
        raise SecurityError("Arquivo regular necessário; hardlinks não são aceitos.", "unsafe_file")
    if path.stat().st_size > maximum:
        raise SecurityError("Arquivo excede o limite técnico da análise.", "file_too_large")
    return path.resolve()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_process(argv, *, timeout=30, max_output=512 * 1024, cwd=None, env=None, redact_output=True, cancel=None):
    """Executa só o analisador selecionado; nunca o arquivo suspeito.

    Structured-output callers may disable text redaction only to parse bounded
    JSON internally, then redact the parsed values before returning any result.
    """
    started = time.monotonic()
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(argv, shell=False, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT,
                                   creationflags=0x08000000 if os.name == "nt" else 0)
        timed_out = output_limited = cancelled = False
        try:
            while process.poll() is None:
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break
                if time.monotonic() - started > timeout:
                    timed_out = True
                    break
                if os.fstat(output.fileno()).st_size > max_output:
                    output_limited = True
                    break
                time.sleep(0.05)
            if timed_out or output_limited or cancelled:
                Tools._kill_tree(process)
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                Tools._kill_tree(process)
        output.seek(0)
        text = output.read(max_output).decode("utf-8", errors="replace")
        return {"ok": process.returncode == 0 and not timed_out and not output_limited and not cancelled,
                "exit_code": process.returncode, "output": redact_secrets(text) if redact_output else text, "timed_out": timed_out,
                "truncated": output_limited or os.fstat(output.fileno()).st_size > max_output, "cancelled": cancelled,
                "duration_seconds": round(time.monotonic() - started, 3)}
