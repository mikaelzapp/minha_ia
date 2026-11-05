"""Bounded, read-only host observations; discovery never executes PATH tools."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

import psutil

from .common import redact_secrets, run_process


MAX_ROWS = 150
MAX_OUTPUT = 512 * 1024
SECTIONS = {"overview", "processes", "connections", "startup", "tasks", "defender", "events"}
# Literal scripts only. No model/user data is interpolated into PowerShell.
SCRIPTS = {
    "startup": "@(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object -First 150 Name,Location,User)",
    "tasks": "@(Get-ScheduledTask -ErrorAction Stop | Select-Object -First 150 TaskName,TaskPath,State,Description,@{n='Actions';e={@($_.Actions | Select-Object Execute,WorkingDirectory)}})",
    "defender": "Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,AntivirusSignatureAge,QuickScanAge,FullScanAge,IsTamperProtected,RebootRequired,ComputerState",
    "events": "@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction Stop | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message)",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _powershell(section: str) -> dict:
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    if os.name != "nt" or not executable.is_file():
        return {"ok": False, "code": "windows_unavailable", "error": "Consulta disponível somente no Windows com PowerShell nativo."}
    script = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $WarningPreference='SilentlyContinue'; "
              "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
              "try { $result = " + SCRIPTS[section] + "; ConvertTo-Json -InputObject $result -Depth 6 -Compress } "
              "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    try:
        done = run_process([str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           timeout=20, max_output=MAX_OUTPUT, redact_output=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": "tool_timeout", "error": "Consulta nativa excedeu 20 segundos."}
    except OSError as exc:
        return {"ok": False, "code": "tool_unavailable", "error": redact_secrets(str(exc)[:1000])}
    if done.get("timed_out"):
        return {"ok": False, "code": "tool_timeout", "error": "Consulta nativa excedeu 20 segundos."}
    if done.get("truncated"):
        return {"ok": False, "code": "output_limit", "error": "Saída nativa excedeu 512 KiB; não foi interpretada como resultado completo."}
    if not done.get("ok"):
        return {"ok": False, "code": "native_query_failed", "error": redact_secrets(done.get("output", "")[:4000]),
                "exit_code": done.get("exit_code"), "note": "Pode indicar cmdlet ausente, proteção de terceiros ou permissões insuficientes; não significa proteção desativada."}
    try:
        # Text redaction can introduce quotes inside JSON strings. Parse the
        # bounded native response first, then sanitize values recursively.
        data = redact_secrets(json.loads(done["output"].lstrip("\ufeff")))
    except (ValueError, UnicodeError):
        return {"ok": False, "code": "invalid_tool_output", "error": "PowerShell não retornou JSON válido."}
    return {"ok": True, "code": "ok", "data": data, "source": "Windows PowerShell / cmdlet nativo"}


def blue_status(section: str = "overview") -> dict:
    """Observe the current account's view. Never elevate or change protection."""
    if section not in SECTIONS:
        return {"ok": False, "code": "invalid_section", "error": "Seção desconhecida."}
    result = {"section": section, "timestamp": _now(), "read_only": True,
              "limitations": ["Retrato sob demanda, sem monitoramento contínuo ou detecção conclusiva de malware.",
                              "A conta atual pode não enxergar todos os processos, eventos e conexões."]}
    try:
        if section == "overview":
            memory = psutil.virtual_memory()
            data = {"os": platform.system(), "release": platform.release(), "machine": platform.machine(),
                    "boot_time": datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat(),
                    "cpu_percent": psutil.cpu_percent(interval=None),
                    "memory": {"total": memory.total, "available": memory.available, "percent": memory.percent},
                    "process_count": len(psutil.pids())}
            result.update(ok=True, code="ok", source="psutil / APIs do sistema", data=data)
        elif section == "processes":
            rows = []
            denied = 0
            for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "username", "create_time", "memory_info"], ad_value=None):
                try:
                    info = dict(proc.info)
                    memory = info.pop("memory_info", None)
                    info["rss_bytes"] = getattr(memory, "rss", None)
                    rows.append(info)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    denied += 1
                if len(rows) >= MAX_ROWS:
                    break
            result.update(ok=True, code="ok", source="psutil.process_iter", data=rows,
                          max_rows=MAX_ROWS, truncated=len(rows) >= MAX_ROWS, unavailable=denied)
            result["limitations"].append("Linhas de comando e ambiente dos processos não são coletados.")
        elif section == "connections":
            rows = []
            connections = psutil.net_connections(kind="inet")
            for connection in connections[:MAX_ROWS]:
                def addr(value):
                    return {"ip": value.ip, "port": value.port} if value else None
                rows.append({"pid": connection.pid, "family": str(connection.family), "type": str(connection.type),
                             "local": addr(connection.laddr), "remote": addr(connection.raddr), "status": connection.status})
            result.update(ok=True, code="ok", source="psutil.net_connections", data=rows,
                          max_rows=MAX_ROWS, truncated=len(connections) > MAX_ROWS)
        else:
            result.update(_powershell(section))
            result["max_rows"] = 50 if section == "events" else MAX_ROWS
            result["limitations"].append("Listagem limitada; ausência de um item nesta página não comprova sua ausência no computador.")
            if section in {"startup", "tasks"}:
                result["limitations"].append("Linhas de comando e argumentos são omitidos para reduzir exposição de credenciais.")
    except psutil.AccessDenied:
        result.update(ok=False, code="permission_denied", error="A conta atual não tem acesso a esta consulta; nenhuma elevação foi solicitada.")
    except (OSError, psutil.Error) as exc:
        result.update(ok=False, code="host_query_failed", error=str(exc)[:1000])
    return redact_secrets(result)


TOOLS = {
    "nmap": ("nmap", "nmap.exe"), "nuclei": ("nuclei", "nuclei.exe"),
    "zap": ("zap.bat", "zap.sh", "ZAP.exe"), "yara": ("yara", "yara64.exe", "yara.exe"),
    "yara_x": ("yr", "yr.exe", "yarax", "yarax.exe"), "capa": ("capa", "capa.exe"),
    "floss": ("floss", "floss.exe"), "semgrep": ("semgrep", "semgrep.exe"),
    "trivy": ("trivy", "trivy.exe"), "ghidra": ("analyzeHeadless.bat", "analyzeHeadless", "ghidraRun.bat", "ghidraRun"),
    "java": ("java", "java.exe"), "node": ("node", "node.exe"), "rea": ("rea", "rea.cmd", "rea-agents", "rea-agents.cmd"),
}


def provenance_inventory() -> dict:
    """Record bytes and paths; PATH discovery is not a provenance verdict."""
    tools = []
    for name, candidates in TOOLS.items():
        found = next((path for candidate in candidates if (path := shutil.which(candidate))), None)
        row = {"id": name, "name": name, "available": bool(found), "path": found,
               "version": None, "trusted": False, "executed": False,
               "code": "discovered_unverified" if found else "not_found",
               "mode": "discovery_only", "signature_verified": False,
               "note": "Localizado no PATH; hash identifica bytes, sem comprovar autoria ou segurança." if found
                       else "Não encontrado no PATH; pode existir fora dele. Nenhuma instalação automática."}
        if found:
            try:
                path = Path(found)
                info = path.stat()
                row["size_bytes"] = info.st_size
                if info.st_size <= 64 * 1024 * 1024 and path.is_file():
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                    row["sha256"] = digest.hexdigest()
                else:
                    row["hash_note"] = "Arquivo acima de 64 MiB ou não regular; hash não calculado."
            except OSError as exc:
                row.update(code="metadata_unavailable", note=str(exc)[:500])
        if name == "rea" and not found:
            from .rea import _package
            cached = _package()
            if cached.get("available"):
                row.update(available=True, path=cached["entry"], version=cached["version"],
                           sha256=cached["entry_sha256"], code="cached_package", mode="mcp_static_adapter",
                           note="Pacote npm cached conhecido; comunicação MCP e provedores têm verificação separada.")
        if name == "yara_x" and not found:
            try:
                distribution = importlib.metadata.distribution("yara-x")
                row.update(available=True, version=distribution.version, mode="python_package",
                           code="python_package", note="Distribuição Python local detectada sem importar ou executar o pacote.",
                           path=str(distribution.locate_file("yara_x")))
            except importlib.metadata.PackageNotFoundError:
                pass
        tools.append(row)
    return {"ok": True, "code": "ok", "timestamp": _now(), "tools": tools,
            "limitations": ["Inventário não executa utilitários encontrados nem baixa dependências.",
                            "Versões não verificadas permanecem null; disponibilidade não garante compatibilidade ou confiança."]}
