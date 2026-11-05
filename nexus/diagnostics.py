"""Inventário somente leitura; nunca altera serviços ou configurações globais."""
from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

def run(args, timeout=12):
    try:
        result = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout, creationflags=0x08000000 if os.name == "nt" else 0)
        return {"ok": result.returncode == 0, "output": (result.stdout or result.stderr).strip()[:12000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}

def system_status():
    import psutil
    mem = psutil.virtual_memory()
    disk = shutil.disk_usage(Path(__file__).resolve().parent.parent)
    gpu = []
    result = run(["nvidia-smi", "--query-gpu=name,memory.total,memory.used,driver_version,utilization.gpu", "--format=csv,noheader,nounits"], 5)
    if result["ok"]:
        for line in result["output"].splitlines():
            try:
                name, total, used, driver, utilization = [p.strip() for p in line.split(",")]
                gpu.append({"name": name, "memory_total_mb": int(total), "memory_used_mb": int(used), "driver": driver, "utilization": int(utilization)})
            except ValueError:
                pass
    return {"ram_total_gb": round(mem.total / 2**30, 2), "ram_used_gb": round(mem.used / 2**30, 2), "ram_available_gb": round(mem.available / 2**30, 2), "ram_percent": mem.percent, "cpu_percent": psutil.cpu_percent(), "gpu": gpu, "disk_free_gb": round(disk.free / 2**30, 2), "process_ram_mb": round(psutil.Process().memory_info().rss / 2**20, 1)}

def diagnostic():
    import httpx
    cpu = platform.processor()
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                cpu = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    tools = {}
    for name, args in {"python": ["--version"], "node": ["--version"], "git": ["--version"], "ollama": ["--version"], "docker": ["version", "--format", "{{.Server.Version}}"], "wsl": ["--status"]}.items():
        path = shutil.which(name)
        tools[name] = {"path": path, "version": run([path, *args]) if path else None}
    tools["code"] = {"path": shutil.which("code")}
    tools["tor"] = {"path": shutil.which("tor")}
    ports = {}
    for port in (3000, 5432, 8000, 8080, 11434, 8765, 9050, 9150):
        with socket.socket() as sock:
            sock.settimeout(0.2)
            ports[str(port)] = "occupied" if sock.connect_ex(("127.0.0.1", port)) == 0 else "available"
    try:
        with httpx.Client(trust_env=False, timeout=10) as client:
            response = client.get("http://127.0.0.1:11434/api/tags")
            response.raise_for_status()
            ollama = response.json()
    except Exception as exc:
        ollama = {"error": str(exc)}
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "os": platform.platform(), "cpu": cpu, "logical_cpus": os.cpu_count(), "system": system_status(), "tools": tools, "ports": ports, "ollama": ollama, "budget": {"chat_weights_gb": 3.4, "chat_vram_expected_gb": "3.5–5.2; confirmar com benchmark", "context_tokens": 4096, "concurrent_generations": 1, "extra_disk_without_models_gb": "1–2 com navegador", "embeddings_optional_download_mb": 622, "warning": "Modelo 9B existente excede a VRAM disponível; não será carregado automaticamente."}}

if __name__ == "__main__":
    result = diagnostic()
    destination = Path(__file__).resolve().parent.parent / "reports" / "diagnostico.json"
    destination.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
