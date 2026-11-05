"""Encerra somente a árvore do processo registrada pelo NEXUS."""
import json
import sys
from datetime import datetime
from pathlib import Path

import psutil

from .config import ROOT

def stop(state_file):
    path = Path(state_file).resolve()
    path.relative_to(ROOT / ".runtime")
    state = json.loads(path.read_text(encoding="utf-8-sig"))
    try:
        parent = psutil.Process(int(state["pid"]))
        expected = datetime.fromisoformat(state["started"].replace("Z", "+00:00")).timestamp()
        if abs(parent.create_time() - expected) > 0.1 or Path(parent.exe()).resolve() != Path(state["path"]).resolve():
            raise ValueError("PID reutilizado ou executável diferente: processo preservado.")
        descendants = parent.children(recursive=True)
        for process in reversed(descendants):
            try:
                process.terminate()
            except psutil.NoSuchProcess:
                pass
        parent.terminate()
        _, alive = psutil.wait_procs([*descendants, parent], timeout=8)
        for process in alive:
            try:
                process.kill()
            except psutil.NoSuchProcess:
                pass
        print(f"Árvore NEXUS {parent.pid} encerrada ({len(descendants)} descendentes).")
    except psutil.NoSuchProcess:
        print("O processo registrado já estava encerrado.")
    path.unlink(missing_ok=True)

if __name__ == "__main__":
    stop(sys.argv[1])
