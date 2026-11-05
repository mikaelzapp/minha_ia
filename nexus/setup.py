"""Configura apenas arquivos deste projeto e faz backup SQLite consistente."""
import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

from .config import DATA, ROOT, Settings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--embeddings", action="store_true")
    parser.add_argument("--thinking", action="store_true")
    parser.add_argument("--coding-model")
    parser.add_argument("--quality-mode", choices=("balanced", "careful"))
    parser.add_argument("--profile", choices=("standard", "unrestricted_local"))
    parser.add_argument("--computer-access", action="store_true")
    parser.add_argument("--context", type=int)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--backup")
    parser.add_argument("--lock", action="store_true")
    args = parser.parse_args()
    if args.lock:
        text = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True)
        (ROOT / "requirements-lock.txt").write_text(text, encoding="utf-8")
        print("Lock atualizado a partir do ambiente validado.")
        return
    if args.backup:
        destination = Path(args.backup).resolve()
        destination.relative_to(ROOT)
        destination.mkdir(parents=True, exist_ok=True)
        for filename in ("memory.sqlite3", "activity.sqlite3", "security/security.sqlite3", "library/agents.sqlite3", "developer/history.sqlite3", "research/research.sqlite3"):
            source = DATA / filename
            if source.exists():
                (destination / filename).parent.mkdir(parents=True, exist_ok=True)
                with sqlite3.connect(source) as src, sqlite3.connect(destination / filename) as dst:
                    src.backup(dst)
        if (DATA / "security" / "samples").exists():
            shutil.copytree(DATA / "security" / "samples", destination / "security" / "samples", dirs_exist_ok=True)
        if (DATA / "library" / "jobs.json").is_file():
            (destination / "library").mkdir(exist_ok=True)
            shutil.copy2(DATA / "library" / "jobs.json", destination / "library" / "jobs.json")
        if (DATA / "security" / "modules.json").is_file():
            (destination / "security").mkdir(exist_ok=True)
            shutil.copy2(DATA / "security" / "modules.json", destination / "security" / "modules.json")
        for name in ("config.json", "computer-access.json"):
            if (DATA / name).exists():
                shutil.copy2(DATA / name, destination / name)
        if (ROOT / "requirements-lock.txt").exists():
            shutil.copy2(ROOT / "requirements-lock.txt", destination / "requirements-lock.txt")
        if (ROOT / "profiles").exists():
            shutil.copytree(ROOT / "profiles", destination / "profiles", dirs_exist_ok=True)
        print("Backup SQLite consistente concluído.")
        return
    settings = Settings()
    updates = {}
    if args.embeddings:
        updates["embedding_model"] = "embeddinggemma"
    if args.thinking:
        updates["thinking"] = True
    if args.coding_model is not None:
        updates["coding_model"] = args.coding_model
    if args.quality_mode:
        updates["quality_mode"] = args.quality_mode
    if args.profile:
        updates["profile"] = args.profile
    if args.computer_access:
        updates["computer_enabled"] = True
    if args.context is not None:
        updates["context"] = args.context
    if args.temperature is not None:
        updates["temperature"] = args.temperature
    settings.update(updates)
    print("Configuração local gravada; nenhum serviço global alterado.")

if __name__ == "__main__":
    main()
