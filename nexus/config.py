"""Configuração restrita a loopback, persistida somente dentro do projeto."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
WORKSPACES = ROOT / "workspaces"
for directory in (DATA, WORKSPACES, ROOT / "reports"):
    directory.mkdir(exist_ok=True)

def load_dotenv() -> None:
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                if key.strip().startswith(("NEXUS_", "OLLAMA_")):
                    os.environ.setdefault(key.strip(), value.strip().strip("\"'"))

load_dotenv()

def loopback_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.username or parsed.password:
        raise ValueError("O motor e serviços auxiliares precisam usar URL local sem credenciais.")
    return url.rstrip("/")

DEFAULTS = {
    "model": os.getenv("NEXUS_MODEL", "qwen3.5:4b-q4_K_M"),
    "context": int(os.getenv("NEXUS_CONTEXT", "4096")),
    "temperature": float(os.getenv("NEXUS_TEMPERATURE", "0.3")),
    "thinking": os.getenv("NEXUS_THINKING", "true").lower() == "true",
    "coding_model": os.getenv("NEXUS_CODING_MODEL", ""),
    "quality_mode": os.getenv("NEXUS_QUALITY_MODE", "balanced"),
    "profile": os.getenv("NEXUS_PROFILE", "standard"),
    "computer_enabled": os.getenv("NEXUS_COMPUTER_ENABLED", "false").lower() == "true",
    "concurrency": min(2, max(1, int(os.getenv("NEXUS_CONCURRENCY", "1")))),
    "ollama_url": loopback_url(os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")),
    "embedding_model": os.getenv("NEXUS_EMBEDDING_MODEL", ""),
    "searxng_url": os.getenv("NEXUS_SEARXNG_URL", ""),
    "tor_enabled": os.getenv("NEXUS_TOR_ENABLED", "false").lower() == "true",
    "tor_proxy": os.getenv("NEXUS_TOR_PROXY", "socks5h://127.0.0.1:9050"),
}

class Settings:
    def __init__(self):
        self.path = DATA / "config.json"
        self.values = dict(DEFAULTS)
        if self.path.exists():
            self.update(json.loads(self.path.read_text(encoding="utf-8")), save=False)

    def update(self, updates: dict, save: bool = True) -> dict:
        candidate = dict(self.values)
        candidate.update({k: v for k, v in updates.items() if k in DEFAULTS})
        candidate["context"] = max(2048, min(8192, int(candidate["context"])))
        candidate["temperature"] = max(0.0, min(2.0, float(candidate["temperature"])))
        candidate["concurrency"] = max(1, min(2, int(candidate["concurrency"])))
        candidate["tor_enabled"] = candidate["tor_enabled"] is True
        candidate["thinking"] = candidate["thinking"] is True
        candidate["computer_enabled"] = candidate["computer_enabled"] is True
        if candidate["quality_mode"] not in ("balanced", "careful"):
            raise ValueError("Qualidade deve ser balanced ou careful.")
        from .profiles import validate_profile
        validate_profile(candidate["profile"])
        if not isinstance(candidate["coding_model"], str) or len(candidate["coding_model"]) > 200:
            raise ValueError("Modelo de programação inválido.")
        candidate["ollama_url"] = loopback_url(str(candidate["ollama_url"]))
        if candidate["searxng_url"]:
            candidate["searxng_url"] = loopback_url(str(candidate["searxng_url"]))
        if not isinstance(candidate["model"], str) or not candidate["model"].strip():
            raise ValueError("Escolha um modelo local válido.")
        self.values = candidate
        if save:
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(candidate, indent=2, ensure_ascii=False), encoding="utf-8")
            temporary.replace(self.path)
        return self.public()

    def public(self):
        return dict(self.values)

    def __getitem__(self, key):
        return self.values[key]
