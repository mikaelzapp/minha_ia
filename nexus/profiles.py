"""Perfis de conversa; não concedem permissões ao executor do computador."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .config import ROOT

PROFILE_DIR = ROOT / "profiles"
DEFINITIONS = {
    "standard": {"name": "NEXUS PADRÃO", "preserve_original": False, "instructions_file": "standard.md"},
    "unrestricted_local": {"name": "NEXUS UNRESTRICTED — LOCAL", "preserve_original": True,
                           "instructions_file": "unrestricted_local.md"},
}


def validate_profile(value):
    if not isinstance(value, str) or value not in DEFINITIONS:
        raise ValueError("Perfil desconhecido. Use standard ou unrestricted_local.")
    return value


def list_profiles():
    return [{"id": key, **value} for key, value in DEFINITIONS.items()]


def role_instructions(role):
    files = {"coder": "coder.md", "reviewer": "reviewer.md", "security_center": "security_center.md"}
    if role not in files:
        raise ValueError("Papel de instruções desconhecido.")
    return _read(files[role])


def _read(name):
    path = PROFILE_DIR / name
    if PROFILE_DIR.is_symlink() or path.is_symlink():
        raise ValueError("Arquivos de perfil precisam ser arquivos locais, sem links.")
    try:
        if path.stat().st_size > 24_000:
            raise ValueError("Arquivo de perfil excede 24 KB; reduza as instruções para a janela do modelo.")
        text = path.read_text(encoding="utf-8-sig").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Não foi possível ler profiles/{name}. Restaure o arquivo pelo backup.") from exc
    if not text:
        raise ValueError(f"O arquivo profiles/{name} está vazio.")
    return text


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    preserve_original: bool
    instructions: str
    operations: str
    specialties: dict
    instructions_sha256: str

    def public(self):
        return {"id": self.id, **DEFINITIONS[self.id], "instructions_sha256": self.instructions_sha256}


def load_profile(value="standard"):
    if isinstance(value, Profile):
        return value
    key = validate_profile(value)
    definition = DEFINITIONS[key]
    instructions = _read(definition["instructions_file"])
    operations = _read("operations.md")
    agents_source = _read("agents.json")
    try:
        agents = json.loads(agents_source)
        common = agents["standard"]
        overrides = agents.get(key, {}) if key != "standard" else {}
        if not isinstance(common, dict) or not isinstance(overrides, dict):
            raise ValueError("As especialidades devem ser objetos JSON.")
        specialties = {**common, **overrides}
        if not all(isinstance(name, str) and isinstance(text, str) and text.strip() for name, text in specialties.items()):
            raise ValueError("Cada especialidade precisa ter instruções textuais.")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("profiles/agents.json inválido; confira os objetos standard e unrestricted_local.") from exc
    digest = hashlib.sha256((instructions + "\n" + operations + "\n" + agents_source).encode("utf-8")).hexdigest()
    return Profile(key, definition["name"], definition["preserve_original"], instructions, operations, specialties, digest)
