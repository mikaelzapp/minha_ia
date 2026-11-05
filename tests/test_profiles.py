"""Editable profiles and original-output streaming; no real model or user data."""
import dataclasses
import json
import shutil

import httpx
import pytest

import nexus.config as config
import nexus.profiles as profiles
from nexus.engine import ModelError, system_prompt
from test_engine_quality import collect, done, local_http


@pytest.mark.parametrize("body", ["not JSON", "[]"])
def test_invalid_capabilities_are_identified_as_model_service_protocol_error(monkeypatch, body):
    import httpx
    import nexus.engine as engine
    original_client = httpx.AsyncClient

    def handler(request):
        assert request.url.path == "/api/show"
        return httpx.Response(200, text=body)

    monkeypatch.setattr(engine.httpx, "AsyncClient", lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs))
    with pytest.raises(ModelError) as caught:
        collect(preserve_original=True)
    assert caught.value.source == "model_service"
    assert caught.value.code == "model_protocol_error"


@pytest.fixture
def profile_files(tmp_path, monkeypatch):
    destination = tmp_path / "profiles"
    shutil.copytree(profiles.PROFILE_DIR, destination)
    monkeypatch.setattr(profiles, "PROFILE_DIR", destination)
    return destination


@pytest.mark.parametrize("key,original", [("standard", False), ("unrestricted_local", True)])
def test_known_profiles_have_distinct_output_contracts(profile_files, key, original):
    profile = profiles.load_profile(key)
    assert profile.id == key and profile.preserve_original is original
    assert profile.instructions and profile.operations and profile.specialties["coder"]
    assert len(profile.instructions_sha256) == 64
    assert profile.public()["preserve_original"] is original
    assert profiles.load_profile(profile) is profile
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.instructions = "changed"


@pytest.mark.parametrize("value", [None, "", "UNRESTRICTED", "../unrestricted_local", "standard.md",
                                  "C:/profiles/standard", "standard/../standard", 1, True, {}, []])
def test_unknown_profiles_and_traversal_are_rejected_before_file_access(monkeypatch, value):
    def unexpected_read(*_args):
        pytest.fail("An unknown profile must not select any filesystem path")
    monkeypatch.setattr(profiles, "_read", unexpected_read)
    with pytest.raises(ValueError, match="Perfil desconhecido"):
        profiles.load_profile(value)


def test_catalog_is_public_metadata_and_cannot_mutate_definitions():
    first = profiles.list_profiles()
    assert {row["id"] for row in first} == {"standard", "unrestricted_local"}
    assert all(set(row) == {"id", "name", "preserve_original", "instructions_file"} for row in first)
    first[0]["name"] = "tampered"
    assert profiles.list_profiles()[0]["name"] != "tampered"


def test_editable_instructions_reload_and_existing_snapshot_stays_unchanged(profile_files):
    path = profile_files / "unrestricted_local.md"
    path.write_text("FIRST LOCAL INSTRUCTIONS", encoding="utf-8")
    first = profiles.load_profile("unrestricted_local")
    path.write_text("SECOND LOCAL INSTRUCTIONS", encoding="utf-8")
    second = profiles.load_profile("unrestricted_local")
    assert first.instructions == "FIRST LOCAL INSTRUCTIONS"
    assert second.instructions == "SECOND LOCAL INSTRUCTIONS"
    assert first.instructions_sha256 != second.instructions_sha256
    assert "FIRST LOCAL INSTRUCTIONS" in system_prompt("coder", "CHAT", "workspace", profile=first)
    assert "SECOND LOCAL INSTRUCTIONS" in system_prompt("coder", "CHAT", "workspace", profile=second)


def test_operations_and_agent_overrides_are_external_and_affect_fingerprint(profile_files):
    previous = profiles.load_profile("unrestricted_local")
    (profile_files / "operations.md").write_text("LOCAL EXECUTOR CONTRACT", encoding="utf-8")
    agents_path = profile_files / "agents.json"
    agents = json.loads(agents_path.read_text(encoding="utf-8"))
    agents["unrestricted_local"]["coder"] = "LOCAL CODER SPECIALTY"
    agents_path.write_text(json.dumps(agents), encoding="utf-8")
    current = profiles.load_profile("unrestricted_local")
    prompt = system_prompt("coder", "CODE", "workspace", profile=current)
    assert "LOCAL EXECUTOR CONTRACT" in prompt and "LOCAL CODER SPECIALTY" in prompt
    assert current.specialties["architect"] == agents["standard"]["architect"]
    assert current.instructions_sha256 != previous.instructions_sha256


@pytest.mark.parametrize("filename", ["standard.md", "operations.md", "agents.json"])
def test_missing_profile_dependency_fails_explicitly(profile_files, filename):
    (profile_files / filename).unlink()
    with pytest.raises(ValueError, match="Não foi possível ler"):
        profiles.load_profile("standard")


@pytest.mark.parametrize("content,match", [(b"  \n", "está vazio"), (b"x" * 24001, "excede 24 KB"),
                                          (b"\xff\xfe\x80", "Não foi possível ler")])
def test_empty_oversized_and_non_utf8_instructions_fail(profile_files, content, match):
    (profile_files / "standard.md").write_bytes(content)
    with pytest.raises(ValueError, match=match):
        profiles.load_profile("standard")


@pytest.mark.parametrize("invalid", ["{", "[]", '{}', '{"standard":[]}',
                                    '{"standard":{"coder":null}}',
                                    '{"standard":{"coder":" "}}',
                                    '{"standard":{},"unrestricted_local":[]}'])
def test_malformed_agents_never_silently_replace_valid_instructions(profile_files, invalid):
    (profile_files / "agents.json").write_text(invalid, encoding="utf-8")
    with pytest.raises(ValueError, match="agents.json inválido"):
        profiles.load_profile("unrestricted_local")


@pytest.mark.parametrize("linked", ["directory", "instructions"])
def test_linked_profile_directory_or_instruction_is_rejected(profile_files, monkeypatch, linked):
    from pathlib import Path
    target = profile_files if linked == "directory" else profile_files / "standard.md"
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == target or original(self))
    with pytest.raises(ValueError, match="sem links"):
        profiles.load_profile("standard")


@pytest.mark.parametrize("role", ["coder", "reviewer"])
def test_external_role_instructions_reload_from_known_files(profile_files, role):
    path = profile_files / (role + ".md")
    path.write_text("FIRST ROLE", encoding="utf-8")
    assert profiles.role_instructions(role) == "FIRST ROLE"
    path.write_text("SECOND ROLE", encoding="utf-8")
    assert profiles.role_instructions(role) == "SECOND ROLE"
    with pytest.raises(ValueError, match="Papel de instruções desconhecido"):
        profiles.role_instructions("../" + role)


def test_profile_setting_roundtrips_and_invalid_update_is_atomic(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA", tmp_path)
    settings = config.Settings()
    for key in ("standard", "unrestricted_local"):
        settings.update({"profile": key, "quality_mode": "careful"})
        assert config.Settings()["profile"] == key
        assert config.Settings()["quality_mode"] == "careful"
    original_values, original_bytes = settings.public(), settings.path.read_bytes()
    for invalid in (None, "../standard", "unknown", 7, []):
        with pytest.raises(ValueError, match="Perfil desconhecido"):
            settings.update({"profile": invalid, "context": 8192, "temperature": 1.5})
        assert settings.public() == original_values
        assert settings.path.read_bytes() == original_bytes


def test_legacy_settings_without_profile_load_with_standard_default(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA", tmp_path)
    monkeypatch.setitem(config.DEFAULTS, "profile", "standard")
    legacy = {"model": "legacy:local", "quality_mode": "careful", "context": 4096}
    (tmp_path / "config.json").write_text(json.dumps(legacy), encoding="utf-8")
    settings = config.Settings()
    assert settings["profile"] == "standard"
    assert settings["model"] == "legacy:local" and settings["quality_mode"] == "careful"


@pytest.mark.parametrize("answer", ["", " \n\t ", "Não posso ajudar com esse pedido.",
                                   "  Código e crítica: resposta original.\n"])
def test_original_output_contract_never_retries_or_rewrites_model_text(local_http, answer):
    local_http["responses"] = [[done(answer, reason="length")]]
    events = collect(thinking=True, preserve_original=True)
    assert len(local_http["requests"]) == 1
    assert "".join(row["content"] for row in events if row["type"] == "token") == answer
    assert not [row for row in events if row["type"] == "status" and "Tentando" in row["content"]]
    assert events[-1]["done_reason"] == "length" and events[-1]["attempt"] == 1


@pytest.mark.parametrize("response,code", [
    (lambda: httpx.Response(503, text="unavailable"), "model_http_error"),
    (lambda: httpx.Response(200, text="not-json"), "model_protocol_error"),
    (lambda: [{"message": {"content": "partial"}}], "model_stream_incomplete"),
])
def test_original_contract_keeps_technical_model_service_errors(local_http, response, code):
    local_http["responses"] = [response()]
    with pytest.raises(ModelError) as error:
        collect(thinking=True, preserve_original=True)
    assert error.value.source == "model_service" and error.value.code == code
    assert len(local_http["requests"]) == 1
