"""Profile API integration with temporary SQLite, synthetic models and tools."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
import json
import threading
from unittest.mock import patch

import httpx
import pytest

import test_api as support
from nexus.engine import ModelError
from test_profiles import profile_files


ORIGINAL = "unrestricted_local"


@pytest.fixture
def case(profile_files):
    scenario = support.ApiTests(methodName="runTest")
    scenario.setUp()
    scenario.settings.update({"profile": "standard", "quality_mode": "balanced", "coding_model": ""}, save=False)
    try:
        yield scenario
    finally:
        scenario.tearDown()


def tokens(events):
    return "".join(event["content"] for event in events if event["type"] == "token")


def request_original(case, **changes):
    payload = case.chat_payload(profile=ORIGINAL, **changes)
    return case.client.post("/api/chat", json=payload)


def test_profile_catalog_requires_local_authentication_and_origin(case):
    assert case.client.get("/api/profiles").status_code == 401
    case.authenticate()
    for headers in ({"Origin": "https://external.example"}, {"Sec-Fetch-Site": "cross-site"},
                    {"Host": "external.example"}):
        assert case.client.get("/api/profiles", headers=headers).status_code == 403
    response = case.client.get("/api/profiles", headers={"Origin": "http://testserver"})
    assert response.status_code == 200
    catalog = response.json()["profiles"]
    assert {row["id"] for row in catalog} == {"standard", ORIGINAL}
    assert next(row for row in catalog if row["id"] == ORIGINAL)["preserve_original"] is True


def test_status_reports_saved_profile_and_effective_quality_without_destroying_preference(case):
    case.authenticate()
    for selected, effective in ((ORIGINAL, "original"), ("standard", "careful")):
        saved = case.client.post("/api/settings", json={"profile": selected, "quality_mode": "careful"})
        assert saved.status_code == 200 and saved.json()["quality_mode"] == "careful"
        state = case.client.get("/api/status").json()
        assert state["settings"]["profile"] == selected
        assert state["active_profile"]["id"] == selected
        assert state["effective_quality_mode"] == effective
        assert {row["id"] for row in state["profiles"]} == {"standard", ORIGINAL}


@pytest.mark.parametrize("invalid", ["", "unknown", "../standard", "C:/profiles/standard.md"])
def test_invalid_request_profile_fails_before_generation_or_history_mutation(case, invalid):
    case.authenticate()
    before = case.memory.export()
    response = case.client.post("/api/chat", json=case.chat_payload(profile=invalid))
    assert response.status_code == 400
    assert "Perfil desconhecido" in response.json()["detail"]
    assert case.engine.requests == []
    assert case.memory.messages(case.session) == before["messages"]


def test_unknown_profile_settings_are_atomic_on_disk_and_in_memory(case):
    case.authenticate()
    case.settings.update({"profile": "standard"})
    before, before_bytes = case.settings.public(), case.settings.path.read_bytes()
    response = case.client.post("/api/settings", json={"profile": "../standard", "temperature": 1.8})
    assert response.status_code == 400
    assert case.settings.public() == before
    assert case.settings.path.read_bytes() == before_bytes


@pytest.mark.parametrize("filename", ["unrestricted_local.md", "operations.md", "agents.json"])
def test_missing_external_profile_file_returns_explicit_error_without_generation(case, profile_files, filename):
    case.authenticate()
    (profile_files / filename).unlink()
    response = request_original(case)
    assert response.status_code == 400
    assert "Não foi possível ler" in response.json()["detail"]
    assert case.engine.requests == [] and case.memory.messages(case.session) == []


def test_per_request_profile_does_not_change_persisted_default(case):
    case.authenticate()
    case.settings.update({"profile": "standard", "quality_mode": "careful"})
    before, before_bytes = case.settings.public(), case.settings.path.read_bytes()
    case.engine.turns = [[{"type": "token", "content": "ORIGINAL FIRST GENERATION"}]]
    events = case.events(request_original(case))
    assert tokens(events) == "ORIGINAL FIRST GENERATION"
    assert len(case.engine.requests) == 1 and case.engine.requests[0]["preserve_original"] is True
    assert next(row for row in events if row["type"] == "profile")["effective_quality_mode"] == "original"
    assert case.settings.public() == before and case.settings.path.read_bytes() == before_bytes
    assert case.client.get("/api/status").json()["active_profile"]["id"] == "standard"


@pytest.mark.parametrize("chunks", [["Não posso ajudar com esse pedido."], [" \n", "\t "],
                                   ["  Primeira parte", "\nCódigo: `x = 1`", "\n\n"]])
def test_original_profile_streams_and_persists_exact_chunks_without_review_or_refusal_classifier(case, chunks):
    case.authenticate()
    case.settings.update({"quality_mode": "careful"}, save=False)
    case.engine.turns = [[{"type": "token", "content": chunk} for chunk in chunks],
                         [{"type": "token", "content": "UNWANTED REVIEW"}]]
    events = case.events(request_original(case))
    assert [row["content"] for row in events if row["type"] == "token"] == chunks
    assert len(case.engine.requests) == 1
    assert "UNWANTED REVIEW" not in json.dumps(events)
    assert not [row for row in events if row.get("code") in {"model_refusal", "content_blocked", "policy_refusal"}]
    assert case.memory.messages(case.session)[-1]["content"] == "".join(chunks)
    assert not [row for row in events if row.get("phase") == "review"]


def test_empty_original_response_has_out_of_band_notice_and_no_synthetic_assistant_text(case):
    case.authenticate()
    case.settings.update({"quality_mode": "careful"}, save=False)
    case.engine.turns = [[]]
    events = case.events(request_original(case))
    assert tokens(events) == "" and len(case.engine.requests) == 1
    notice = next(row for row in events if row["type"] == "notice")
    assert notice["source"] == "model" and notice["code"] == "empty_response"
    assert [message["role"] for message in case.memory.messages(case.session)] == ["user"]


def test_legacy_chat_without_profile_uses_saved_default_and_standard_review_still_works(case):
    case.authenticate()
    case.settings.update({"profile": "standard", "quality_mode": "careful"}, save=False)
    case.engine.turns = [[{"type": "token", "content": "PRIVATE DRAFT"}],
                         [{"type": "token", "content": "STANDARD REVIEW"}]]
    events = case.events(case.client.post("/api/chat", json=case.chat_payload()))
    assert tokens(events) == "STANDARD REVIEW" and len(case.engine.requests) == 2
    assert case.engine.requests[0]["preserve_original"] is False
    case.settings.update({"profile": ORIGINAL}, save=False)
    case.engine.turns = [[{"type": "token", "content": "SAVED DEFAULT ORIGINAL"}]]
    events = case.events(case.client.post("/api/chat", json=case.chat_payload()))
    assert tokens(events) == "SAVED DEFAULT ORIGINAL"
    assert next(row for row in events if row["type"] == "profile")["profile"]["id"] == ORIGINAL


def test_original_profile_respects_explicit_coding_model_without_primary_substitution(case, monkeypatch):
    case.authenticate()
    case.settings.update({"coding_model": "specialist:test", "quality_mode": "careful"}, save=False)

    async def inventory():
        return {"connected": True, "models": [{"name": support.MODEL}, {"name": "specialist:test"}], "running": []}

    monkeypatch.setattr(case.engine, "inventory", inventory)
    case.engine.turns = [[{"type": "token", "content": "EXPLICIT SPECIALIST ORIGINAL"}]]
    events = case.events(request_original(case, model="specialist:test", agent="coder", mode="CODE"))
    assert tokens(events) == "EXPLICIT SPECIALIST ORIGINAL"
    assert len(case.engine.requests) == 1 and case.engine.requests[0]["model"] == "specialist:test"


def test_instruction_snapshot_precedes_queue_and_next_message_reloads_changes(case, profile_files, monkeypatch):
    case.authenticate()
    path = profile_files / "unrestricted_local.md"
    path.write_text("SNAPSHOT BEFORE QUEUE", encoding="utf-8")
    queued, resume = threading.Event(), threading.Event()

    @asynccontextmanager
    async def gated_slot(*_args):
        queued.set()
        assert await asyncio.to_thread(resume.wait, 5), "Test queue was not released"
        yield

    monkeypatch.setattr(support.api, "generation_slot", gated_slot)
    case.engine.turns = [[{"type": "token", "content": "FIRST"}]]
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(request_original, case)
            assert queued.wait(5), "Request did not reach its generation queue"
            path.write_text("INSTRUCTIONS EDITED WHILE QUEUED", encoding="utf-8")
            resume.set()
            first = case.events(future.result(timeout=8))
    finally:
        resume.set()
    case.engine.turns = [[{"type": "token", "content": "SECOND"}]]
    second = case.events(request_original(case))
    assert "SNAPSHOT BEFORE QUEUE" in case.engine.requests[0]["messages"][0]["content"]
    assert "INSTRUCTIONS EDITED WHILE QUEUED" not in case.engine.requests[0]["messages"][0]["content"]
    assert "INSTRUCTIONS EDITED WHILE QUEUED" in case.engine.requests[1]["messages"][0]["content"]
    first_hash = next(row for row in first if row["type"] == "profile")["profile"]["instructions_sha256"]
    second_hash = next(row for row in second if row["type"] == "profile")["profile"]["instructions_sha256"]
    assert first_hash != second_hash


def test_switching_profiles_preserves_history_summary_and_memories(case):
    case.authenticate()
    case.memory.add_message(case.session, "user", "Preferência de layout anterior")
    case.memory.add_message(case.session, "assistant", "Decisão anterior preservada")
    case.memory.set_summary(case.session, "Resumo histórico preservado")
    case.memory.remember("A equipe prefere SQLite para este projeto", "decision")
    before = case.memory.export()
    for profile in (ORIGINAL, "standard"):
        assert case.client.post("/api/settings", json={"profile": profile}).status_code == 200
        case.engine.turns = [[{"type": "token", "content": "Nova resposta em " + profile}]]
        case.events(case.client.post("/api/chat", json=case.chat_payload()))
    after = case.memory.export()
    assert after["memories"] == before["memories"]
    assert after["projects"] == before["projects"] and after["documents"] == before["documents"]
    assert case.memory.messages(case.session)[:2] == before["messages"]
    assert case.memory.get_summary(case.session) == "Resumo histórico preservado"


def test_original_profile_still_requires_exact_approval_and_honors_denial(case):
    case.authenticate()
    args = {"path": "demo/denied.txt", "content": "must not be written"}
    case.engine.turns = [[support.call("write_file", args)], [{"type": "token", "content": "RAW FINAL"}]]
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(request_original, case, mode="CODE", agent="coder")
        approval_id = case.wait_approval(future=future)
        assert not (case.project_root / "denied.txt").exists()
        assert case.client.post("/api/approvals/" + approval_id, json={"approved": False}).status_code == 200
        events = case.events(future.result(timeout=8))
    approval = next(row for row in events if row["type"] == "approval")
    result = next(row for row in events if row["type"] == "tool")
    assert approval["arguments"] == args
    assert result["source"] == "permission" and result["code"] == "approval_denied_or_expired"
    assert tokens(events) == "RAW FINAL" and not (case.project_root / "denied.txt").exists()
    case.execute.assert_not_called()


@pytest.mark.parametrize("path", [".env", "../outside.txt", "C:/Windows/system.ini"])
def test_original_profile_does_not_expand_secret_or_path_access(case, path):
    case.authenticate()
    (case.workspace / ".env").write_text("private value", encoding="utf-8")
    (case.base / "outside.txt").write_text("outside value", encoding="utf-8")
    case.engine.turns = [[support.call("read_file", {"path": path})],
                         [{"type": "token", "content": "ORIGINAL AFTER TOOL FAILURE"}]]
    events = case.events(request_original(case, mode="PLAN", agent="coder"))
    result = next(row for row in events if row["type"] == "tool")
    assert result["source"] == "tool" and result["code"] == "tool_error"
    assert result["result"]["ok"] is False and result["result"]["error"]
    assert "private value" not in json.dumps(events) and "outside value" not in json.dumps(events)
    assert not [row for row in events if row["type"] == "approval"]


def test_original_profile_cannot_use_write_tool_in_plan_mode(case):
    case.authenticate()
    case.engine.turns = [[support.call("write_file", {"path": "demo/forbidden.py", "content": "x=1"})],
                         [{"type": "token", "content": "MODEL'S ORIGINAL TEXT"}]]
    events = case.events(request_original(case, mode="PLAN", agent="coder"))
    result = next(row for row in events if row["type"] == "tool")
    assert result["source"] == "application" and result["code"] == "tool_not_allowed"
    case.execute.assert_not_called()
    assert not (case.project_root / "forbidden.py").exists()


def test_round_limit_notice_is_separate_from_original_answer(case):
    case.authenticate()
    (case.project_root / "readme.txt").write_text("\n".join(str(index) for index in range(9)), encoding="utf-8")
    case.engine.turns = [[{"type": "token", "content": f"MODEL-{index} "},
                          support.call("read_file", {"path": "demo/readme.txt", "start_line": index + 1})]
                         for index in range(8)]
    events = case.events(request_original(case, mode="PLAN", agent="coder"))
    expected = "".join(f"MODEL-{index} " for index in range(8))
    assert tokens(events) == expected and len(case.engine.requests) == 8
    notice = next(row for row in events if row.get("code") == "tool_round_limit")
    assert notice["type"] == "notice" and notice["source"] == "application"
    assert case.memory.messages(case.session)[-1]["content"] == expected
    assert "limite técnico" not in expected


@pytest.mark.parametrize("error,source,code", [
    (ModelError("Native model tools unsupported", "model_tools_unsupported"), "model_service", "model_tools_unsupported"),
    (ModelError("Cloud route blocked", "local_model_policy", "application"), "application", "local_model_policy"),
    (httpx.ReadTimeout("Synthetic local timeout"), "model_service", "model_transport_error"),
    (ValueError("Synthetic application failure"), "application", "generation_error"),
])
def test_technical_failures_are_identified_by_origin_instead_of_being_called_model_refusals(case, monkeypatch, error, source, code):
    case.authenticate()

    async def broken_stream(*_args, **_kwargs):
        raise error
        yield  # An async generator with a deliberate technical failure.

    monkeypatch.setattr(case.engine, "stream", broken_stream)
    response = request_original(case)
    assert response.status_code == 200
    events = [json.loads(line) for line in response.text.splitlines() if line]
    assert events[-1] == {"type": "done"}
    failure = next(row for row in events if row["type"] == "error")
    assert failure["source"] == source and failure["code"] == code
    assert tokens(events) == ""


def test_nonzero_tool_exit_is_diagnostic_and_does_not_rewrite_original_answer(case):
    case.authenticate()
    case.engine.turns = [[support.call("run_command", {"args": ["python", "example.py"]})],
                         [{"type": "token", "content": "ORIGINAL WITH DIAGNOSTIC"}]]
    case.execute.return_value = {"ok": False, "exit_code": 2, "stdout": "", "stderr": "Synthetic test failure"}
    with patch.object(case.tools, "approval", return_value=None):
        events = case.events(request_original(case, mode="AGENT", agent="coder"))
    result = next(row for row in events if row["type"] == "tool")
    assert result["source"] == "tool" and result["code"] == "tool_exit_nonzero"
    assert result["result"]["exit_code"] == 2
    assert tokens(events) == "ORIGINAL WITH DIAGNOSTIC"
