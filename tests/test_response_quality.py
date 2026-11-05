"""Regressions for lost requirements and missing execution evidence."""
import json

import pytest

import test_api as api_support
from nexus.quality import review_messages


@pytest.fixture
def case():
    fixture = api_support.ApiTests(methodName="runTest")
    fixture.setUp()
    fixture.settings.update({"quality_mode": "balanced", "coding_model": "", "computer_enabled": False}, save=False)
    try:
        fixture.authenticate()
        yield fixture
    finally:
        fixture.tearDown()


def test_api_preserves_start_and_end_of_a_long_current_request(case):
    question = "REQUISITO_INICIAL: JSON sem markdown.\n" + "contexto neutro " * 1800 + "\nREQUISITO_FINAL: inclua status."
    case.events(case.client.post("/api/chat", json=case.chat_payload(message=question)))
    packed = "\n".join(row.get("content", "") for row in case.engine.requests[0]["messages"])
    assert "REQUISITO_INICIAL: JSON sem markdown." in packed
    assert "REQUISITO_FINAL: inclua status." in packed
    assert len(packed) < len(question)
    assert case.memory.messages(case.session)[0]["content"] == question


def test_careful_review_produces_text_without_a_second_thinking_budget(case):
    case.settings.update({"quality_mode": "careful", "thinking": True}, save=False)
    case.engine.turns = [[{"type": "token", "content": "Proposta calculada."}],
                         [{"type": "token", "content": "Resultado conferido."}]]
    events = case.events(case.client.post("/api/chat", json=case.chat_payload()))
    assert case.engine.requests[0]["thinking"] is True
    assert case.engine.requests[1]["thinking"] is False
    assert case.engine.requests[1].get("tools", []) == []
    assert "".join(e["content"] for e in events if e["type"] == "token") == "Resultado conferido."
    case.execute.assert_not_called()


def test_tool_round_retains_the_request_and_real_failure_as_valid_json(case):
    case.settings.update({"thinking": True}, save=False)
    question = "Leia demo/inexistente.py; se falhar, explique o erro real."
    case.engine.turns = [[api_support.call("read_file", {"path": "demo/inexistente.py"})],
                         [{"type": "token", "content": "O arquivo não existe."}]]
    case.events(case.client.post("/api/chat", json=case.chat_payload(message=question, mode="PLAN", agent="coder")))
    second = case.engine.requests[1]["messages"]
    assert case.engine.requests[0]["max_tokens"] == 1536
    assert any(row["role"] == "user" and question in row["content"] for row in second)
    result = json.loads(next(row["content"] for row in second if row["role"] == "tool"))
    assert result.get("error")
    assert not (case.project_root / "inexistente.py").exists()


def test_review_keeps_failure_after_large_reads_and_does_not_break_json():
    evidence = [
        {"name": "read_file", "result": {"ok": True, "content": "arquivo extenso " * 3000}},
        {"name": "write_file", "result": {"ok": True, "path": "sistema.py", "sha256": "a" * 64}},
        {"name": "run_command", "result": {"ok": False, "exit_code": 1, "output": "log " * 2000 + "ASSERTION_FAILED_FINAL"}},
        {"name": "read_file", "result": {"ok": True, "path": "tests.py", "content": "teste " * 2000}},
    ]
    messages = review_messages("Corrija a falha", "Ainda há erro de teste.", evidence, 4096)
    facts = json.loads(messages[1]["content"].split("Evidências reais de ferramentas (podem estar incompletas):\n", 1)[1])
    assert len(facts) == 4
    execution = next(row for row in facts if row.get("name") == "run_command")
    assert execution["result"]["exit_code"] == 1
    assert execution["result"]["ok"] is False
    assert "ASSERTION_FAILED_FINAL" in execution["result"]["output"]


def test_large_tool_result_is_structured_before_entering_the_next_turn(case):
    content = "LONG_READ_HEAD " + "linha de contexto " * 600 + " LONG_READ_TAIL"
    (case.project_root / "large.py").write_text(content, encoding="utf-8")
    case.engine.turns = [[api_support.call("read_file", {"path": "demo/large.py", "max_lines": 2000})],
                         [{"type": "token", "content": "Arquivo lido parcialmente."}]]
    case.events(case.client.post("/api/chat", json=case.chat_payload(mode="PLAN", agent="coder")))
    tool = next(row for row in case.engine.requests[1]["messages"] if row["role"] == "tool")
    result = json.loads(tool["content"])
    assert result.get("path") == "demo/large.py"
    assert "LONG_READ_HEAD" in result["content"]
    assert "LONG_READ_TAIL" in result["content"]


def test_review_keeps_first_requirement_and_last_conclusion_of_long_draft():
    question = "FIRST_REQUIREMENT_JSON " + "neutral " * 5000 + " LAST_REQUIREMENT_ENGLISH"
    draft = "INITIAL_PROPOSAL " + "draft context " * 5000 + " FINAL_LIMITATION_NOT_EXECUTED"
    messages = review_messages(question, draft, [], 4096)
    text = messages[1]["content"]
    for marker in ("FIRST_REQUIREMENT_JSON", "LAST_REQUIREMENT_ENGLISH", "INITIAL_PROPOSAL", "FINAL_LIMITATION_NOT_EXECUTED"):
        assert marker in text
    assert sum(len(row["content"]) for row in messages) <= 4096 * 2
