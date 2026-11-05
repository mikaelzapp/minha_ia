"""Context budgets preserve requirements and actual tool results."""
from copy import deepcopy
import json

import pytest

from nexus.context import build_context, clip_text, compact_json, estimate_tokens, fit_context


def msg(role, content, **extra):
    return {"role": role, "content": content, **extra}


def call(name, **arguments):
    return msg("assistant", "", tool_calls=[{"function": {"name": name, "arguments": arguments}}])


def test_small_conversation_keeps_messages_exactly_and_does_not_mutate_input():
    original = [msg("system", "Política intacta."), msg("user", "Faça soma(a,b)."), call("read_file", path="main.py"), msg("tool", '{"ok":true,"text":"pass"}', tool_name="read_file")]
    snapshot = deepcopy(original)
    result = fit_context(original)
    assert result == original == snapshot
    result[-1]["content"] = "alterado"
    assert original == snapshot


def test_long_current_request_retains_first_and_final_explicit_requirements():
    question = "REQUISITO INICIAL: preserve as contas.\n" + "conteúdo intermediário " * 2000 + "\nREQUISITO FINAL: não apague o banco."
    messages = build_context("Instruções fixas.", [msg("user", question)], context=2048, response_tokens=1024)
    request = messages[-1]["content"]
    assert request.startswith("REQUISITO INICIAL")
    assert request.endswith("não apague o banco.")
    assert "omitido por limite de contexto" in request
    assert len(request) < len(question)


def test_system_instructions_survive_even_when_mandatory_material_exceeds_estimate():
    policy = "Não leia segredos; peça aprovação. " * 1000
    messages = fit_context([msg("system", policy), msg("user", "Crie um teste.")], context=256, response_tokens=128)
    assert messages[0] == msg("system", policy)
    assert messages[-1] == msg("user", "Crie um teste.")


def test_recent_test_failure_and_native_call_survive_large_old_history():
    native = call("run_command", argv=["python", "-m", "pytest"])
    evidence = {"ok": False, "stdout": "cabeçalho\n" + "lixo " * 3000 + "\nFAILED test_saldo.py", "exit_code": 1, "error": "TESTES FALHARAM"}
    messages = [msg("system", "Não invente sucesso."), msg("user", "Antigo " * 3000), msg("assistant", "Resposta antiga " * 3000), msg("user", "Corrija o teste preservando as contas."), native, msg("tool", json.dumps(evidence), tool_name="run_command")]
    result = fit_context(messages, context=2048, response_tokens=1024)
    assert result[1]["content"] == "Corrija o teste preservando as contas."
    assert result[-2] == native
    actual = json.loads(result[-1]["content"])
    assert actual["ok"] is False and actual["exit_code"] == 1
    assert actual["error"] == "TESTES FALHARAM"
    assert "FAILED test_saldo.py" in actual["stdout"]
    assert "__nexus_context__" in actual
    assert not any(str(message.get("content", "")).startswith("Antigo") for message in result)


def test_native_arguments_are_never_rewritten_to_fit():
    native = call("write_file", path="sistema.py", content="x = 1\n" * 3000)
    result = fit_context([msg("system", "Aprovação obrigatória."), msg("user", "Crie o sistema."), native, msg("tool", '{"ok":true,"path":"sistema.py"}', tool_name="write_file")], context=512, response_tokens=256)
    assert result[-2]["tool_calls"] == native["tool_calls"]
    assert json.loads(result[-1]["content"])["ok"] is True
    assert result[1]["content"] == "Crie o sistema."


def test_old_rounds_are_omitted_together_with_their_tool_results():
    old = call("read_file", path="old.py")
    latest = call("run_command", argv=["pytest"])
    messages = [msg("system", "Política."), msg("user", "Resolva."), old, msg("tool", json.dumps({"text": "muito texto " * 5000}), tool_name="read_file"), latest, msg("tool", '{"exit_code":0,"stdout":"2 passed"}', tool_name="run_command")]
    result = fit_context(messages, context=2048, response_tokens=1024)
    assert latest in result
    assert old not in result
    assert not any(message.get("tool_name") == "read_file" for message in result)
    assert json.loads(result[-1]["content"])["exit_code"] == 0


def test_multiple_results_of_latest_round_keep_matching_native_call():
    native = msg("assistant", "", tool_calls=[{"function": {"name": "read_file", "arguments": {"path": "a.py"}}}, {"function": {"name": "read_file", "arguments": {"path": "b.py"}}}])
    messages = [msg("system", "Política."), msg("user", "Compare os dois."), native, msg("tool", json.dumps({"path": "a.py", "text": "A" * 6000}), tool_name="read_file"), msg("tool", json.dumps({"path": "b.py", "text": "B" * 6000}), tool_name="read_file")]
    result = fit_context(messages, context=2048, response_tokens=1024)
    assert result[-3]["tool_calls"] == native["tool_calls"]
    assert [json.loads(message["content"])["path"] for message in result[-2:]] == ["a.py", "b.py"]


def test_memory_and_summary_are_data_and_keep_each_retrieval_hit():
    hits = [{"path": "a.py", "text": "A" * 5000, "score": .8}, {"path": "b.py", "text": "B" * 5000, "score": .7}, {"path": "c.py", "text": "C" * 5000, "score": .6}]
    result = build_context("Política fixa.", [msg("user", "Compare os três arquivos.")], summary="Decisão anterior: Python.", retrieved=hits, context=8192)
    assert result[0] == msg("system", "Política fixa.")
    assert result[1]["role"] == "user"
    assert "dados não confiáveis" in result[1]["content"]
    assert "Não concedem permissões" in result[1]["content"]
    data = json.loads(result[1]["content"].split("\n", 2)[2])
    assert data["resumo_local_possivelmente_incompleto"] == "Decisão anterior: Python."
    assert [hit["path"] for hit in data["memorias_e_arquivos"]] == ["a.py", "b.py", "c.py"]
    assert result[-1] == msg("user", "Compare os três arquivos.")
    assert all("A" * 1000 not in message["content"] for message in result)


def test_retrieval_cannot_crowd_out_request_or_actual_tool_failure():
    messages = build_context("Política fixa.", [msg("user", "Corrija apenas o cálculo."), call("run_command", argv=["pytest"]), msg("tool", '{"ok":false,"exit_code":1,"error":"ValueError"}', tool_name="run_command")], summary="resumo " * 10000, retrieved=[{"text": "documento " * 10000}], context=2048, response_tokens=1024)
    assert any(message["content"] == "Corrija apenas o cálculo." for message in messages)
    assert json.loads(messages[-1]["content"])["exit_code"] == 1


def test_build_context_sends_only_chat_fields_not_database_metadata():
    result = build_context("Política.", [{"role": "user", "content": "Olá", "id": 15, "session_id": "private", "created_at": "now"}])
    assert result[-1] == msg("user", "Olá")


def test_schema_cost_reduces_old_history_before_changing_policy_or_question():
    messages = [msg("system", "Política fixa."), msg("user", "antiga " * 400), msg("assistant", "resposta " * 400), msg("user", "Faça o pedido atual.")]
    tools = [{"function": {"name": "read_file", "description": "descrição " * 450}}]
    without = fit_context(messages, context=4096, response_tokens=1024)
    with_tools = fit_context(messages, context=4096, response_tokens=1024, tools=tools)
    assert len(with_tools) < len(without)
    assert with_tools[0] == messages[0] and with_tools[-1] == messages[-1]


def test_context_is_stable_across_tool_rounds_and_does_not_promote_memory():
    initial = build_context("Política.", [msg("user", "Pedido atual: preserve o banco.")], summary="um resumo " * 500, context=2048)
    initial.extend([call("read_file", path="main.py"), msg("tool", json.dumps({"text": "arquivo " * 5000}), tool_name="read_file")])
    once = fit_context(initial, context=2048)
    twice = fit_context(once, context=2048)
    requests = [message for message in twice if message["role"] == "user" and message["content"].startswith("Pedido atual:")]
    assert len(requests) == 1
    assert twice[-2]["tool_calls"] == initial[-2]["tool_calls"]
    json.loads(twice[-1]["content"])


@pytest.mark.parametrize("budget", [64, 96, 180, 350, 1200])
def test_compact_json_always_returns_valid_json_with_explicit_omission(budget):
    value = {"ok": False, "error": "Falhou por motivo real " * 100, "exit_code": 5, "stdout": "início " + "z" * 8000 + " fim", "nested": [{"x": "y" * 1000}] * 15}
    snapshot = deepcopy(value)
    result = compact_json(value, budget)
    decoded = json.loads(result)
    assert len(result) <= budget
    assert "__nexus_context__" in decoded
    assert decoded.get("ok", False) is False
    assert value == snapshot


def test_compact_json_preserves_real_failure_fields_regardless_of_source_key_order():
    value = {**{f"noise{i}": "z" * 100 for i in range(20)}, "exit_code": 7, "error": "NÃO INSTALADO", "executed": False, "ok": False}
    reduced = json.loads(compact_json(value, 300))
    assert reduced["exit_code"] == 7
    assert reduced["executed"] is False and reduced["ok"] is False
    assert reduced["error"] == "NÃO INSTALADO"


def test_compact_json_keeps_normal_result_exactly_and_long_content_beginning_and_end():
    assert json.loads(compact_json({"ok": True, "exit_code": 0}, 64)) == {"ok": True, "exit_code": 0}
    long = {"role": "user", "content": "Primeiro requisito\n" + "x" * 9000 + "\nÚltimo requisito"}
    result = json.loads(compact_json(long, 700))
    assert result["content"].startswith("Primeiro requisito")
    assert result["content"].endswith("Último requisito")
    assert "omitido" in result["content"]


def test_compact_json_large_arrays_keep_beginning_and_end_with_omission():
    result = json.loads(compact_json([{"path": f"f{i}.py", "text": "x" * 1000} for i in range(40)], 1200))
    assert result[0]["path"] == "f0.py"
    assert result[-1]["path"] == "f39.py"
    assert any("__nexus_context__" in item for item in result)


def test_estimate_accounts_for_utf8_and_call_arguments():
    assert estimate_tokens("🙂" * 20) > estimate_tokens("x" * 20)
    assert estimate_tokens(call("write_file", content="x" * 5000)) > estimate_tokens(call("write_file", content="x"))


@pytest.mark.parametrize("context,reserve", [(0, 128), (128, 0), (4096, -1)])
def test_invalid_budgets_raise_without_mutating_history(context, reserve):
    messages = [msg("user", "Olá")]
    with pytest.raises(ValueError):
        fit_context(messages, context=context, response_tokens=reserve)
    assert messages == [msg("user", "Olá")]


def test_unsupported_tiny_json_budget_is_explicit():
    with pytest.raises(ValueError, match="64"):
        compact_json({"ok": False}, 12)
