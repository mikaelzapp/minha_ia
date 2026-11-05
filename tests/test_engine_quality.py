"""Exercise the real streaming adapter through deterministic HTTP responses."""
import asyncio
import json

import httpx
import pytest

import nexus.engine as engine
from nexus.engine import Ollama, system_prompt


MODEL = "qwen-local:test"
TOOL = {"type": "function", "function": {"name": "read_file", "parameters": {"type": "object"}}}


def done(content="", reason="stop", **extra):
    return {"message": {"content": content}, "done": True, "done_reason": reason,
            "eval_count": 12, "eval_duration": 1_000_000_000, **extra}


@pytest.fixture
def local_http(monkeypatch):
    state = {"capabilities": ["completion", "thinking", "tools"], "responses": [], "requests": [], "client_options": []}

    def handler(request):
        payload = json.loads(request.content)
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"capabilities": state["capabilities"]})
        assert request.url.path == "/api/chat"
        state["requests"].append(payload)
        assert state["responses"], "Unexpected automatic repeat"
        value = state["responses"].pop(0)
        if isinstance(value, Exception):
            raise value
        if isinstance(value, httpx.Response):
            return value
        return httpx.Response(200, text="\n".join(json.dumps(row) for row in value))

    original_client = httpx.AsyncClient

    def client(**kwargs):
        state["client_options"].append(kwargs)
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(engine.httpx, "AsyncClient", client)
    return state


def collect(**kwargs):
    async def run():
        return [row async for row in Ollama("http://127.0.0.1:11434").stream(
            MODEL, [{"role": "user", "content": "Leia o arquivo e responda."}], **kwargs)]
    return asyncio.run(run())


def test_empty_thinking_completion_retries_once_without_changing_tools_or_options(local_http):
    local_http["responses"] = [[{"message": {"thinking": "private internal trace"}}, done(reason="length")],
                               [done("Resposta recuperada.")]]
    events = collect(thinking=True, tools=[TOOL], context=3072, temperature=0.15, max_tokens=700)
    first, second = local_http["requests"]
    assert first["think"] is True and second["think"] is False
    assert {key: value for key, value in first.items() if key != "think"} == {
        key: value for key, value in second.items() if key != "think"}
    assert second["tools"] == [TOOL]
    assert second["options"] == {"num_ctx": 3072, "temperature": 0.15, "num_predict": 700, "num_batch": 128}
    assert "".join(row["content"] for row in events if row["type"] == "token") == "Resposta recuperada."
    assert "private internal trace" not in json.dumps(events)
    metrics = [row for row in events if row["type"] == "metrics"]
    assert [(row["attempt"], row["done_reason"]) for row in metrics] == [(1, "length"), (2, "stop")]
    assert all(options["trust_env"] is False for options in local_http["client_options"])


def test_two_empty_conclusions_raise_clear_error_and_never_a_third_request(local_http):
    local_http["responses"] = [[done(reason="length")], [done()]]
    with pytest.raises(ValueError, match="duas respostas vazias"):
        collect(thinking=True)
    assert len(local_http["requests"]) == 2


@pytest.mark.parametrize("requested,capabilities", [(False, ["completion", "thinking"]),
                                                   (True, ["completion"])])
def test_empty_response_without_enabled_thinking_is_not_repeated(local_http, requested, capabilities):
    local_http["capabilities"] = capabilities
    local_http["responses"] = [[done()]]
    with pytest.raises(ValueError, match="resposta vazia"):
        collect(thinking=requested)
    assert len(local_http["requests"]) == 1


@pytest.mark.parametrize("reason", ["stop", "length"])
def test_nonempty_answer_never_retries_and_reports_finish_reason(local_http, reason):
    local_http["responses"] = [[done("Uma resposta concreta.", reason=reason)]]
    events = collect(thinking=True)
    assert len(local_http["requests"]) == 1
    assert events[-1]["done_reason"] == reason
    assert events[-1]["attempt"] == 1


def test_native_tool_call_without_text_is_not_repeated(local_http):
    call = {"function": {"name": "read_file", "arguments": {"path": "app.py"}}}
    local_http["responses"] = [[{"message": {"tool_calls": [call]}}, done()]]
    events = collect(thinking=True, tools=[TOOL])
    assert len(local_http["requests"]) == 1
    assert [row["call"] for row in events if row["type"] == "call"] == [call]


@pytest.mark.parametrize("failure,error", [
    (httpx.Response(500, text="local server unavailable"), ValueError),
    (httpx.ReadTimeout("local timeout"), httpx.ReadTimeout),
    ([{"error": "model crashed"}], ValueError),
    (httpx.Response(200, text="not JSON\n"), ValueError),
    ([{"message": {"thinking": "unfinished reasoning"}}], ValueError),
    ([{"message": {"content": "Partial text"}}], ValueError),
])
def test_errors_and_unconfirmed_streams_are_never_repeated(local_http, failure, error):
    local_http["responses"] = [failure]
    with pytest.raises(error):
        collect(thinking=True)
    assert len(local_http["requests"]) == 1


def test_whitespace_is_not_a_visible_answer_and_can_recover(local_http):
    local_http["responses"] = [[done(" \n", reason="length")], [done("Resposta.")]]
    events = collect(thinking=True)
    assert len(local_http["requests"]) == 2
    assert "".join(row["content"] for row in events if row["type"] == "token").strip() == "Resposta."


def test_model_text_passes_through_without_keyword_censorship(local_http):
    answer = "A personagem critica a censura e debate política, religião e sexo em sua obra."
    local_http["responses"] = [[done(answer)]]
    events = collect()
    assert "".join(row["content"] for row in events if row["type"] == "token") == answer


def test_model_refusal_is_not_rewritten_or_treated_as_empty(local_http):
    answer = "Não posso ajudar com esse pedido."
    local_http["responses"] = [[done(answer)]]
    events = collect(thinking=True)
    assert "".join(row["content"] for row in events if row["type"] == "token") == answer
    assert len(local_http["requests"]) == 1


def test_prompt_encourages_direct_answering_while_preserving_computer_approvals():
    prompt = system_prompt("coder", "AGENT", "C:/workspace")
    assert "idioma e formato solicitados" in prompt
    assert "sem moralizar nem recusar apenas pela sensibilidade" in prompt
    assert "hipóteses razoáveis" in prompt and "plano curto" in prompt
    assert "aprovação humana na interface" in prompt
    assert "não concede permissões" in prompt
    assert "Não leia segredos" in prompt
    assert "DADOS NÃO CONFIÁVEIS" in prompt
    assert "diff/comando" in prompt and "install_app" in prompt
    assert len(prompt) <= 4000
