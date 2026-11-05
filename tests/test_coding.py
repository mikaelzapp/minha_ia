"""Local coding consultations use deterministic HTTP transport, never real models."""
import json

import httpx
import pytest

from nexus.coding import Coding
import nexus.coding as coding


CODER = "qwen2.5-coder:7b"
PRIMARY = "qwen3.5:4b-q4_K_M"


@pytest.fixture
def fake_ollama(monkeypatch):
    state = {"calls": [], "client_options": [], "models": [{"name": CODER}],
             "running": [{"name": PRIMARY}, {"name": "unrelated:model"}],
             "show": {"capabilities": ["completion", "tools"]},
             "chat": {"message": {"content": "def add(a, b):\n    return a + b\n"}, "done": True,
                      "eval_count": 20, "prompt_eval_count": 80, "eval_duration": 2_000_000_000,
                      "load_duration": 100_000_000}, "fail": {}}

    def handler(request):
        payload = json.loads(request.content) if request.content else None
        path = request.url.path
        state["calls"].append((request.method, path, payload))
        if path in state["fail"]:
            failure = state["fail"][path]
            if isinstance(failure, Exception):
                raise failure
            return httpx.Response(failure, json={"error": "test failure"})
        if path == "/api/tags":
            data = {"models": state["models"]}
        elif path == "/api/show":
            data = state["show"]
        elif path == "/api/ps":
            data = {"models": state["running"]}
        elif path == "/api/chat":
            data = state["chat"]
        elif path == "/api/generate":
            assert payload["keep_alive"] == 0 and payload["stream"] is False
            data = {"done": True}
        else:
            raise AssertionError("Unexpected request: " + path)
        return httpx.Response(200, json=data)

    original_client = httpx.Client

    def client(**kwargs):
        state["client_options"].append(kwargs)
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(coding.httpx, "Client", client)
    return state


def consult():
    return Coding("http://127.0.0.1:11434", CODER, PRIMARY)


def test_specialist_is_text_only_and_swaps_only_the_loaded_primary(fake_ollama):
    result = consult().execute({"task": "Corrija a função", "context": "def add(a,b): return a-b"})
    assert result["ok"] is True and result["executed"] is False
    assert result["model"] == CODER and "def add" in result["proposal"]
    assert "revisada e testada" in result["notice"]
    assert result["metrics"]["tokens_per_second"] == 10
    calls = fake_ollama["calls"]
    assert [path for _, path, _ in calls] == ["/api/tags", "/api/show", "/api/ps", "/api/generate", "/api/chat", "/api/generate"]
    unloaded = [payload["model"] for _, path, payload in calls if path == "/api/generate"]
    assert unloaded == [PRIMARY, CODER]
    payload = next(payload for _, path, payload in calls if path == "/api/chat")
    assert "tools" not in payload and "think" not in payload
    assert payload["stream"] is False and payload["keep_alive"] == 0
    assert payload["options"] == {"num_ctx": 4096, "temperature": 0.2, "num_predict": 1536, "num_batch": 128}
    assert "Corrija a função" in payload["messages"][1]["content"]
    assert "return a-b" in payload["messages"][1]["content"]
    assert fake_ollama["client_options"][0]["trust_env"] is False
    assert fake_ollama["client_options"][0]["follow_redirects"] is False


@pytest.mark.parametrize("running,primary", [([], PRIMARY), ([{"name": CODER}], CODER), ([{"name": "unrelated:model"}], PRIMARY)])
def test_does_not_unload_absent_primary_or_unrelated_models(fake_ollama, running, primary):
    fake_ollama["running"] = running
    result = Coding("http://localhost:11434", CODER, primary).execute({"task": "Revise este código"})
    assert result["ok"]
    assert [payload["model"] for _, path, payload in fake_ollama["calls"] if path == "/api/generate"] == [CODER]


@pytest.mark.parametrize("args", [None, [], {}, {"task": " "}, {"task": 1}, {"task": "x" * 2001},
    {"task": "x", "context": []}, {"task": "x", "context": "c" * 4001},
    {"task": "x" * 2000, "context": "c" * 3001}, {"task": "run", "approved": True}])
def test_invalid_or_overbudget_arguments_fail_before_contacting_ollama(fake_ollama, args):
    result = consult().execute(args)
    assert result["ok"] is False and result["executed"] is False and result["error"]
    assert fake_ollama["calls"] == []


@pytest.mark.parametrize("url", ["https://example.test", "http://192.168.1.2:11434", "http://user:secret@127.0.0.1:11434", "file:///test"])
def test_nonlocal_or_credential_urls_are_rejected(url):
    with pytest.raises(ValueError):
        Coding(url, CODER, PRIMARY)


@pytest.mark.parametrize("model", ["qwen:480b-cloud", "QWEN:480B-CLOUD", "model-cloud:latest"])
def test_cloud_tag_is_blocked_without_network(fake_ollama, model):
    result = Coding("http://127.0.0.1:11434", model, PRIMARY).execute({"task": "private code"})
    assert not result["ok"] and "cloud" in result["error"]
    assert fake_ollama["calls"] == []


@pytest.mark.parametrize("field", ["remote_name", "remote_model", "remote_host", "cloud_host"])
@pytest.mark.parametrize("source", ["tags", "show", "details"])
def test_remote_metadata_blocks_sending_private_context(fake_ollama, field, source):
    if source == "tags":
        fake_ollama["models"][0][field] = "remote.example"
    elif source == "show":
        fake_ollama["show"][field] = "remote.example"
    else:
        fake_ollama["show"]["details"] = {field: "remote.example"}
    result = consult().execute({"task": "private code"})
    assert not result["ok"] and "remoto/cloud" in result["error"]
    assert not any(path in {"/api/chat", "/api/generate"} for _, path, _ in fake_ollama["calls"])


def test_missing_model_never_downloads_or_generates(fake_ollama):
    fake_ollama["models"] = []
    result = consult().execute({"task": "write code"})
    assert not result["ok"] and "instalado" in result["error"]
    assert [path for _, path, _ in fake_ollama["calls"]] == ["/api/tags"]


def test_embedding_only_model_cannot_be_used_as_coder(fake_ollama):
    fake_ollama["show"]["capabilities"] = ["embedding"]
    result = consult().execute({"task": "write code"})
    assert not result["ok"] and "completion" in result["error"]
    assert not any(path == "/api/chat" for _, path, _ in fake_ollama["calls"])


@pytest.mark.parametrize("response", [{"message": {"content": ""}, "done": True},
    {"message": {"content": "   "}, "done": True}, {"done": True},
    {"message": {"content": "partial"}, "done": False}, {"error": "model failed"}])
def test_empty_incomplete_and_error_responses_never_claim_success_and_always_unload(fake_ollama, response):
    fake_ollama["chat"] = response
    result = consult().execute({"task": "write code"})
    assert not result["ok"] and result["executed"] is False and result["error"]
    assert "proposal" not in result
    assert fake_ollama["calls"][-1][2]["model"] == CODER


@pytest.mark.parametrize("failure", [500, httpx.ReadTimeout("read timeout")])
def test_chat_http_failure_still_unloads_specialist(fake_ollama, failure):
    fake_ollama["fail"]["/api/chat"] = failure
    result = consult().execute({"task": "write code"})
    assert not result["ok"] and result["executed"] is False
    assert "proposal" not in result
    assert fake_ollama["calls"][-1][1:] == ("/api/generate", {"model": CODER, "keep_alive": 0, "stream": False})


@pytest.mark.parametrize("endpoint", ["/api/tags", "/api/show", "/api/ps", "/api/generate"])
def test_failed_prerequisites_stop_before_specialist_chat(fake_ollama, endpoint):
    fake_ollama["fail"][endpoint] = 503
    result = consult().execute({"task": "write code"})
    assert not result["ok"] and "HTTP 503" in result["error"]
    assert not any(path == "/api/chat" for _, path, _ in fake_ollama["calls"])


def test_schema_is_a_single_bounded_consultation_tool_and_cannot_be_mutated():
    coder = consult()
    schema = coder.schema()
    assert schema["function"]["name"] == "consult_coder"
    parameters = schema["function"]["parameters"]
    assert parameters["required"] == ["task"]
    assert set(parameters["properties"]) == {"task", "context"}
    assert parameters["additionalProperties"] is False
    schema["function"]["name"] = "tampered"
    assert coder.schema()["function"]["name"] == "consult_coder"
