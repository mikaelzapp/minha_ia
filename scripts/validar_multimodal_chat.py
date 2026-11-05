"""Ensaio real curto: custom agent → 4B → search_many → histórico com origem.

Não baixa modelos. Cria conversa de validação, remove só o agente temporário e
descarrega o próprio modelo se o Ollama estava vazio antes do ensaio.
"""
import json
from pathlib import Path
from datetime import datetime, timezone
import time
import httpx
import psutil

ROOT = Path(__file__).resolve().parent.parent
MODEL = "qwen3.5:4b-q4_K_M"


def main():
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "model": MODEL,
              "ram_available_gib": round(psutil.virtual_memory().available / 2**30, 3), "minimum_test_gib": 1,
              "downloads": False, "status": "not_run_resources"}
    agent_id = None
    if report["ram_available_gib"] >= 1:
        with httpx.Client(base_url="http://127.0.0.1:8765", trust_env=False, timeout=240) as client:
            client.get("/").raise_for_status()
            running = client.get("/api/status").json()["ollama"]["running"]
            if running:
                report.update(status="not_run_busy", reason="Outro modelo residente; ensaio não altera cargas de outros clientes.")
            else:
                try:
                    response = client.post("/api/library/agents", json={"name": "QA pesquisa multimodal temporário", "workspace_mode": "search",
                        "prompt": "Pesquise usando search_many com as duas consultas exatas solicitadas; depois responda uma frase com duas URLs retornadas. Não invente fontes.",
                        "tool_allowlist": ["search_many"], "memory": {"read": False, "write": False, "scope": "conversation"},
                        "permissions": {"file_read": False, "file_write": False, "terminal": False, "external_network": True}})
                    response.raise_for_status(); agent_id = response.json()["id"]
                    response = client.post("/api/sessions", json={"title": "Validação multimodal — pesquisa real", "workspace_mode": "search"})
                    response.raise_for_status(); session = response.json()["id"]
                    started = time.perf_counter()
                    with client.stream("POST", "/api/chat", json={"session_id": session, "workspace_mode": "search", "mode": "RESEARCH",
                        "agent": agent_id, "model": MODEL, "context": 4096, "temperature": 0, "thinking": False, "profile": "unrestricted_local",
                        "message": "Use agora a ferramenta search_many com queries [\"Ollama official API create GGUF\", \"Python pathlib official documentation\"] e max_results 2. Depois escreva apenas uma frase com duas URLs realmente retornadas."}) as stream:
                        stream.raise_for_status()
                        events = [json.loads(line) for line in stream.iter_lines() if line]
                    report.update(events=events, seconds=round(time.perf_counter() - started, 3), session_id=session)
                    tools = [event for event in events if event.get("type") == "tool"]
                    assert any(event.get("name") == "search_many" and event.get("result", {}).get("ok") for event in tools), "Modelo não executou pesquisa nativa com sucesso."
                    assert any(event.get("type") == "research_status" and event["performed"] for event in events), "Pesquisa não foi identificada pelo backend."
                    history = client.get("/api/sessions/" + session).json()
                    assistant = [row for row in history["messages"] if row["role"] == "assistant"]
                    assert assistant and assistant[-1]["metadata"]["model"] == MODEL and assistant[-1]["metadata"]["workspace_mode"] == "search"
                    report.update(status="passed", history_metadata=assistant[-1]["metadata"])
                except Exception as exc:
                    report.update(status="failed", error=str(exc))
                finally:
                    if agent_id:
                        value = client.get("/api/library/agents/" + agent_id).json()
                        response = client.delete("/api/library/agents/" + agent_id, params={"revision": value["revision"]})
                        report["temporary_agent_removed"] = response.status_code == 200
                    try:
                        httpx.post("http://127.0.0.1:11434/api/generate", json={"model": MODEL, "keep_alive": 0, "stream": False}, trust_env=False, timeout=45).raise_for_status()
                    except Exception as exc:
                        report["unload_error"] = str(exc)
    else:
        report["reason"] = "Margem preventiva de 1 GiB não atingida; nenhum pedido de inferência foi enviado."
    target = ROOT / "reports/multimodal-chat-runtime.json"
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
