"""Ensaio curto real de roteamento/ferramenta; sem downloads ou alvos externos."""
import json
from datetime import datetime, timezone
from pathlib import Path
import time

import httpx
import psutil

ROOT = Path(__file__).resolve().parent.parent
MODELS = [("qwen3.5:4b-q4_K_M", 1), ("huihui_ai/qwen3.5-abliterated:9b-q4_K", 4)]


def main():
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "kind": "single_security_tool_smoke",
              "comparison_completed": False, "models": [], "downloads": False}
    token = (ROOT / "data/auth.secret").read_text(encoding="ascii").strip()
    with httpx.Client(base_url="http://127.0.0.1:8765", headers={"Authorization": "Bearer " + token},
                      trust_env=False, timeout=180) as client:
        projects = client.get("/api/projects").json()
        project = next(item for item in projects if Path(item["path"]).name == "security-center-lab")
        for model, minimum in MODELS:
            available = psutil.virtual_memory().available / 2**30
            row = {"model": model, "ram_available_gib": round(available, 3), "minimum_test_gib": minimum}
            report["models"].append(row)
            if available < minimum:
                row.update(status="not_run_resources", reason="Orçamento preventivo do ensaio; não é requisito oficial do modelo.")
                continue
            before = client.get("/api/status").json()["ollama"]["running"]
            if before:
                row.update(status="not_run_busy", reason="Outro modelo está residente; ensaio não altera cargas de outros clientes.")
                continue
            session = client.post("/api/sessions", json={"title": "Validação Security Center — " + model,
                                                         "project_id": project["id"]}).json()["id"]
            started, events = time.perf_counter(), []
            try:
                with client.stream("POST", "/api/chat", json={"session_id": session, "project_id": project["id"],
                    "message": "Audite o repositório selecionado. Use agora security_code_audit com project_id " + project["id"] +
                    ". Não execute o código. Depois resuma em até 120 palavras o achado, a linha e uma correção. Diferencie hipótese e confirmação.",
                    "agent": "auto", "mode": "REVIEW", "model": model, "context": 4096,
                    "temperature": 0, "thinking": False, "profile": "unrestricted_local"}) as response:
                    response.raise_for_status()
                    for line in response.iter_lines():
                        if line:
                            events.append(json.loads(line))
                row.update(seconds=round(time.perf_counter() - started, 3), session_id=session,
                           routed_agent="code_auditor", events=events)
                calls = [item for item in events if item.get("type") == "tool"]
                errors = [item for item in events if item.get("type") == "error"]
                row["native_security_tool_passed"] = any(item.get("name") == "security_code_audit" and item.get("result", {}).get("ok") for item in calls)
                row["status"] = "passed" if row["native_security_tool_passed"] and not errors else "failed"
                row["note"] = "Um caso de ferramenta, sem estimativa geral de qualidade ou de frequência de recusas."
            except Exception as exc:
                row.update(status="failed", error=str(exc), seconds=round(time.perf_counter() - started, 3))
            finally:
                # O ensaio começou com lista vazia. Só descarrega o próprio alvo.
                try:
                    httpx.post("http://127.0.0.1:11434/api/generate", json={"model": model, "keep_alive": 0, "stream": False},
                               trust_env=False, timeout=45).raise_for_status()
                except Exception as exc:
                    row["unload_error"] = str(exc)
    destination = ROOT / "reports/security-model-smoke.json"
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"report": str(destination), "models": [{key: value for key, value in row.items() if key not in {"events"}} for row in report["models"]]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
