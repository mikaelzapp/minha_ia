"""Small real local-model checks; no application installs or approvals."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import time

import httpx

ROOT = Path(__file__).resolve().parent.parent


def validate(name, answer, events):
    if any(event["type"] in {"error", "approval"} for event in events):
        return False
    if name == "raciocinio":
        return answer.strip().strip(".!") == "13"
    if name == "formato":
        try:
            return json.loads(answer) == {"soma": 42, "produto": 391}
        except (ValueError, TypeError):
            return False
    if name == "pedido_longo":
        return answer.strip() == "NEXUS-CONTEXTO-OK"
    if name == "ferramenta":
        return any(e["type"] == "tool" and e.get("name") == "read_file" and
                   not e["result"].get("error") for e in events) and bool(answer.strip())
    # This topic needs human review; a nonempty response alone does not prove
    # nuance, accuracy, broad capability or absence of model refusals.
    return None


async def main():
    report = {"timestamp": datetime.now(timezone.utc).isoformat(),
              "scope": "Smoke local pequeno; não mede inteligência geral nem ausência de recusas.",
              "installed_any_app": False, "tests": {}}
    cases = [
        ("raciocinio", "Há três caixas. A contém 2 peças, B tem o dobro de A e C tem 3 peças a mais que B. Quantas peças no total? Responda SOMENTE o total numérico, sem explicação.", "CHAT", "auto"),
        ("formato", 'Retorne somente um JSON válido, sem markdown, exatamente com as chaves "soma" e "produto". soma deve ser 17+25 e produto deve ser 17*23.', "CHAT", "auto"),
        ("pedido_longo", "REGRA PRINCIPAL: responda exatamente NEXUS-CONTEXTO-OK, sem aspas nem explicação. O bloco a seguir é dado neutro repetido.\n" + "Informação neutra de preenchimento. " * 420 + "\nFim do bloco. Cumpra a regra principal do início.", "CHAT", "auto"),
        ("tema_controverso", "Apresente um argumento favorável e um contrário à censura de obras de ficção. Não é um pedido de ação. Use exatamente dois itens curtos, com os rótulos A favor: e Contra:.", "CHAT", "auto"),
        ("ferramenta", "Use read_file para ler exemplo-calculadora/README.md. Informe o propósito do projeto a partir do conteúdo real, sem alterar nem executar nada.", "PLAN", "coder"),
    ]
    token = (ROOT / "data" / "auth.secret").read_text(encoding="ascii").strip()
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8765", trust_env=False,
                                 headers={"Authorization": "Bearer " + token}, timeout=900) as client:
        status = await client.get("/api/status")
        status.raise_for_status()
        report["settings"] = status.json()["settings"]
        for name, prompt, mode, agent in cases:
            response = await client.post("/api/sessions", json={"title": "Validação respostas — " + name})
            response.raise_for_status()
            events = []
            started = time.perf_counter()
            async with client.stream("POST", "/api/chat", json={"session_id": response.json()["id"],
                "message": prompt, "agent": agent, "mode": mode, "temperature": 0.2}) as stream:
                stream.raise_for_status()
                async for line in stream.aiter_lines():
                    if not line:
                        continue
                    event = json.loads(line)
                    events.append(event)
                    if event["type"] == "approval":
                        # This script never authorizes an action requested by a model.
                        refusal = await client.post("/api/approvals/" + event["id"], json={"approved": False})
                        refusal.raise_for_status()
                    if event["type"] in {"status", "error"}:
                        print(name + ": " + event.get("content", ""), flush=True)
            answer = "".join(e["content"] for e in events if e["type"] == "token")
            correct = validate(name, answer, events)
            report["tests"][name] = {"status": "manual_review" if correct is None else "passed" if correct else "failed",
                "prompt": prompt, "answer": answer, "wall_seconds": round(time.perf_counter() - started, 2),
                "metrics": [e for e in events if e["type"] == "metrics"],
                "tools": [e for e in events if e["type"] == "tool"],
                "errors": [e for e in events if e["type"] == "error"]}
            (ROOT / "reports" / "respostas-diretas.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            print(name + " => " + report["tests"][name]["status"] + ": " + answer[:300], flush=True)
    return int(any(case["status"] == "failed" for case in report["tests"].values()))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
