"""Exercita o agente real; aprova só dois casos de teste estritamente conhecidos."""
import asyncio
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from nexus.config import Settings

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case")
    args = parser.parse_args()
    settings = Settings()
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "tests": {}}
    report_path = ROOT / "reports" / "agente.json"
    if args.case and report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    token = (ROOT / "data" / "auth.secret").read_text(encoding="ascii").strip()
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8765", headers={"Authorization": "Bearer " + token}, trust_env=False, timeout=300) as client:
        async def run_case(name, message, mode, checker, approve=None):
            if args.case and args.case != name:
                return
            session = (await client.post("/api/sessions", json={"title": "Teste agente — " + name})).json()["id"]
            events = []
            async with client.stream("POST", "/api/chat", json={"session_id": session, "message": message, "mode": mode, "agent": "coder", "model": settings["model"]}) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    event = json.loads(line)
                    events.append(event)
                    if event["type"] == "approval":
                        allowed = bool(approve and approve(event))
                        decision = await client.post("/api/approvals/" + event["id"], json={"approved": allowed})
                        decision.raise_for_status()
            ok = checker(events) and not any(e["type"] == "error" for e in events)
            previous = report["tests"].get(name)
            report["tests"][name] = {"status": "passed" if ok else "failed", "events": events, "revalidated_at": datetime.now(timezone.utc).isoformat()}
            if previous:
                report["tests"][name]["previous_attempt"] = previous
            print(name + (": PASSOU" if ok else ": FALHOU"), flush=True)
            (ROOT / "reports" / "agente.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        await run_case("leitura_real", "Use read_file para ler exemplo-calculadora/calculadora.py e diga qual operação soma(a,b) executa. Não altere nada.", "PLAN", lambda es: any(e["type"] == "tool" and e.get("name") == "read_file" and not e.get("result", {}).get("error") for e in es))
        path = "exemplo-calculadora/aprovacao_nexus.txt"
        content = "NEXUS: escrita aprovada no teste."
        await run_case("diff_e_aprovacao", f"Crie o arquivo {path} usando write_file com o conteúdo exato: {json.dumps(content, ensure_ascii=False)}. Peça a aprovação pela ferramenta e depois informe o resultado.", "CODE", lambda es: any(e["type"] == "approval" for e in es) and any(e["type"] == "tool" and e.get("name") == "write_file" and e.get("result", {}).get("ok") for e in es), lambda e: e.get("tool") == "write_file" and e["arguments"].get("path") == path and e["arguments"].get("content") == content)
        await run_case("recusa_sem_escrita", "Use write_file para criar exemplo-calculadora/NAO_APROVADO.txt com conteúdo 'recusado'. Aguarde a decisão da ferramenta e informe o resultado sem tentar outro caminho.", "CODE", lambda es: any(e["type"] == "approval" for e in es) and not (ROOT / "workspaces" / "exemplo-calculadora" / "NAO_APROVADO.txt").exists(), lambda _: False)
        expected = [sys.executable, "-I", "exemplo-calculadora/calculadora.py"]
        await run_case("terminal_aprovado", "Execute com run_command exatamente args=" + json.dumps(expected) + ", cwd='.', timeout=15. Não altere arquivos. Informe o resultado real dos testes.", "AGENT", lambda es: any(e["type"] == "tool" and e.get("name") == "run_command" and e.get("result", {}).get("exit_code") == 0 for e in es), lambda e: e.get("tool") == "run_command" and e["arguments"].get("args") == expected and e["arguments"].get("cwd", ".") == ".")
    return 0 if all(t["status"] == "passed" for t in report["tests"].values()) else 1

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
