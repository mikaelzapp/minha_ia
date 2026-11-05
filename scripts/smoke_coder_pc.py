"""Integração real; aprova só código aritmético de teste, nunca aplicativos."""
import ast
import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
TARGET = "validacao-coder/sistema_demo.py"
ARGV = [sys.executable, "-I", TARGET]

def safe_test_code(code):
    try:
        tree = ast.parse(code)
        allowed = (ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Return, ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Name, ast.Load, ast.Constant, ast.Expr, ast.Call, ast.Assert, ast.Compare, ast.Eq, ast.UnaryOp, ast.USub)
        return bool(tree.body) and all(isinstance(node, allowed) for node in ast.walk(tree)) and all(node.id in {"a", "b", "soma", "print"} for node in ast.walk(tree) if isinstance(node, ast.Name)) and all(isinstance(node.func, ast.Name) and node.func.id in {"soma", "print"} for node in ast.walk(tree) if isinstance(node, ast.Call)) and all(node.name == "soma" and not node.decorator_list for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
    except (ValueError, SyntaxError):
        return False

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=("codigo", "pc_catalogo", "pasta_pc"))
    cli_options = parser.parse_args()
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "installed_any_app": False, "tests": {}}
    report_path = ROOT / "reports" / "integracao-coder-pc.json"
    if cli_options.only and report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    token = (ROOT / "data" / "auth.secret").read_text(encoding="ascii").strip()
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8765", headers={"Authorization": "Bearer " + token}, trust_env=False, timeout=900) as client:
        response = await client.get("/api/status")
        response.raise_for_status()
        report["settings"] = response.json()["settings"]
        before = await client.get("/api/computer")
        before.raise_for_status()
        grant = await client.post("/api/computer/roots", json={"path": str(ROOT / "workspaces" / "validacao-coder")})
        grant.raise_for_status()
        root_id = grant.json()["id"]
        report["tests"]["grant_real"] = {"status": "passed", "root": grant.json()}
        async def chat_case(name, message, agent, mode):
            if cli_options.only and cli_options.only != name:
                prior_key = {"codigo": "codigo_integrado", "pc_catalogo": "catalogo_integrado", "pasta_pc": "pasta_pc_integrada"}[name]
                return report["tests"].get(prior_key, {}).get("events", [])
            session = await client.post("/api/sessions", json={"title": "Validação atualização — " + name})
            session.raise_for_status()
            events = []
            async with client.stream("POST", "/api/chat", json={"session_id": session.json()["id"], "message": message, "agent": agent, "mode": mode}) as answer:
                answer.raise_for_status()
                async for line in answer.aiter_lines():
                    if not line:
                        continue
                    event = json.loads(line)
                    events.append(event)
                    if event["type"] == "status":
                        print(name + ": " + event.get("content", ""), flush=True)
                    if event["type"] == "tool":
                        print(name + " TOOL " + event["name"] + " ok=" + str(not bool(event["result"].get("error"))), flush=True)
                    if event["type"] == "approval":
                        args = event.get("arguments", {})
                        allowed = event.get("tool") == "write_file" and args.get("path") == TARGET and safe_test_code(args.get("content", ""))
                        allowed = allowed or (event.get("tool") == "run_command" and args.get("args") == ARGV and args.get("cwd", ".") == ".")
                        decision = await client.post("/api/approvals/" + event["id"], json={"approved": bool(allowed)})
                        decision.raise_for_status()
                        print(name + " APPROVAL " + event.get("tool", "") + "=" + str(allowed), flush=True)
            return events
        try:
            events = await chat_case("codigo", "Use consult_coder para propor um pequeno programa Python. Crie somente " + TARGET + " com def soma(a,b), assert soma(2,3)==5, assert soma(-2,2)==0 e print('TESTE OK'). Sem imports, decorators ou anotações. Use write_file e peça a aprovação do diff. Depois execute run_command exatamente args=" + json.dumps(ARGV) + ", cwd='.', timeout=15. Corrija se os testes falharem. Informe só resultados reais.", "coder", "AGENT")
            tools = [e for e in events if e["type"] == "tool"]
            consulted = any(e["name"] == "consult_coder" and e["result"].get("ok") for e in tools)
            written = any(e["name"] == "write_file" and e["result"].get("ok") for e in tools)
            executed = any(e["name"] == "run_command" and e["result"].get("exit_code") == 0 and "TESTE OK" in e["result"].get("output", "") for e in tools)
            reviewed = any(e["type"] == "metrics" and e.get("phase") == "review" and e.get("model") == "qwen2.5-coder:7b" for e in events)
            report["tests"]["codigo_integrado"] = {"status": "passed" if consulted and written and executed and reviewed else "failed", "consulted": consulted, "written": written, "executed": executed, "reviewed": reviewed, "events": events}
            (ROOT / "reports" / "integracao-coder-pc.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            events = await chat_case("pc_catalogo", "Use computer_info e depois app_details para consultar Microsoft.VisualStudioCode no escopo user. Apenas informe versão, fornecedor e licença do catálogo oficial. NÃO instale nada, NÃO execute run_command.", "devops", "AGENT")
            metadata = [e for e in events if e["type"] == "tool" and e.get("name") == "app_details"]
            ok = any(e["result"].get("ok") and e["result"].get("publisher") == "Microsoft Corporation" for e in metadata)
            report["tests"]["catalogo_integrado"] = {"status": "passed" if ok else "failed", "installed_any_app": False, "events": events}
            pc_events = await chat_case("pasta_pc", "Use pc_read_file com root_id=" + root_id + " e path='sistema_demo.py' para ler o arquivo na pasta autorizada do computador. Apenas informe o que os asserts verificam; não altere ou execute nada.", "coder", "PLAN")
            read = any(e["type"] == "tool" and e.get("name") == "pc_read_file" and e["result"].get("ok") for e in pc_events)
            report["tests"]["pasta_pc_integrada"] = {"status": "passed" if read else "failed", "events": pc_events}
        finally:
            if not any(r["id"] == root_id for r in before.json()["roots"]):
                revoked = await client.delete("/api/computer/roots/" + root_id)
                revoked.raise_for_status()
                report["tests"]["grant_real"]["temporary_grant_revoked"] = True
            (ROOT / "reports" / "integracao-coder-pc.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if all(t["status"] == "passed" for t in report["tests"].values()) else 1

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
