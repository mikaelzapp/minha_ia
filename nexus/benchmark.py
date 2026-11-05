"""Testes reais A–J. Resultados e falhas são gravados, sem simular sucesso.

python -m nexus.benchmark --quick  # A, H e J
python -m nexus.benchmark --base-url http://127.0.0.1:8765  # A–J
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .config import DATA, ROOT, WORKSPACES, Settings
from .diagnostics import system_status
from .engine import Ollama

def clean_code(text):
    match = re.search(r"```(?:python)?\s*([\s\S]*?)```", text)
    code = match.group(1).strip() if match else text.strip()
    tree = ast.parse(code)
    allowed = (ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Return, ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Name, ast.Load, ast.Constant, ast.Expr)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise ValueError("Programa gerado saiu do subconjunto aritmético permitido pelo benchmark.")
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef) or tree.body[0].name != "soma":
        raise ValueError("O programa precisa conter somente def soma(a,b).")
    if tree.body[0].decorator_list or any(n.id not in ("a", "b") for n in ast.walk(tree) if isinstance(n, ast.Name)):
        raise ValueError("Código inesperado no benchmark.")
    return code

def run_program(code, path):
    clean_code(code)
    path.write_text(code + '\nassert soma(2,3)==5\nassert soma(-2,2)==0\nprint("2 testes passaram")\n', encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(path)], capture_output=True, text=True, timeout=15, cwd=path.parent)
    return {"returncode": result.returncode, "stdout": result.stdout.strip(), "stderr": result.stderr[-1500:]}

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--model", action="append", help="Repita para comparar modelos já instalados. 9B nunca é escolhido automaticamente.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--tor", action="store_true", help="Executa I somente se Tor também estiver ativado na configuração.")
    parser.add_argument("--tor-test-url", default="", help="URL .onion v3 legítima explicitamente escolhida pelo operador.")
    args = parser.parse_args()
    settings = Settings()
    engine = Ollama(settings["ollama_url"])
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "real_tests": True, "before": system_status(), "models": [], "tests": {}}
    output_path = ROOT / "reports" / ("benchmark-quick.json" if args.quick else "integracao.json")

    def record(name, ok, **data):
        report["tests"][name] = {"status": "passed" if ok else "failed", **data}
        output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"{name}: {'PASSOU' if ok else 'FALHOU'}", flush=True)

    async def generate(model, prompt, max_tokens=256, thinking=False):
        text, metrics = "", {}
        async for event in engine.stream(model, [{"role": "user", "content": prompt}], context=settings["context"], temperature=0, max_tokens=max_tokens, thinking=thinking):
            if event["type"] == "token":
                text += event["content"]
            elif event["type"] == "metrics":
                metrics = event
        return text, metrics

    for model in args.model or [settings["model"]]:
        current = {"model": model}
        try:
            await engine.prepare(model, {settings["model"], settings["coding_model"], *(args.model or [])} - {""})
            answer, metrics = await generate(model, "Responda somente: NEXUS local funcionando", 40)
            current.update({"answer": answer, "metrics": metrics})
            record("A_modelo", bool(answer.strip()), model=model, answer=answer, metrics=metrics)
            tools = [{"type": "function", "function": {"name": "somar", "description": "Calcula soma exata de dois inteiros. Use sempre esta ferramenta para somar.", "parameters": {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}, "required": ["a", "b"]}}}]
            calls, tool_metrics = [], {}
            async for event in engine.stream(model, [{"role": "user", "content": "Use a ferramenta somar com a=17 e b=25. Não calcule mentalmente."}], tools=tools, temperature=0, max_tokens=128):
                if event["type"] == "call":
                    calls.append(event["call"])
                if event["type"] == "metrics":
                    tool_metrics = event
            result = None
            for call in calls:
                f = call.get("function", {})
                parameters = f.get("arguments", {})
                if isinstance(parameters, str):
                    parameters = json.loads(parameters)
                if f.get("name") == "somar" and parameters == {"a": 17, "b": 25}:
                    result = parameters["a"] + parameters["b"]
            current["tool_calls"] = calls
            current["tool_metrics"] = tool_metrics
            record("H_ferramentas", result == 42, model=model, calls=calls, executed_result=result, metrics=tool_metrics)
            reasoning, reason_metrics = await generate(model, "Há três caixas. A contém 2 peças, B tem o dobro de A e C tem 3 peças a mais que B. Quantas peças no total? Responda SOMENTE o total numérico, sem explicação.", 1536, thinking=True)
            current["reasoning"] = {"answer": reasoning, "expected": 13, "metrics": reason_metrics, "automatic_check": bool(re.search(r"\b13\b", reasoning))}
            if not args.quick:
                demo = WORKSPACES / "exemplo-calculadora"
                demo.mkdir(exist_ok=True)
                code, code_metrics = await generate(model, "Escreva somente código Python: def soma(a, b) que retorna a soma. Sem imports, docstrings ou comentários, apenas a função.", 128)
                generated = clean_code(code)
                first = run_program(generated, demo / "calculadora_gerada.py")
                # Erro inserido deliberadamente para verificar um ciclo de correção reproduzível.
                faulty = "def soma(a, b):\n    return a - b\n"
                failure = run_program(faulty, demo / "calculadora_bug.py")
                fixed, fix_metrics = await generate(model, "Corrija este código. Teste assert soma(2,3)==5 falhou com AssertionError. Retorne SOMENTE a função Python sem imports: \n" + faulty, 128)
                corrected = clean_code(fixed)
                corrected_result = run_program(corrected, demo / "calculadora.py")
                record("B_programacao", first["returncode"] == 0 and failure["returncode"] != 0 and corrected_result["returncode"] == 0, generated_code=generated, generated_run=first, deliberately_seeded_bug=faulty, failing_test=failure, corrected_code=corrected, corrected_run=corrected_result, metrics=[code_metrics, fix_metrics])
            report["models"].append(current)
        except Exception as exc:
            current["error"] = str(exc)
            report["models"].append(current)
            record("A_modelo", False, model=model, error=str(exc))

    if not args.quick:
        from .memory import Memory
        from .tools import Tools
        memory = Memory(DATA / "memory.sqlite3", WORKSPACES, settings["ollama_url"], settings["embedding_model"])
        tools = Tools(WORKSPACES, DATA, settings["ollama_url"], settings["searxng_url"], settings["tor_enabled"], settings["tor_proxy"])
        demo = WORKSPACES / "exemplo-calculadora"
        demo.mkdir(exist_ok=True)
        (demo / "README.md").write_text("# Calculadora de exemplo NEXUS\nProjeto Python de exemplo. calculadora.py contém soma(a,b), usada para adicionar dois números.\n", encoding="utf-8")
        try:
            project = memory.register_project("Calculadora de exemplo", str(demo))
            indexed = await asyncio.to_thread(memory.index_project, project["id"])
            found = await asyncio.to_thread(memory.search, "função que adiciona dois números calculadora", project["id"], 4)
            answer, metrics = await generate(settings["model"], "Responda apenas com base nos arquivos recuperados: qual arquivo contém soma(a,b)?\n" + json.dumps(found, ensure_ascii=False)[:5000], 150)
            record("C_projeto", bool(found) and "calculadora" in answer.lower(), project=project, indexed=indexed, retrieved=found, answer=answer, metrics=metrics, memory_status=memory.status())
        except Exception as exc:
            record("C_projeto", False, error=str(exc))
        try:
            results = await asyncio.to_thread(tools.execute, "search_web", {"query": "site:docs.python.org/3/library/pathlib.html Path documentation", "max_results": 4})
            page = await asyncio.to_thread(tools.execute, "fetch_page", {"url": "https://docs.python.org/3/library/pathlib.html"})
            record("D_pesquisa", not bool(results.get("error")) and not bool(page.get("error")) and "pathlib" in json.dumps(page).lower(), search=results, official_page=page)
        except Exception as exc:
            record("D_pesquisa", False, error=str(exc))
        try:
            page = await asyncio.to_thread(tools.execute, "browser_open", {"url": "https://example.com"})
            record("E_navegacao", not bool(page.get("error")) and "Example Domain" in json.dumps(page), result=page)
        except Exception as exc:
            record("E_navegacao", False, error=str(exc))
        try:
            preference = "No projeto de demonstração NEXUS, prefiro type hints em Python e testes com unittest."
            saved = await asyncio.to_thread(memory.remember, preference, "preference")
            another = Memory(DATA / "memory.sqlite3", WORKSPACES, settings["ollama_url"], settings["embedding_model"])
            new_session = another.create_session("Teste de memória — nova sessão")
            retrieved = await asyncio.to_thread(another.search, "preferência type hints Python unittest", None, 5)
            record("F_memoria", any("type hints" in r.get("text", "") for r in retrieved), stored=saved, new_session=new_session, retrieved=retrieved)
        except Exception as exc:
            record("F_memoria", False, error=str(exc))
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=300, base_url=args.base_url) as client:
                front = await client.get("/")
                front.raise_for_status()
                session = await client.post("/api/sessions", json={"title": "Teste G — interface e modelo local"})
                session.raise_for_status()
                answer = await client.post("/api/chat", json={"session_id": session.json()["id"], "message": "Responda em uma frase: o modelo local está conectado?", "mode": "CHAT", "model": settings["model"]})
                answer.raise_for_status()
                events = [json.loads(line) for line in answer.text.splitlines() if line]
                text = "".join(e.get("content", "") for e in events if e["type"] == "token")
                record("G_interface", front.status_code == 200 and bool(text) and not any(e["type"] == "error" for e in events), answer=text, events=events, note="API chamada pela interface verificada aqui; teste DOM separado em reports/ui.json.")
        except Exception as exc:
            record("G_interface", False, error=str(exc))
        if args.tor and settings["tor_enabled"]:
            try:
                connection = await asyncio.to_thread(tools.execute, "tor_check", {})
                if args.tor_test_url:
                    page = await asyncio.to_thread(tools.execute, "tor_fetch", {"url": args.tor_test_url})
                    record("I_tor", not bool(connection.get("error")) and not bool(page.get("error")), connection=connection, page=page)
                else:
                    report["tests"]["I_tor"] = {"status": "skipped", "reason": "Conexão verificável, mas nenhuma URL onion de teste foi autorizada.", "connection": connection}
            except Exception as exc:
                record("I_tor", False, error=str(exc))
        else:
            report["tests"]["I_tor"] = {"status": "skipped", "reason": "Módulo desativado; usuário não ativou Tor."}
        if hasattr(tools, "close"):
            tools.close()
    after = system_status()
    inventory = await engine.inventory()
    report["after"] = after
    record("J_recursos", bool(after["gpu"]), before=report["before"], after=after, ollama_running=inventory["running"], note="RAM inclui os demais programas; VRAM e alocação de modelos são medidas reais. Não é um teste prolongado de estabilidade.")
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(str(output_path), flush=True)
    return 1 if any(t["status"] == "failed" for t in report["tests"].values()) else 0

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
