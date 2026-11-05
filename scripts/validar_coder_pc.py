"""Mede o especialista em 4K e verifica geração/correção sem instalar programas."""
import ast
import asyncio
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from nexus.engine import Ollama
from nexus.diagnostics import system_status
from nexus.computer import Computer

MODEL = "qwen2.5-coder:7b"

async def main():
    engine = Ollama("http://127.0.0.1:11434")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "model": MODEL, "context": 4096, "before": system_status(), "tests": {}}
    await engine.prepare(MODEL, {MODEL, "qwen3.5:4b-q4_K_M"})
    schemas = [{"type": "function", "function": {"name": "somar", "description": "Use esta função para somar dois inteiros.", "parameters": {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}, "required": ["a", "b"]}}}]
    text, calls, metrics = "", [], {}
    async for event in engine.stream(MODEL, [{"role": "system", "content": "You are a tool-using assistant. Always invoke the supplied function when requested. Do not write function calls as text."}, {"role": "user", "content": "Call somar with a=17 and b=25 now."}], tools=schemas, context=4096, temperature=0, max_tokens=256):
        if event["type"] == "token": text += event["content"]
        if event["type"] == "call": calls.append(event["call"])
        if event["type"] == "metrics": metrics = event
    invoked = any(c.get("function", {}).get("name") == "somar" and c["function"].get("arguments") == {"a": 17, "b": 25} for c in calls)
    report["tests"]["tools_4k"] = {"status": "passed" if invoked else "failed", "calls": calls, "text": text, "executed_result": 42 if invoked else None, "metrics": metrics}
    print("tools_4k: " + ("PASSOU" if invoked else "FALHOU"), flush=True)
    cases = [
        ("geracao", "Write only Python code, no markdown: a single function soma(a,b) returning the sum. No imports, no annotations, no docstrings."),
        ("correcao", "Fix this Python function. Test soma(2,3)==5 currently fails. Return ONLY the function without imports, annotations, docstrings or markdown:\ndef soma(a,b):\n    return a-b"),
    ]
    for name, prompt in cases:
        code, metrics = "", {}
        async for event in engine.stream(MODEL, [{"role": "user", "content": prompt}], context=4096, temperature=0, max_tokens=192):
            if event["type"] == "token": code += event["content"]
            if event["type"] == "metrics": metrics = event
        match = re.search(r"```(?:python)?\s*([\s\S]*?)```", code)
        code = match.group(1).strip() if match else code.strip()
        allowed = (ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Return, ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Name, ast.Load, ast.Constant, ast.Expr)
        try:
            tree = ast.parse(code)
            if any(not isinstance(node, allowed) for node in ast.walk(tree)) or len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef) or tree.body[0].name != "soma" or tree.body[0].decorator_list or any(n.id not in ("a", "b") for n in ast.walk(tree) if isinstance(n, ast.Name)):
                raise ValueError("Código fora do subconjunto aritmético autorizado pelo teste.")
            folder = ROOT / "workspaces" / "validacao-coder"
            folder.mkdir(exist_ok=True)
            target = folder / (name + ".py")
            target.write_text(code + '\nassert soma(2,3)==5\nassert soma(-2,2)==0\nassert soma(0,0)==0\nprint("3 testes passaram")\n', encoding="utf-8")
            process = subprocess.run([sys.executable, "-I", str(target)], capture_output=True, text=True, timeout=10)
            result = {"returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr[-1000:]}
            ok = process.returncode == 0
        except Exception as exc:
            ok, result = False, {"error": str(exc)}
        report["tests"][name] = {"status": "passed" if ok else "failed", "code": code, "execution": result, "metrics": metrics}
        print(name + (": PASSOU" if ok else ": FALHOU"), flush=True)
    report["after"] = system_status()
    report["running"] = (await engine.inventory())["running"]
    report["computer"] = Computer(ROOT / "data", ROOT / "workspaces").execute("computer_info", {})
    metadata = Computer(ROOT / "data", ROOT / "workspaces").execute("app_details", {"package_id": "Microsoft.VisualStudioCode", "scope": "user"})
    report["tests"]["winget_metadata"] = {"status": "passed" if metadata.get("ok") else "failed", "result": metadata, "installed_any_app": False}
    (ROOT / "reports" / "coder-pc.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    await engine.unload(MODEL)
    print(str(ROOT / "reports" / "coder-pc.json"), flush=True)
    return 0 if all(v["status"] == "passed" for v in report["tests"].values()) else 1

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
