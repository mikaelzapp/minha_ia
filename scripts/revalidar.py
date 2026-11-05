"""Revalida pesquisa corrigida, raciocínio e seis ciclos sequenciais reais."""
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from nexus.config import Settings, DATA, WORKSPACES
from nexus.diagnostics import system_status
from nexus.engine import Ollama
from nexus.tools import Tools

async def main():
    settings = Settings()
    tools = Tools(WORKSPACES, DATA, settings["ollama_url"], settings["searxng_url"], settings["tor_enabled"], settings["tor_proxy"])
    path = ROOT / "reports" / "integracao.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    old = report["tests"]["D_pesquisa"]
    search = await asyncio.to_thread(tools.execute, "search_web", {"query": "site:docs.python.org/3/library/pathlib.html Path documentation", "max_results": 4})
    generic = await asyncio.to_thread(tools.execute, "search_web", {"query": "Python pathlib official documentation", "max_results": 3})
    page = await asyncio.to_thread(tools.execute, "fetch_page", {"url": "https://docs.python.org/3/library/pathlib.html"})
    ok = bool(search.get("results")) and not search.get("error") and bool(generic.get("results")) and not generic.get("error") and page.get("status") == 200 and "pathlib" in page.get("text", "").casefold()
    report["tests"]["D_pesquisa"] = {"status": "passed" if ok else "failed", "revalidated_at": datetime.now(timezone.utc).isoformat(), "search": search, "generic_search": generic, "official_page": page, "previous_attempt": old}
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print("D_pesquisa: " + ("PASSOU" if ok else "FALHOU"), flush=True)
    engine = Ollama(settings["ollama_url"])
    samples = []
    resources = [system_status()]
    for number in range(6):
        prompt = "Há três caixas. A contém 2 peças, B tem o dobro de A e C tem 3 peças a mais que B. Quantas peças no total? Responda SOMENTE o total numérico, sem explicação." if number == 0 else f"Calcule {number}+{number} e responda somente o número."
        text, metrics = "", {}
        async for event in engine.stream(settings["model"], [{"role": "user", "content": prompt}], temperature=0, max_tokens=256):
            if event["type"] == "token":
                text += event["content"]
            if event["type"] == "metrics":
                metrics = event
        expected = 13 if number == 0 else number * 2
        correct = bool(re.search(r"\b" + str(expected) + r"\b", text))
        samples.append({"prompt": prompt, "answer": text, "expected": expected, "correct": correct, "metrics": metrics})
        resources.append(system_status())
        print(f"ciclo {number + 1}: " + ("PASSOU" if correct else "FALHOU"), flush=True)
    stability = {"status": "passed" if all(s["correct"] for s in samples) else "failed", "real_cycles": 6, "samples": samples, "resources": resources, "peak_system_ram_gb": max(r["ram_used_gb"] for r in resources), "peak_gpu_mb": max(g["memory_used_mb"] for r in resources for g in r["gpu"]), "note": "Smoke de estabilidade sequencial; não representa uso prolongado por horas."}
    (ROOT / "reports" / "estabilidade.json").write_text(json.dumps(stability, indent=2, ensure_ascii=False), encoding="utf-8")
    previous = report["models"][0].get("reasoning")
    report["models"][0]["reasoning"] = {**samples[0], "previous_attempt": previous}
    report["tests"]["J_recursos"]["sequential_stability"] = stability
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    tools.close()
    return 0 if ok and stability["status"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
