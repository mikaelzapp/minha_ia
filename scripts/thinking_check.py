"""Compara o mesmo problema com o raciocínio local ativado, sem apagar falha anterior."""
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from nexus.config import Settings
from nexus.engine import Ollama

async def main():
    settings = Settings()
    engine = Ollama(settings["ollama_url"])
    prompt = "Há três caixas. A contém 2 peças, B tem o dobro de A e C tem 3 peças a mais que B. Quantas peças no total? Responda SOMENTE o total numérico, sem explicação."
    answer, metrics = "", {}
    async for event in engine.stream(settings["model"], [{"role": "user", "content": prompt}], context=4096, temperature=0, thinking=True, max_tokens=1536):
        if event["type"] == "token":
            answer += event["content"]
        if event["type"] == "metrics":
            metrics = event
    correct = bool(re.fullmatch(r"\s*13[.!]?\s*", answer))
    result = {"timestamp": datetime.now(timezone.utc).isoformat(), "status": "passed" if correct else "failed", "model": settings["model"], "thinking": True, "prompt": prompt, "answer": answer, "expected": 13, "metrics": metrics, "note": "Um único problema; não representa capacidade geral nem substitui testes de software."}
    (ROOT / "reports" / "raciocinio.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    return 0 if correct else 1

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
