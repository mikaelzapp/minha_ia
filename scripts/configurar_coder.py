"""Acrescenta consultor ao perfil Continue NEXUS preservando configuração atual."""
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BLOCK = """
  # Consultor para propostas de código. Para Agent, use NEXUS Qwen 3.5 4B.
  - name: NEXUS Coder 7B (consultor)
    provider: ollama
    model: qwen2.5-coder:7b
    apiBase: http://127.0.0.1:11434
    roles:
      - chat
      - edit
      - apply
    defaultCompletionOptions:
      contextLength: 4096
      maxTokens: 1536
      temperature: 0.2
      keepAlive: 0
"""

for target in (ROOT / "integrations" / "continue.yaml", ROOT / "data" / "continue" / "config.yaml"):
    if not target.exists():
        continue
    source = target.read_text(encoding="utf-8-sig")
    if "model: qwen2.5-coder:7b" in source:
        print("Consultor já configurado: " + str(target.relative_to(ROOT)))
        continue
    if "models:" not in source or any(line and not line.startswith((" ", "#")) and line.split(":", 1)[0] in {"rules", "prompts", "context", "mcpServers"} for line in source.splitlines()):
        raise ValueError("Configuração personalizada com outras seções: adicione o bloco models manualmente para preservar sua estrutura.")
    backup = target.with_name(target.name + "." + datetime.now().strftime("%Y%m%d%H%M%S") + ".bak")
    backup.write_bytes(target.read_bytes())
    target.write_text(source.rstrip() + "\n" + BLOCK, encoding="utf-8")
    print("Consultor adicionado: " + str(target.relative_to(ROOT)))
