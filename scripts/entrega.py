"""Consolida evidências existentes e consulta estado final sem expor o token."""
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

ROOT = Path(__file__).resolve().parent.parent

def main():
    reports = ROOT / "reports"
    integration = json.loads((reports / "integracao.json").read_text(encoding="utf-8"))
    agent = json.loads((reports / "agente.json").read_text(encoding="utf-8"))
    ui = json.loads((reports / "ui.json").read_text(encoding="utf-8"))
    reasoning = json.loads((reports / "raciocinio.json").read_text(encoding="utf-8"))
    log_bytes = (reports / "instalacao.log").read_bytes()
    install_log = log_bytes.decode("utf-16") if log_bytes.startswith((b"\xff\xfe", b"\xfe\xff")) else log_bytes.decode("utf-8", errors="replace")
    matches = re.findall(r"\d+ passed, \d+ skipped[^\r\n]*", install_log)
    tests_line = matches[-1] if matches else "Consulte reports/instalacao.log"
    token = (ROOT / "data" / "auth.secret").read_text(encoding="ascii").strip()
    with httpx.Client(base_url="http://127.0.0.1:8765", headers={"Authorization": "Bearer " + token}, trust_env=False, timeout=30) as client:
        status = client.get("/api/status")
        status.raise_for_status()
        final_status = status.json()
        # Remove somente a preferência artificial criada pelo teste F; evidência permanece no relatório.
        test_memory = integration["tests"]["F_memoria"].get("stored", {})
        if test_memory.get("text", "").startswith("No projeto de demonstração NEXUS,"):
            deleted = client.delete("/api/memory/" + test_memory["id"])
            deleted.raise_for_status()
            integration["tests"]["F_memoria"]["test_preference_removed_after_validation"] = True
            (reports / "integracao.json").write_text(json.dumps(integration, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        now = datetime.now(ZoneInfo("America/Sao_Paulo"))
    except ZoneInfoNotFoundError:
        now = datetime.now().astimezone()
    summary = {"timestamp": now.isoformat(), "project": str(ROOT), "url": "http://127.0.0.1:8765", "installer_validated": "Instalação pronta" in install_log or "Instala\ufffd\ufffdo pronta" in install_log, "unit_tests": tests_line, "integration": {k: v["status"] for k, v in integration["tests"].items()}, "agent": {k: v["status"] for k, v in agent["tests"].items()}, "ui": ui["status"], "reasoning_with_thinking": reasoning["status"], "system": final_status["system"], "memory": final_status["memory"], "settings": final_status["settings"], "limitations": ["Tor desativado e sem instalação oficial validada", "Interação na janela do VS Code não testada manualmente", "Teste de estabilidade curto, sem validação prolongada", "Um erro lógico sem thinking está preservado nos relatórios", "Um ERR_ABORTED foi registrado no QA UI; resposta e persistência passaram; causa não confirmada", "Execução de comandos aprovados usa permissões do usuário e não é sandbox de SO", "Não foi configurado início automático após login Windows"]}
    (reports / "entrega.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    systems = final_status["system"]
    rows = []
    labels = {"A_modelo": "A — Modelo local", "B_programacao": "B — Programa e correção", "C_projeto": "C — Repositório e recuperação", "D_pesquisa": "D — Documentação oficial", "E_navegacao": "E — Browser público", "F_memoria": "F — Memória em nova sessão", "G_interface": "G — Interface e modelo", "H_ferramentas": "H — Tool calling real", "I_tor": "I — Tor opcional", "J_recursos": "J — GPU/RAM e latência"}
    details = {"A_modelo": "Resposta gerada pelo Qwen instalado; 100% GPU.", "B_programacao": "Python gerado, erro inserido deliberadamente, teste falhou e modelo corrigiu.", "C_projeto": "Projeto exemplo indexado e pergunta respondida com contexto dos arquivos.", "D_pesquisa": "Fontes reais DuckDuckGo e documentação Python. Consulta restrita usa verificação direta explicitamente rotulada. Falha anterior preservada.", "E_navegacao": "example.com renderizado no Chromium isolado; título e screenshot extraídos.", "F_memoria": "Preferência recuperada por nova instância; dado artificial removido após validação.", "G_interface": "API e navegador real responderam; desktop/mobile e memória CRUD/export passaram.", "H_ferramentas": "Chamada somar(17,25) gerada pelo modelo e executada com resultado42.", "I_tor": "Não ativado pelo usuário; sem conexão onion testada.", "J_recursos": "Métricas reais e seis chamadas sequenciais sem falha técnica; uma resposta lógica errada sem raciocínio, revalidada separadamente com raciocínio ativo."}
    for key, label in labels.items():
        value = integration["tests"].get(key, {"status": "not-run"})
        state = {"passed": "Passou", "failed": "Falhou", "skipped": "Não executado"}.get(value["status"], value["status"])
        rows.append(f"| {label} | {state} | {details[key]} |")
    content = f"""# Entrega NEXUS AI

Validação final: {now.strftime('%d/%m/%Y %H:%M %z')} (São Paulo).

Projeto instalado: `{ROOT}`. Interface local: **http://127.0.0.1:8765**.

## Uso

- Iniciar: **Iniciar NEXUS.cmd**, ou `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\\iniciar.ps1 -Abrir`.
- Parar: **Parar NEXUS.cmd**, ou `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\\parar.ps1`.
- VS Code: `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\\vscode.ps1`.
- Diagnóstico: `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\\diagnosticar.ps1`.

Ollama preexistente foi reutilizado. Qwen3.5 4B Q4_K_M já estava baixado; EmbeddingGemma (622 MB) foi baixado com autorização. Nenhum modelo, container ou projeto preexistente foi removido. A API NEXUS escuta apenas em 127.0.0.1 e exige token/cookie local. Não houve mudança de firewall, antivírus, política global PowerShell ou perfil original do VS Code.

## Testes

Instalador executado novamente com dependências reutilizadas e lock de versões. Resultado: **{tests_line}**. O skip é um teste de symlink que exige privilégio do Windows; junctions NTFS reais e hardlinks foram testados. O aviso de depreciação de TestClient/httpx não afeta o runtime.

| Teste | Estado | Evidência |
| --- | --- | --- |
{chr(10).join(rows)}

O agente integrado também passou em leitura real, diff com aprovação e escrita, recusa sem alteração e terminal autorizado. Após ativar raciocínio, o teste de diff foi repetido e passou. As tentativas anteriores permanecem em `reports/agente.json`.

QA da interface: Chromium real, 1440 × 1000 e 390 × 844, sem overflow horizontal nem erros JS/console. Prompt real retornou `INTERFACE OK`, com histórico persistido. Houve um evento `net::ERR_ABORTED` de streaming, cuja causa não foi confirmada; resposta completa e persistência passaram. Aprovação visual e proteção contra HTML foram verificadas com fixture isolada; execução real foi verificada separadamente.

## Recursos e configuração final

- Modelo: `{final_status['settings']['model']}`, contexto: {final_status['settings']['context']} tokens, concorrência: 1, raciocínio aprofundado: {'ativo' if final_status['settings']['thinking'] else 'inativo'}.
- GPU medida durante inferência: aproximadamente 3,7 GiB / 6 GiB. Velocidade observada: aproximadamente 50–55 tokens/s; tokens internos também contam quando há raciocínio.
- Perguntas curtas sem raciocínio, modelo aquecido: aproximadamente 0,8–2 s. Problema com raciocínio: 7,8 s. Primeira carga: aproximadamente 91 s com RAM já quase cheia.
- Última medição RAM sistema: {systems['ram_used_gb']} GiB usados de {systems['ram_total_gb']} GiB; disponível: {systems['ram_available_gb']} GiB. Inclui outros programas.
- Processo da API na última leitura: {systems['process_ram_mb']} MiB de RAM. Disco livre: {systems['disk_free_gb']} GiB.
- Embeddings: CPU, 4 threads, 768 dimensões, descarregados após cada lote. Memória textual/semântica funciona offline com os modelos presentes.

## Funcionalidades disponíveis

Chat em streaming, histórico persistente, seleção de modelos, seis modos, nove especialidades no mesmo motor, projetos independentes, indexação incremental, FTS5 e embeddings locais, preferências/decisões, resumo progressivo, upload textual, exportação/exclusão, diffs e aprovações, terminal autorizado, pesquisa pública com fontes, browser separado, screenshots, links/tabelas e monitor de recursos. Continue 2.0.0 está instalado e configurado no perfil isolado NEXUS.

## Limites e pendências

O modelo 4B pode errar. O problema 2+4+7 retornou 10 sem raciocínio e 13 com raciocínio; a falha está preservada. O raciocínio foi ativado por padrão, podendo ser desligado no painel. Não se promete excelência universal em programação nem contexto infinito.

Tor permanece desativado, sem instalação oficial validada; teste I não executado. Não foi feita interação manual dentro da janela do VS Code. SearXNG não foi instalado; pesquisa usa alternativas públicas nativas. Não há teste prolongado de estabilidade, integração de PDF/OCR, processamento de imagem ou início automático no login. Projetos fora de `workspaces` devem ser copiados/autorizados dentro dela. Comandos aprovados rodam com permissões do usuário; isso não é sandbox de SO. Continue tem ferramentas/permissões próprias e não herda a memória do painel.

Leia `README.md` para operação, manutenção, instalação em outra máquina e fontes técnicas. Relatórios: `reports/integracao.json`, `reports/agente.json`, `reports/ui.json`, `reports/raciocinio.json`, `reports/estabilidade.json`, `reports/diagnostico.json`, `reports/instalacao.log` e `reports/entrega.json`.
"""
    (ROOT / "ENTREGA.md").write_text(content, encoding="utf-8")
    print(json.dumps({"url": summary["url"], "tests": tests_line, "integration": summary["integration"], "agent": summary["agent"], "system": systems, "thinking": final_status["settings"]["thinking"]}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
