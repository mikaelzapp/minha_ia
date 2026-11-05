# NEXUS AI

## Instalar e atualizar no Windows

Baixe este repositorio inteiro e execute **instalar.bat**. Ele prepara Python, Git, Ollama, dependencias, Chromium, modelos e a integracao com VS Code. Depois, abra **Iniciar NEXUS.cmd**. Para manutencao, execute **atualizar.bat**, que faz backup local antes de atualizar.

```powershell
git clone https://github.com/mikaelzapp/minha_ia.git
cd minha_ia
.\instalar.bat
# Nas proximas atualizacoes:
.\atualizar.bat
```

Consulte o [guia de instalacao e atualizacao](docs/INSTALACAO_WINDOWS.md) para o perfil basico, previa sem alteracoes, recursos opcionais e uso com ZIP. O perfil completo baixa varios GB. Modelos e programas sao baixados das suas fontes; nao ficam neste repositorio.

`data/`, `reports/`, `workspaces/`, ambientes virtuais e credenciais ficam apenas no computador. Os links para `reports/` e `ENTREGA.md`, assim como as medicoes abaixo, descrevem evidencias da instalacao original, geradas localmente; esses relatorios nao acompanham o GitHub. A disponibilidade de cada integracao deve ser verificada no computador onde voce instalar.

Assistente de programação e pesquisa executado neste Windows, com Ollama nativo, interface local em português, ferramentas controladas e memória SQLite. Não usa API paga para inferência. A pesquisa envia palavras-chave públicas aos provedores; páginas externas são dados não confiáveis.

**Comece pelo [Guia de uso do NEXUS AI](docs/GUIA_DE_USO.md)** para aprender a iniciar e fechar, adicionar modelos, usar o VS Code, trabalhar em projetos, fazer backup e resolver problemas comuns.

**Central multimodal:** [guia dos modos, AI Library e Agent Library](docs/CENTRAL_MULTIMODAL.md). Agora é possível instalar/importar modelos, criar variantes e especialistas pela interface, pesquisar com múltiplas consultas e reverter escritas aprovadas. [Entrega e validação](reports/MULTIMODAL_ENTREGA.md).

**Security Center 2.0:** [guia dos dez módulos e da correção supervisionada](docs/SECURITY_CENTER_2.md), [API](docs/SECURITY2_API.md) e [entrega, testes e limitações](reports/SECURITY2_ENTREGA.md). Inclui laboratório SQLi/AUTH, tarefas canceláveis, diffs e revalidação em cópia/branch; integrações externas têm disponibilidade e evidências próprias.

**Motores de segurança instalados:** Nuclei 3.11.1, ZAP 2.17.0, Ghidra 12.2 e OpenJDK 25.0.5+8 estão em pastas portáteis do NEXUS, com downloads verificados e configuração aprovada. A [entrega de instalação e validação nativa](reports/SECURITY_RUNTIME_ENTREGA.md) distingue integridade, configuração e execução; ZAP/Ghidra aguardam RAM suficiente para o ensaio nativo. O Java global foi preservado.

**Security Center:** [guia e capacidades reais](docs/SECURITY_CENTER.md). Seis agentes, escopos, YARA-X, REA MCP, consultas Windows, dorks e relatórios locais. [Compatibilidade](docs/SECURITY_COMPATIBILITY.md) e [entrega/testes](reports/SECURITY_ENTREGA.md) distinguem integrações funcionais das partes pendentes.

**Perfis locais:** [NEXUS UNRESTRICTED — LOCAL](docs/PERFIS_LOCAIS.md) preserva a resposta original do modelo, separando comportamento de conversa das permissões do PC. Consulte a [auditoria](docs/AUDITORIA_DE_CONTEUDO.md) e a [comparação dos modelos instalados](reports/comparacao-perfis-modelos.md).

**Respostas e qualidade:** veja [as melhorias de contexto, respostas diretas e recuperação](docs/RESPOSTAS_E_QUALIDADE.md). O guia explica o comportamento do modelo e os controles de execução no PC.

**Atualização:** consulte [Programação, qualidade e acesso ao PC](docs/PROGRAMACAO_E_ACESSO_PC.md) para usar o Qwen2.5-Coder 7B como consultor, a revisão Cuidadoso, pastas autorizadas e instalações por WinGet com aprovação. As medições e resultados abaixo descrevem a instalação inicial; os relatórios da atualização estão indicados no novo guia.

## Abrir agora

Abra **Iniciar NEXUS.cmd** nesta pasta. A interface fica em **http://127.0.0.1:8765**. Para encerrar, abra **Parar NEXUS.cmd**. Também é possível usar PowerShell:

```powershell
cd C:\caminho\minha_ia
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\iniciar.ps1 -Abrir
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\parar.ps1
```

`RemoteSigned` vale somente para o processo iniciado, permitindo os scripts locais deste projeto. A política global do Windows não é modificada. O servidor roda oculto em segundo plano e escuta somente em loopback. Os dados sobrevivem ao fechamento da interface e ao reinício do computador. A inicialização após login continua manual; não foi criada tarefa global do Windows.

## Configuração deste computador

| Componente | Medição real inicial |
| --- | --- |
| Sistema | Windows 11, build 26200 |
| CPU | AMD Ryzen 7 7735HS, 16 processadores lógicos |
| RAM utilizável | 15,31 GiB; aproximadamente 95% já em uso no diagnóstico |
| GPU | NVIDIA RTX 4050 Laptop, 6.141 MiB |
| Driver NVIDIA | 610.62; aceleração CUDA disponível |
| Armazenamento livre inicial | aproximadamente 53,6 GiB |
| Ollama | 0.40.6 nativo, já instalado em 127.0.0.1:11434 |
| Modelo principal | `qwen3.5:4b-q4_K_M`, 3,4 GB, já existente |
| Embeddings | `embeddinggemma`, 622 MB baixados com autorização |
| Contexto / concorrência | 4.096 tokens / uma geração por vez |
| Portas preservadas | 5432 e 8080 já ocupadas por outros serviços |

O 4B foi escolhido porque cabe inteiramente na GPU e demonstrou chamadas de ferramentas reais. O raciocínio aprofundado está ativado e pode ser desligado em Configurações para reduzir latência. O 9B existente não foi removido nem carregado: seus pesos de aproximadamente 6,6 GB excedem a VRAM. Embeddings usam CPU, quatro threads, lotes pequenos e descarregamento imediato. O Ollama preexistente foi reutilizado sem reiniciar ou alterar suas configurações globais.

No teste inicial sem raciocínio aprofundado, o modelo ocupou aproximadamente **3,7 GB de VRAM**, gerou **52–55 tokens/s** depois de carregado e respondeu em aproximadamente **0,8–2 segundos** nas perguntas curtas com o modelo aquecido. A primeira carga levou aproximadamente **91 segundos** até a resposta. RAM total do sistema oscilou entre 14 e 15 GB, incluindo os demais aplicativos. Com raciocínio ativo, o problema de validação levou **7,8 segundos**, a 54,6 tokens/s incluindo tokens internos. Esses números são medições curtas, não garantia de desempenho. Fechar aplicativos que você não precisa tende a reduzir a paginação. Consulte os relatórios para os valores e horários de cada execução.

O teste encontrou um erro lógico real: sem raciocínio, o modelo respondeu `10` para um problema cuja resposta é `13`. O mesmo problema com raciocínio ativo retornou `13`. Ambos os resultados estão preservados em `reports/estabilidade.json` e `reports/raciocinio.json`. Seis solicitações sequenciais completaram sem falha técnica; isso não garante correção geral nem estabilidade por horas. Valide cálculos e código com ferramentas e testes.

## Conversar e trabalhar em projetos

1. Use **CHAT** para conversar. Escolha modelo e agente nos seletores.
2. Coloque ou copie um projeto autorizado em `workspaces\nome-do-projeto`. A aplicação não alcança automaticamente outras pastas pessoais.
3. Em **Projetos**, registre o nome e o caminho dessa pasta e clique em **Indexar**. A indexação seguinte verifica mudanças incrementalmente.
4. Selecione o projeto na conversa. Use **PLAN** para estudar, **REVIEW** para revisar, **CODE** para editar, **AGENT** para ciclos de execução ou **RESEARCH** para pesquisar fontes.
5. Revise o diff e aceite ou recuse as solicitações da ferramenta. A aprovação expira após cinco minutos e vale só para aquela operação. Alterações concorrentes de arquivo invalidam o diff aprovado.

Os quinze especialistas compartilham o mesmo modelo: nove gerais e seis do Security Center. O seletor Automático escolhe uma especialidade de acordo com a mensagem e o modo. O roteamento usa instruções e ferramentas, sem carregar quinze modelos.

| Modo | Ferramentas |
| --- | --- |
| CHAT | Resposta e recuperação local de memória; sem ferramentas de alteração |
| PLAN | Listagem, leitura e busca de arquivos |
| REVIEW | Inspeção de código sem escrita |
| CODE | Leitura, proposta de escrita e terminal aprovado |
| AGENT | Ciclos de leitura, implementação, execução e navegação dentro da política |
| RESEARCH | Pesquisa e leitura pública; Tor aparece somente quando ativado |

Cada especialista recebe um subconjunto de ferramentas para manter a janela de contexto viável. O agente Browser oferece navegação/interação; Researcher oferece pesquisa e fontes. Operações são limitadas a oito rodadas por etapa, quatro chamadas por rodada e uma geração por vez para controlar recursos e loops. Você pode continuar a conversa sem limite artificial de quantidade de mensagens.

O terminal exige confirmação porque um programa arbitrário pode acessar recursos com as permissões do seu usuário. **Shell desativado e pasta de trabalho restrita não equivalem a sandbox de sistema operacional.** Não aprove comandos desconhecidos. A aplicação bloqueia comandos administrativos e destrutivos óbvios; a aprovação continua sendo uma fronteira humana necessária.

## Memória e arquivos

SQLite armazena conversas completas, preferências, decisões, resumos e documentos. Busca híbrida combina FTS5 e vetores locais de 768 dimensões. Quando embeddings falham ou estão indisponíveis, há fallback textual explícito. O índice registra o modelo dos vetores, evitando combinar embeddings incompatíveis.

Conversas longas são resumidas progressivamente e apenas trechos relevantes entram na janela do modelo. O histórico original permanece no banco. Isso não oferece contexto infinito nem garante recuperar todos os detalhes de uma conversa antiga.

A indexação tem limites técnicos por operação: 1.200 arquivos, 512 KiB por arquivo, 32 MiB de texto e 16 mil chunks. `.git`, dependências, `.env`, chaves, credenciais, links, junctions e hardlinks são ignorados. Padrões conhecidos de segredos são redigidos antes da persistência; a detecção não é perfeita. Autorize apenas conteúdo apropriado.

O upload da conversa é textual, até 20 mil caracteres por arquivo; PDF, OCR e imagem não são interpretados nesse fluxo. O Security Center tem upload binário separado de até 10 MiB para análise estática, sem executar o arquivo. A interface permite adicionar, procurar, excluir e exportar memórias e excluir conversas. Não há envio do índice ou do conteúdo dos projetos a serviços de inferência externos.

## Pesquisa e navegador

A pesquisa usa DuckDuckGo HTML/Lite e Bing RSS sem chave comercial e pode usar SearXNG local configurado em `.env` / `data/config.json`. Se um provedor bloquear, a ferramenta tenta alternativa ou informa o erro. Se a consulta contém uma URL explícita de documentação, pode verificar diretamente essa URL, com o provedor identificado como `direct/url-verification`; isso não é apresentado como resultado de um buscador. Datas de publicação só aparecem quando a fonte fornece; datas não são inventadas. Sempre confira as URLs.

Playwright reutiliza o Chromium já instalado, com um perfil próprio descartável em `data/browser`. Não copia cookies, senhas ou sessões do navegador pessoal. Requisições passam por transporte com validação de IP público, bloqueio de rede interna, proteção a DNS rebinding, limite de bytes e timeout. Só o domínio da página é permitido; dependências externas de alguns sites serão bloqueadas. WebSockets, service workers e downloads automáticos ficam bloqueados. Interações e downloads solicitam aprovação. Não há alegação de isolamento contra falhas do próprio Chromium.

Screenshots ficam em `data/screenshots`. O agente pode gravar texto, JSON, CSV e Markdown no workspace pela ferramenta de escrita. Downloads têm limite de 2 MB e não substituem arquivos existentes.

SearXNG não foi instalado porque Docker/WSL não estavam acessíveis no ambiente de execução, e a alternativa nativa evita acrescentar serviços ao notebook. Nenhum container ou banco existente foi modificado.

## NEXUS TOR RESEARCH — opcional

Na instalação inicial, o módulo estava desativado e Tor não foi encontrado nem instalado. A configuração atual preserva a opção ativada pelo usuário; isso não comprova que o proxy esteja instalado ou conectado. O teste I só roda com ativação e URL autorizada. Instale Tor somente por fonte oficial e confira a procedência do executável. Com o serviço oficial funcionando em loopback, configure, por exemplo, `socks5h://127.0.0.1:9050` em `data/config.json`, ative pelo painel e confira `tor_check`.

O cliente verifica `check.torproject.org` pelo proxy antes de consultar onion v3, valida versão e checksum do endereço, usa DNS remoto por SOCKS5H e nunca recorre à conexão direta. Só esse módulo usa o proxy. Não há execução de arquivos, exploração ou importação de perfis pessoais. Não se promete anonimato absoluto. Uma verificação de rede Tor não certifica a origem do binário do proxy: essa verificação permanece necessária na instalação opcional.

Teste manual após ativação, com URL de teste legítima escolhida por você:

```powershell
.\.venv\Scripts\python.exe -m nexus.benchmark --tor --tor-test-url "http://ENDERECO_V3_AUTORIZADO.onion"
```

## VS Code

Continue 2.0.0 foi instalado em **perfil separado dentro de `data`**. A configuração YAML usa Ollama local e o mesmo Qwen 4B. Suas extensões, configurações e `.continue` originais são preservadas.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\vscode.ps1
# ou um projeto específico:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\vscode.ps1 -Projeto "workspaces\exemplo-calculadora"
```

Abra Continue na barra lateral ou com `Ctrl+L`, selecione **NEXUS Local / NEXUS Qwen 3.5 4B** e use chat, edição ou Agent. Revise diffs e permissões do próprio Continue. A extensão possui ferramentas e histórico próprios; o controle de aprovação e a memória do painel web não são herdados automaticamente pelo Continue. Evite usar os dois geradores ao mesmo tempo: a fila do aplicativo protege suas chamadas, mas não controla outros clientes diretos do Ollama. Autocomplete e indexação automática do perfil IDE ficam desligados para poupar memória; não é necessário login pago para o modelo local.

Instalação da extensão e configuração foram verificadas. O modelo e suas chamadas de ferramenta foram testados na API e no painel; a interação completa dentro da janela do VS Code ainda exige validação manual pelo usuário.

## Scripts, manutenção e reprodução

| Arquivo | Uso |
| --- | --- |
| `instalar.bat` | Prepara programas ausentes, ambiente, navegador, modelos e VS Code; `-Basico` reduz a instalacao |
| `atualizar.bat` | Faz backup, atualiza codigo em clones Git, pacotes e modelos; `-Verificar` mostra o plano |
| `instalar.ps1` | Reutiliza Python/Ollama, cria `.venv`, instala lock de dependências, configura persistência e executa testes |
| `iniciar.ps1` | Inicia em localhost; `-Porta 8766` evita conflito; `-Abrir` abre o navegador |
| `parar.ps1` | Para somente o PID identificado como servidor NEXUS; preserva Ollama preexistente |
| `diagnosticar.ps1` | Inventário somente leitura e relatório em `reports/diagnostico.json` |
| `atualizar.ps1` | Para NEXUS e faz backup SQLite; `-AtualizarDependencias` atualiza pacotes, `-AtualizarCodigo` recebe main por Git |
| `desinstalar.ps1` | Para NEXUS; remoção de ambiente ou dados exige switches explícitos e confirmação |
| `scripts/configurar-vscode.ps1` | Instala Continue no perfil isolado |
| `vscode.ps1` | Abre o perfil NEXUS no VS Code |

O caminho recomendado em outra maquina e `instalar.bat`, que instala programas ausentes pelo WinGet. Para usar diretamente `instalar.ps1`, Python x64 3.11+ e Ollama devem estar disponiveis previamente. Nessa interface manual, os downloads de modelos exigem as opcoes abaixo:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\instalar.ps1
# Autoriza 3,4 GB do modelo e 622 MB de embeddings, se ainda faltarem:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\instalar.ps1 -BaixarModelo -BaixarEmbeddings -InstalarContinue
```

Nenhum navegador novo foi baixado nesta instalação. Em outro computador sem Chromium/Edge compatível, informe-se do tamanho e instale apenas o navegador necessário no projeto:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $PWD '.browsers'
.\.venv\Scripts\python.exe -m playwright install chromium
```

O `atualizar.bat` atualiza os pacotes dentro das faixas de `requirements.txt`, executa testes e registra as versoes validadas em `.runtime/requirements-installed.txt`, sem modificar o lock versionado. Tambem sincroniza os modelos configurados, exceto com `-SemModelos`. A interface manual `atualizar.ps1` so atualiza pacotes com `-AtualizarDependencias` e nao baixa modelos. Um Ollama existente nao e reiniciado para mudar limites de memoria.

Logs: `.runtime/server.err.log` e `.runtime/server.out.log`. Configuração: `data/config.json` (prioridade sobre `.env`). Bancos: `data/memory.sqlite3`, `data/activity.sqlite3`. O token local fica em `data/auth.secret`; não compartilhe esse arquivo. A página local cria cookie HttpOnly/SameSite Strict e a API valida token, Host e Origin. É um aplicativo de usuário local, sem isolamento entre contas do Windows nem autenticação multiusuário. Não exponha a API por proxy ou túnel.

## Verificação

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe -m nexus.benchmark --quick
.\.venv\Scripts\python.exe -m nexus.benchmark --base-url http://127.0.0.1:8765
.\.venv\Scripts\python.exe scripts\agent_check.py
.\.venv\Scripts\python.exe scripts\ui_check.py
```

O benchmark pode comparar modelos **já instalados** com `--model MODELO_A --model MODELO_B`. Não baixa modelos e não carrega 9B por conta própria. Os testes A–J verificam geração, programa Python e correção de erro deliberado, repositório, fontes públicas, browser, memória em nova sessão, interface, tool calls e recursos. O teste Tor só roda mediante ativação e URL autorizada. Testes unitários usam mocks onde indicado; os relatórios de integração registram chamadas reais separadamente.

Resultados detalhados: `reports/diagnostico.json`, `reports/benchmark-quick.json`, `reports/integracao.json`, `reports/agente.json` e `reports/ui.json`. Uma falha fica registrada como falha; não é convertida em resultado positivo por haver mock equivalente. Consulte `ENTREGA.md` para o estado final desta instalação.

## Arquitetura e fontes técnicas

FastAPI/uvicorn serve interface vanilla offline; `engine.py` trata o Ollama; `app.py` orquestra agentes, contexto e aprovações; `tools.py` aplica políticas de arquivo/rede/browser; `memory.py` cuida de SQLite/FTS5/vetores. Uma única inferência compartilhada evita carregar nove modelos. Não há PostgreSQL ou Open WebUI adicional: a interface própria integra diff/aprovação/estado de tarefa em um processo pequeno.

- [Ollama no Windows](https://docs.ollama.com/windows)
- [Qwen3.5 4B](https://ollama.com/library/qwen3.5:4b) e [contexto](https://docs.ollama.com/context-length)
- [Tool calling Ollama](https://docs.ollama.com/capabilities/tool-calling)
- [EmbeddingGemma](https://ollama.com/library/embeddinggemma) e [API de embeddings](https://docs.ollama.com/api/embed)
- [Continue / Ollama](https://docs.continue.dev/customize/model-providers/top-level/ollama) e [YAML](https://docs.continue.dev/reference)
- [Diretório Continue isolado no código oficial](https://github.com/continuedev/continue/blob/main/core/util/paths.ts)
- [Requests SOCKS e DNS remoto](https://requests.readthedocs.io/en/stable/user/advanced/#socks)
