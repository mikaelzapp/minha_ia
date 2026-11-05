# Central multimodal, AI Library e Agent Library

A expansão de **05/11/2026** mantém o NEXUS existente em **http://127.0.0.1:8765**. Para abrir, execute **Iniciar NEXUS.cmd**. Para encerrar o servidor, execute **Parar NEXUS.cmd**; fechar a aba deixa o servidor ativo. Projetos, memórias, perfis, modelos e integração VS Code anteriores foram preservados.

Nesta expansão, os modos são modalidades de trabalho: pesquisa, Tor, pentest, desenvolvimento e defesa. O inventário informa capacidades de imagem declaradas pelos modelos; isso não acrescenta geração de imagem, áudio, vídeo ou envio multimodal de imagens ao chat textual existente.

## Modo → agente → modelo → ferramentas

O seletor principal muda a modalidade, o especialista recomendado, o modo operacional e o painel contextual. O seletor de modelo permanece independente. Se faltar uma capacidade obrigatória declarada, o painel mostra a razão e oferece modelos já instalados compatíveis; nenhum modelo é baixado por trocar de modo.

| Modalidade principal | Especialista inicial / operação | Como usar |
| --- | --- | --- |
| **Chat** | Automático / CHAT | Conversar. O controle operacional existente pode ser alterado manualmente; CHAT não tem ferramentas. |
| **Search Normal** | Researcher / RESEARCH | Pedir pesquisa com duas ou três consultas, abrir documentação, extrair texto/tabelas e citar as fontes retornadas. |
| **Search Deep Web / Tor** | Researcher / RESEARCH | Ativar explicitamente, verificar proxy e ler uma URL pública/onion legítima. Toda navegação deste modo usa Tor. |
| **Hacking / Pentest** | Red Team / AGENT | Cadastrar alvos em Escopos, propor verificações e aprovar cada operação. |
| **Developer** | Coder / CODE | Selecionar projeto, ler arquivos, propor diffs, aprovar escrita/comandos, executar testes e consultar histórico/reversão. |
| **Security / Antivirus** | Blue Team / REVIEW | Consultar Windows/Defender ou analisar arquivo inofensivo/suspeito estaticamente pelo Security Center. |

Os controles **CHAT, PLAN, CODE, AGENT, REVIEW, RESEARCH** continuam existindo e determinam a classe de operação. A modalidade e o agente só podem reduzir as ferramentas permitidas pelo executor. Escolher Pentest não autoriza um domínio, Developer não autoriza qualquer pasta e Tor não inicia uma conexão automaticamente.

O monitor mostra conexão Ollama, modelo, agente, modalidade, GPU/RAM, Tor e ferramentas previstas. O inventário do Security Center detalha quais motores estão realmente disponíveis. “Tools/vision” no modelo significa declaração do Ollama, não garantia de qualidade ou de instalação de todos os programas.

## Search Normal e relatórios

Peça, por exemplo: “Pesquise a documentação oficial de pathlib e da API Ollama, usando duas consultas, e compare as fontes.” A ferramenta `search_many` faz até três consultas sequenciais, identifica o provedor e preserva erros. Reutiliza DuckDuckGo/Bing e SearXNG quando configurado; Playwright e extração HTML existentes continuam disponíveis.

URLs e datas são obtidas das fontes. A data de consulta não é inventada como data de publicação. A resposta mostra um selo indicando se houve pesquisa bem-sucedida ou apenas resposta sem busca nesta etapa. Uma afirmação textual do modelo de que pesquisou não ativa esse selo.

Abra **Relatórios** ou **Sessões e fontes** no painel contextual para consultar pesquisas e baixar JSON/Markdown. A seleção de projeto filtra os relatórios de pesquisa. Falha do provedor é apresentada como falha, sem criar resultados artificiais. Nenhum CAPTCHA é contornado.

## Tor: ativação e limites reais

Deep web inclui páginas não indexadas e áreas autenticadas; serviços onion são uma categoria distinta. Este modo não recupera contas, não ultrapassa autenticação e não garante encontrar índices onion.

1. Selecione **Search Deep Web / Tor**.
2. Confira **Consultar configuração local**. Porta acessível, sozinha, não comprova saída Tor.
3. Use **Ativar Tor explicitamente** se estiver desativado. O padrão para instalação nova é desativado; a preferência previamente salva nesta máquina foi preservada.
4. Com um Tor oficial funcionando no proxy configurado, use **Verificar saída Tor**. Só então solicite leitura pública/onion.
5. Use **Desativar Tor** para retirar a permissão do módulo.

O proxy configurado nesta instalação é `socks5h://127.0.0.1:9050`. **A validação real não encontrou esse proxy acessível.** O botão de verificação retornou falha técnica e não tentou conexão direta. Nenhum serviço Tor foi instalado ou iniciado silenciosamente, nenhuma página onion foi acessada e a navegação Tor real continua dependente de um proxy funcional.

`tor_read` aceita HTTP/HTTPS público e onion v3 validado; `tor_search` consulta um buscador público pelo proxy, sem se apresentar como índice onion garantido. O navegador Tor tem perfil descartável próprio, sem cookies pessoais, downloads, WebSocket ou service workers. As requisições renderizadas são atendidas pelo transporte SOCKS5H; uma conexão direta bloqueada impede fallback do Chromium. O código/transporte foi testado com fixtures, mas a navegação numa saída Tor real não foi validada neste notebook. Não há promessa de anonimato absoluto.

Conteúdo de páginas é dado não confiável, sem autoridade para comandar o agente. Não use este fluxo para baixar ou executar amostras suspeitas.

## Pentest e Security

As modalidades reutilizam o [Security Center](SECURITY_CENTER.md), com escopos domínio/IP/CIDR, projetos registrados, dorks, HTTP/TLS/TCP, consulta CVE, Nmap opcional, YARA-X, REA e Windows.

Cadastre somente alvos pelos quais você é responsável ou tem autorização. Operações de rede mostram alvo, escopo, portas/consulta e impacto antes da aprovação. Revogação de escopo impede operações pendentes; o modelo não possui ferramenta para aprovar ou ampliar o escopo.

Security analisa bytes e consulta o Windows, sem executar a amostra ou substituir o antivírus. Defender/firewall/UAC permanecem ativos. A análise dinâmica em VM, Ghidra profundo, capa/FLOSS, ZAP/Nuclei/Semgrep/Trivy e VirusTotal continuam com as limitações documentadas na [matriz de compatibilidade](SECURITY_COMPATIBILITY.md). Instalar uma ferramenta não cria automaticamente um adaptador validado.

## Developer, testes e reversão

Selecione o projeto e peça leitura antes da mudança: “Leia o arquivo, proponha a correção, mostre o diff e rode os testes após a aprovação necessária.” Terminal, Git, Python, Node e Docker dependem de instalação e permissões existentes. O NEXUS não afirma ter alterado arquivos sem resultado real da ferramenta.

Em **Histórico e reversão de arquivos**, escolha uma escrita aplicada e examine o diff reverso. A reversão tem aprovação individual, validade de cinco minutos e nova conferência de hash/grant. Se outra edição mudou o arquivo, a restauração é interrompida. Desfazer uma criação pode remover apenas o arquivo correspondente aprovado. Os diretórios permanecem.

O histórico cobre `write_file`/`pc_write_file`; comandos, Git, testes, instaladores e bancos podem causar alterações que não são desfeitas automaticamente. Use Git e backups para essas operações. Snapshots originais ficam privados em SQLite; a interface apresenta metadados e diff com credenciais reconhecíveis redigidas. Veja [contrato e limites](DEVELOPER_HISTORY.md).

O terminal continua sem sandbox de sistema operacional. A aprovação de um comando permite efeitos com os privilégios da sua conta; confira o comando. O NEXUS não executa arquivos suspeitos por serem selecionados no modo Developer.

VS Code/Continue permanecem no perfil isolado existente: abra **vscode.ps1**. Selecionar um novo padrão no painel web não modifica silenciosamente o YAML do Continue. Para usar outro modelo na IDE, siga o [guia geral](GUIA_DE_USO.md) e altere a configuração desse perfil separadamente.

## AI Library: modelos instalados

Abra **AI Library**. O inventário consulta `/api/tags`, `/api/show` e `/api/ps` do Ollama local e mostra nome/tag, tamanho, quantização, contexto conhecido, capacidades declaradas, suporte a tools/imagens e residência. Dados ausentes ficam como não informados.

Cada modelo tem ações para selecionar no chat, definir padrão, testar carregamento, descarregar e remover. O padrão exige capacidade local de conversação. Descarregar libera a residência sem apagar pesos. Remover exige digitar o nome completo com tag; modelos usados como principal, consultor ou embedding nas configurações são protegidos até mudar essas referências.

Não se sobrescrevem tags instaladas ao adicionar/criar/importar: use outro nome. A biblioteca diferencia pesos no disco de memória usada no momento; variantes podem compartilhar blobs e o tamanho das tags não mede armazenamento exclusivo.

| Modelo preservado | Tamanho aproximado da tag | Uso |
| --- | --- | --- |
| `qwen3.5:4b-q4_K_M` | 3,4 GB | Principal recomendado para ferramentas nesta máquina. |
| `qwen2.5-coder:7b` | 4,7 GB | Consultor de código; chamada nativa falhou no ensaio anterior, apesar da capacidade declarada. |
| `huihui_ai/qwen3.5-abliterated:9b-q4_K` | 6,6 GB | Experimental; excede a VRAM e não teve comparativo de qualidade concluído. |
| `qwen35-zode-4b:latest` | 3,4 GB | Variante local existente. Nome/instruções diferentes não demonstram pesos mais inteligentes. |
| `embeddinggemma:latest` | 622 MB | Embeddings da memória; não é modelo de conversa. |

Essas são as cinco tags originais ao final. O SmolLM2 e suas variantes foram temporários e removidos após os testes autorizados. [Comparação, licenças e limitações dos modelos](SECURITY_MODELS.md).

## Instalar pela interface

1. Abra **AI Library → Adicionar** e informe um nome/tag da biblioteca Ollama, por exemplo `qwen3:4b`. O exemplo não inicia download por si só.
2. Peça a prévia. Ela consulta informações disponíveis, tamanho conhecido do manifesto, RAM/VRAM/disco e processos com maior RSS, sem encerrar programas.
3. Confira tamanho, origem e avisos. Total desconhecido permanece desconhecido; a tela não inventa percentual.
4. Aprove a operação concreta. A aprovação expira em cinco minutos e não pode trocar argumentos.
5. Acompanhe a fila e os bytes/eventos reais. O percentual é do evento/blob atual, não uma previsão global.
6. Use **Cancelar** quando necessário e atualize o inventário depois.
7. Após conclusão, teste carregamento com margem de RAM e selecione o modelo em um modo compatível.

Cancelar fecha a conexão do NEXUS; outro cliente Ollama pode manter um download compartilhado. Parciais podem ficar em cache e uma operação já concluída no Ollama não é desfeita automaticamente. Reiniciar o NEXUS marca operações interrompidas e não retoma downloads sozinho.

As operações usam a fila do chat/Security Center. O teste curto não carrega outro modelo enquanto houver um residente diferente. Pesos grandes/contextos altos geram avisos e checagens preventivas; 9B pode depender de RAM/CPU. O painel não promete calcular exatamente toda a memória de KV cache. Outros clientes do Ollama, como Continue, não são controlados por essa fila.

## Importar GGUF e referência Hugging Face

Em **Importar GGUF**, selecione explicitamente o arquivo, informe SHA-256 esperado quando tiver uma referência confiável, envie os bytes e escolha nome local, sistema, contexto e temperatura. Confira a prévia equivalente de Modelfile e aprove a criação. Depois execute o teste curto; validar cabeçalho não comprova que todos os pesos carregam corretamente.

O assistente aceita GGUF little-endian v2/v3 completo de até 16 GiB, com arquitetura/tabela de tensores permitidas. Arquivos divididos, formatos diferentes e arquiteturas desconhecidas são rejeitados com motivo técnico. Importação pode precisar de cópia no projeto e no Ollama; há reserva de armazenamento. Excluir uma cópia de upload não remove o modelo já importado.

Em **Hugging Face**, informe `autor/repositório`, arquivo `.gguf` explícito, revisão e nome local. A prévia resolve commit fixo, identifica publicador, licença quando fornecida, tamanho e hash LFS conhecido. O download fica preso ao commit aprovado e confere hash quando disponível. Nenhum script, dependência do repositório ou código remoto é executado. Identificar o publicador não certifica sua confiabilidade.

A prévia HF real foi validada com metadados públicos e recusada sem download adicional. A transferência completa HF foi testada com transporte isolado; não foi feito outro download de pesos HF nesta entrega. A importação de um GGUF real foi validada usando o modelo de teste autorizado.

## Criar variante personalizada

Em **Variantes**, escolha uma base instalada, dê nome novo, escreva o sistema e ajuste contexto/temperatura. Confira o Modelfile equivalente, aprove e teste. Os parâmetros são enviados estruturados ao Ollama; o texto do prompt não vira comandos adicionais.

**Variante não é treinamento/fine-tuning e não cria pesos mais inteligentes.** As instruções do agente e as regras do executor continuam independentes do prompt incorporado no modelo. Uma variante não recebe permissões extras sobre o computador.

## Agent Library: criar especialistas

AI Library administra modelos; **Agent Library** administra instruções e ferramentas. O mesmo 4B pode servir aos quinze especialistas internos e aos personalizados, sem quinze modelos residentes.

Em **Criar agente**, configure nome, descrição, ícone textual, modalidade associada, prompt, modelo padrão opcional, ferramentas, memória, permissões e pesquisa. Você pode duplicar um interno, editar personalizados e exportar/importar JSON. Internos são somente leitura. Importar/duplicar cria novo ID, sem substituir outro agente.

As permissões do agente somente reduzem ferramentas. Marcar terminal, rede ou arquivo não concede pastas do PC, escopos de auditoria, ativação global de Tor, aprovação de comandos ou instalação de modelos. Permissões removidas ou agente excluído durante uma aprovação pendente cancelam a execução antiga. Configurações conflitantes são recusadas antes da execução, sem scripts em JSON.

Memória:

- **Leitura desativada:** o LLM recebe apenas o turno atual, sem recuperar histórico/resumo/memórias anteriores.
- **Escrita desativada:** não cria resumos derivados nem memórias automáticas. O histórico/auditoria da conversa continua persistido.
- **Conversa:** limita recuperação ao contexto da própria conversa.
- **Projeto:** usa o projeto atual e memórias globais explicitamente salvas, sem recuperar outro projeto.

Busca pode herdar o provedor, usar DuckDuckGo ou exigir SearXNG configurado. A opção Tor do agente também depende da ativação global. Detalhes: [API da Agent Library](AGENT_LIBRARY_API.md).

## Histórico e privacidade

Conversas registram projeto, modalidade, agente, modelo e data. A lista possui filtros; eles usam os metadados mais recentes da conversa. Cada nova resposta guarda sua própria origem, inclusive modelos consultados/revisor, quando usados. Mensagens antigas sem essa informação não recebem autoria inventada. O nome do agente é preservado no snapshot mesmo se ele for excluído depois.

Você pode trocar de modelo na mesma conversa. Trocar de projeto abre uma conversa nova para não misturar o histórico privado; a API também impede associar uma conversa de um projeto a outro. A recuperação automática sem projeto usa somente memórias globais. A busca humana global na área Memória continua explícita e independente.

PADRÃO e UNRESTRICTED permanecem disponíveis, sem perda de memória. A expansão não adiciona filtro de assuntos ou lista de palavras proibidas. Conteúdo, capacidades, disponibilidade e autorização são controles separados; respostas ainda podem conter erros ou comportamentos aprendidos no modelo.

## Backup e reprodução

Backup anterior às alterações: **`reports/backup-multimodal-20261105-024857`**, 117 arquivos com hashes e cópias SQLite consistentes. Os modelos originais permaneceram nos locais Ollama.

Novos dados: `data/library/agents.sqlite3`, `data/library/jobs.json`, uploads em `data/library/uploads`, `data/developer/history.sqlite3` e `data/research/research.sqlite3`. O SQLite de memória original recebeu tabelas auxiliares de metadados, sem reescrever mensagens antigas.

```powershell
.\.venv\Scripts\python.exe -m nexus.setup --backup reports/backup-dados-multimodal
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\ui_multimodal_check.py
.\.venv\Scripts\python.exe scripts\ui_multimodal_readonly.py
```

O backup de dados inclui os novos bancos e histórico de jobs; **não copia pesos Ollama, uploads GGUF grandes nem todo o código/workspaces**. Para backup completo, feche o servidor e copie o projeto/arquivos autorizados separadamente; guarde pesos/uploads conforme o espaço disponível. Use destino novo. Snapshots Developer contêm fonte original privada para restauração exata; proteja esse banco como protege seus projetos.

O validador `scripts/validar_model_library.py --authorized-test` baixa e remove um modelo temporário de 271 MB: só repita quando quiser autorizar esses efeitos. `scripts/validar_multimodal_chat.py` usa o 4B instalado com margem de RAM, sem downloads. O [relatório de entrega](../reports/MULTIMODAL_ENTREGA.md) distingue testes reais, fixtures e pendências; [contratos de modelos](MODEL_LIBRARY_API.md) explicam limites, códigos e fontes oficiais.
