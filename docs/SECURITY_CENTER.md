# Guia do NEXUS Security Center

**Atualização 2.0:** veja [módulos, tarefas, relatórios e correção supervisionada](SECURITY_CENTER_2.md). Este documento preserva o funcionamento do painel anterior, que continua integrado e acessível.

O Security Center está integrado ao NEXUS existente em **http://127.0.0.1:8765**. Seus seis agentes compartilham o modelo local e ferramentas reais, com operações sequenciais. Esta entrega de **05/11/2026** tem partes funcionais e partes ainda indisponíveis, discriminadas abaixo.

## Abrir, usar e fechar

1. Abra **Iniciar NEXUS.cmd** na pasta do NEXUS. Se a instância já estiver aberta, atualize a página.
2. Clique em **Security Center** no menu lateral. No celular, abra primeiro o menu de navegação.
3. Confira **Visão geral**. A primeira consulta ao REA pode levar alguns segundos; não carrega um LLM.
4. Escolha uma área: **Agentes e ferramentas, Escopos autorizados, Rede e CVEs, OSINT e dorks, Arquivos e investigação, Auditoria de código, Windows ou Relatórios**.
5. As análises pelo painel funcionam sem inferência. Para conversar, selecione modelo/agente em **Agentes e ferramentas** e clique em **Usar agente no chat**. O perfil de conversa continua sendo o escolhido no topo.
6. Fechar o painel volta à conversa. Fechar a aba deixa o servidor funcionando; **Parar NEXUS.cmd** encerra o servidor e preserva dados e Ollama preexistente.

O monitor exibe RAM e GPU/VRAM e atualiza enquanto o painel está aberto. O notebook tem aproximadamente 15,31 GiB de RAM e 6 GiB de VRAM; houve apenas 329 MiB de RAM livre durante o inventário. Recomenda-se **Qwen3.5 4B** para ferramentas e Coder 7B como consultor textual, um por vez. Veja [modelos, licenças e medições](SECURITY_MODELS.md).

## O que funciona

| Módulo | Funcional nesta entrega | Limites e partes pendentes |
| --- | --- | --- |
| RED TEAM | Escopos; HTTP HEAD; TLS; TCP limitado; CVE oficial; adaptador Nmap opcional | Nmap não instalado; ZAP/Nuclei sem adaptadores operacionais. Sem pentest completo ou exploração automática de autenticação. |
| OSINT | Construtor de dorks, prévia/aprovação, pesquisa pública existente, URLs delimitadas ao domínio | Sem download de documentos, entrada em contas ou bypass de CAPTCHA. Provedores podem limitar operadores e resultados. |
| REA | MCP stdio 6.8.0 verificado, inspeção estática PE/ELF/ZIP | Ghidra/Hopper/IDA/Kuna indisponíveis; sem pseudocódigo profundo nem execução do alvo. |
| MALWARE LAB | SHA-256, formato, PE/ELF básicos, strings, entropia, indicadores, YARA-X real | Três regras descritivas, sem feed completo. capa/FLOSS, VM e VirusTotal não integrados. |
| BLUE TEAM | Defender, processos, conexões, inicialização, tarefas e eventos sob demanda, somente leitura | Sem serviço de monitoramento, varredura antivírus iniciada pelo NEXUS, atualização forçada, remoção ou quarentena. |
| CODE AUDITOR | AST Python e verificações limitadas JS/TS/PHP/config/Docker; segredos redigidos; dependências inventariadas | Sem análise completa de fluxo nem correlação automática com CVEs. Semgrep/Trivy não integrados. |

“Localizado” significa descoberta do executável, não integração validada ou assinatura confiável. Hash identifica bytes observados; não certifica toda a distribuição. Detalhes em [compatibilidade/procedência](SECURITY_COMPATIBILITY.md), [rede/OSINT](SECURITY_NETWORK.md) e [análise estática](SECURITY_STATIC.md).

## Autorizar e testar sua rede

Em **Escopos autorizados**, informe nome, ambiente, finalidade, alvos e tipos de teste. Aceita domínio sem URL, IP ou rede CIDR, um por linha. Marque somente testes permitidos e confirme que é responsável pelos alvos ou tem autorização explícita. Subdomínios dependem da opção específica. O modelo não possui ferramenta para criar/ampliar escopos.

Exemplo para seu próprio laboratório: alvo `127.0.0.1`, ambiente “desenvolvimento local”, testes HTTP e TCP. Em **Rede e CVEs**, use a URL do seu servidor, por exemplo `http://127.0.0.1:8000/`. Não declare um domínio de terceiros como próprio para testar um exemplo.

Escolha escopo, alvo, teste e, para TCP/Nmap, portas numéricas separadas por vírgula. **Revisar operação** apresenta alvo, escopo, revisão, portas e impacto. A aprovação vale para uma operação, expira em cinco minutos e é consumida uma vez. Revogar escopo impede novas operações e invalida decisões pendentes; não desfaz conexões já iniciadas.

HTTP lê cabeçalhos com HEAD, sem corpo. TLS valida o certificado. TCP permite até oito portas e não envia protocolo de aplicação. Nmap, quando instalado no local canônico, usa argumentos fixos e não oferece scripts, exploração, evasão ou shell arbitrário. Redirecionamentos não são seguidos. Domínio que resolve para rede privada precisa de concessão explícita do IP/rede privada. Os controles são operacionais, sem classificação temática de perguntas.

A consulta **CVE** usa um identificador como `CVE-2021-44228` em fonte oficial. Consulta um registro público, não um alvo; não precisa declarar um domínio como seu. Um CVE citado não comprova que seu sistema esteja afetado.

## OSINT e dorks

Selecione escopo com OSINT permitido e informe domínio, operadores `intitle`, `inurl`, `intext`, documento, termos, exclusões e até dez resultados. Operadores vazios são omitidos; cada linha de exclusão vira um termo separado.

Clique em **Pré-visualizar consulta**, confira a consulta completa e depois **Revisar pesquisa**. Aprove o envio ao buscador. Editar um campo invalida a prévia. Pelo chat, `security_osint` também exige prévia/aprovação. Revogação antes da aprovação impede a busca.

As palavras da consulta vão ao provedor público; não inclua código privado ou credenciais. O mecanismo existente tenta os provedores configurados e identifica origem/falhas. SearXNG é opcional, conforme o [guia geral](GUIA_DE_USO.md); não foi instalado outro servidor. Resultados fora do domínio são descartados. O módulo não baixa documentos, coleta credenciais ou contorna autenticação/CAPTCHA.

## Investigar arquivos

Em **Arquivos e investigação**, envie explicitamente uma amostra de **1 byte a 10 MiB**. Ela é armazenada como `data/security/samples/<id>.bin`. Nome de apresentação, tamanho e SHA-256 ficam no banco; o nome original não vira caminho de execução. O upload não inicia a amostra nem a envia à internet. O Defender continua ativo e pode agir segundo suas próprias políticas.

Selecione a amostra e escolha:

- **Análise estática local:** hashes, formatos, strings, indicadores e YARA-X.
- **Inspecionar com REA:** MCP estático para formatos suportados.
- **Investigar amostra:** MALWARE LAB seguido de REA, sobre o mesmo arquivo, com evidências compartilhadas num relatório.

O hash é conferido antes da análise; links, junctions, hardlinks e alterações de arquivo são rejeitados. Amostras não são executadas, importadas ou extraídas. Armazenamento inerte e análise estática **não são VM nem sandbox do Windows**: os analisadores processam bytes potencialmente malformados. Não use o terminal de programação para executar uma amostra suspeita no host.

Análise dinâmica continua indisponível: exigiria VM dedicada com snapshots e sem compartilhar pastas, clipboard, credenciais ou dispositivos. VirusTotal não configurado não recebe arquivos ou hashes automaticamente.

YARA-X 1.21.0 foi instalado apenas no `.venv`, com hash do wheel verificado. As três regras descritivas iniciais reconhecem MZ, ELF e referência a shell; não são um feed completo de malware. Correspondência ou ausência de indicador não confirma segurança. Nenhuma base ou amostra é baixada automaticamente.

## Auditar código e corrigir

Cadastre o projeto na área **Projetos** do NEXUS, dentro de `workspaces`. Em **Auditoria de código**, selecione-o e execute a análise. O scanner não importa módulos, executa código nem instala dependências. Achados apresentam gravidade, confiança, arquivo/linha, evidência redigida, impacto e recomendação; permanecem **não confirmados** até validação.

Foi criado/registrado `workspaces/security-center-lab`, com uma função `eval` deliberadamente insegura apenas para inspeção estática. Não implante esse exemplo como sistema real.

Para corrigir, selecione **NEXUS CODE AUDITOR**, modo CODE/AGENT, e peça leitura do arquivo, patch e teste. Escrita e comandos usam o fluxo existente de diff/aprovação; o scanner não altera arquivos sozinho. O terminal opera com as permissões da sua conta, sem sandbox de sistema operacional. Dependências listadas pelo auditor ainda não foram correlacionadas automaticamente com CVEs.

## Consultar o Windows

Em **Windows**, escolha visão geral, Defender, processos, conexões, inicialização, tarefas ou eventos e consulte. As ferramentas usam psutil/scripts literais nativos, sem incorporar expressões fornecidas pelo usuário. Não elevam privilégios nem alteram Defender, firewall, UAC ou serviços.

Defender informa estado/data/idade de assinaturas conhecidos pelo Windows; não é uma varredura do NEXUS. Há limite de 150 itens e 50 eventos dos últimos sete dias. Permissão negada é falha de consulta, não evidência de proteção desativada. Não há monitoramento periódico, remoção ou quarentena nesta entrega.

## Chat, perfis e relatórios

Automático reconhece “audite meu aplicativo”, “investigue este executável”, “verifique o Defender” e “revise o repositório”. As palavras selecionam capacidades, não proíbem assuntos. Instruções são configuráveis em `profiles/agents.json` e `profiles/security_center.md`, separadas do código e dos perfis PADRÃO/UNRESTRICTED. Trocar perfil não remove permissões ou apaga conversas/memória.

CHAT não executa ferramentas; PLAN/REVIEW inspecionam; buscas públicas entram em RESEARCH/CODE/AGENT; sondagens de alvos entram em AGENT. Cada papel recebe um subconjunto de ferramentas. “Investigar amostra” encadeia adaptadores estáticos, não seis LLMs independentes. A fila é compartilhada entre chat e análises; a configuração atual é uma operação por vez. Clientes externos do Ollama não ficam sob essa fila.

Resultados de código, páginas, arquivos e scanners são dados não confiáveis. As instruções impedem usá-los como autorização ou comandos; o executor também verifica escopos, modos e decisões. Isso reduz riscos de prompt injection, sem prometer imunidade. O perfil UNRESTRICTED preserva a resposta do modelo; nenhum filtro temático ou promessa de ausência de recusas foi adicionado.

Em **Relatórios**, veja histórico e exporte JSON/Markdown. Erros também ficam registrados. Cada análise inclui `ok`, `tool`, `code`, `source`, data, achados e evidências específicas. O `report_id` permite recuperar o mesmo resultado pelo agente. Indicadores de bytes podem não ter linha de código. Credenciais reconhecíveis são redigidas; padrões não detectam todo segredo arbitrário.

## Dados, backup e manutenção

O backup anterior às mudanças está em `reports/backup-security-20261105-021125`, com manifesto SHA-256 e SQLite consistente. Modelos Ollama e extensões permaneceram nos locais originais.

Novos dados: **`data/security/security.sqlite3`** e **`data/security/samples`**. Conversas/memória permanecem em `data/memory.sqlite3`; atividades em `data/activity.sqlite3`. Não compartilhe `data/auth.secret`. O aplicativo é pessoal, autenticado em loopback; não o exponha por proxy ou túnel.

Para um novo backup de dados:

```powershell
.\.venv\Scripts\python.exe -m nexus.setup --backup reports/backup-manual-security
```

Inclui SQLite consistente dos três bancos, configurações, perfis, lock e amostras. **Não inclui todo o código ou os projetos.** Para backup completo, feche o servidor e copie também `nexus`, `scripts`, `profiles`, `docs`, `workspaces` e arquivos da raiz; modelos têm estratégia própria. Use destino novo para preservar backups anteriores.

Nenhum modelo foi baixado. Antes de adicionar um motor futuro, confira fonte oficial, licença, hash/assinatura, recursos e contrato do adaptador. Instalar executável não cria automaticamente integração.

## Reproduzir a validação

Execute na pasta do projeto:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
# Cria/retém laboratório e relatórios, revoga os escopos de teste.
.\.venv\Scripts\python.exe scripts\validar_security.py --public-research
# Navegador real com backend interceptado, dados só do harness.
.\.venv\Scripts\python.exe scripts\security_ui_check.py
# Interface real somente GET/HEAD; sem inferência ou alterações.
.\.venv\Scripts\python.exe scripts\security_ui_readonly.py
# Ensaio LLM condicionado à RAM disponível, sem downloads.
.\.venv\Scripts\python.exe scripts\validar_security_model.py
```

O ensaio público envia somente termos técnicos e ID CVE. O de modelo usa margens preventivas de 1 GiB para 4B e 4 GiB para 9B, não requisitos oficiais. Ambos foram pulados por recursos nesta tentativa. Benchmarks anteriores do 4B ficam separados das novas integrações.

Evidências: [entrega e diagnóstico](../reports/SECURITY_ENTREGA.md), [integração real](../reports/security-integration.json), [interface real](../reports/security-ui-live.json) e [ensaio de modelos](../reports/security-model-smoke.json). `TOOL_UNAVAILABLE` é ferramenta ausente, `scope_revoked` é autorização revogada e timeout é falha operacional; nenhum deles é uma recusa temática do modelo.
