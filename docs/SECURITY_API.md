# Security Center — arquitetura e API local

O código modular fica em `nexus/security`. Não há segundo servidor: `install_security_routes` registra um router no FastAPI existente. Os mesmos controles de autenticação, Host, Origin, SameSite e CSP protegem o painel. Nunca exponha o token local em documentação ou chamadas compartilhadas.

## Componentes

| Arquivo | Responsabilidade |
| --- | --- |
| `store.py` | SQLite separado, escopos/revisões, amostras inertes e relatórios; verificação de links e hashes. |
| `center.py` | Schemas, validação de argumentos, planos de capacidade, aprovação e despacho sequencial. |
| `api.py` | Ações humanas, streaming limitado de upload, decisões de uso único e exportação. |
| `network.py` | Normalização de alvos, escopo/DNS fixado, HTTP/TLS/TCP/Nmap, dorks, busca e CVE oficial. |
| `static.py` | Leitura limitada, PE/ELF/strings/YARA, AST e verificações de fonte/config/dependências. |
| `platform.py` | Consultas nativas somente leitura e inventário de procedência. |
| `rea.py` | Cliente MCP stdio de operações estáticas permitidas, sem SDK extra ou `npx` em runtime. |
| `common.py` | Erros estruturados, redação de segredos, leitura/hashes e subprocesso limitado. |
| `static/security.js` | Painel integrado; renderização de dados com DOM/textContent, sem executar HTML dos resultados. |

`AgentTools` compõe ferramentas gerais, PC, consultor e Security Center. `engine.route_agent` preserva o agente escolhido explicitamente; Automático usa `task_plan` antes do roteamento geral. O arquivo `profiles/security_center.md` adiciona instruções operacionais apenas aos seis agentes de segurança. Conteúdo de páginas/código/strings é evidência não confiável, não nova instrução.

`app.select_schemas` limita ferramentas por papel e modo. Os jobs do painel e o chat usam o mesmo semáforo de inferência, configurado com concorrência 1 nesta instalação. `security_investigate` roda análise estática e REA sequencialmente com a mesma amostra. Isso não cria uma equipe de LLMs independentes.

## Rotas autenticadas

| Método e caminho | Contrato |
| --- | --- |
| GET `/api/security/status` | Agentes, projetos existentes, escopos, amostras, relatórios, limites e capacidades reais. Inventário pesado em cache por 60 s. |
| GET/POST `/api/security/scopes` | GET retorna `{scopes:[]}`. POST exige `name`, `targets`, `allowed_tests`, `authorization_confirmed:true`; ambiente/finalidade/subdomínios opcionais. |
| DELETE `/api/security/scopes/{id}` | Revogação persistente e incremento da revisão; não apaga o histórico. |
| GET `/api/security/samples` | `{samples:[]}`, até cem metadados recentes. Não serve o binário pelo navegador. |
| POST `/api/security/samples?name=arquivo.zip` | Corpo binário bruto `application/octet-stream`, 1 byte a 10 MiB. Não é multipart nem upload textual da conversa. |
| POST `/api/security/dorks/preview` | Argumentos da ferramenta `security_dork`. Retorna consulta validada, sem busca ou DNS; persiste relatório da prévia. |
| POST `/api/security/jobs` | `{tool,args,mode}`. Resposta final ou `{requires_approval:true,approval_id,preview}`. |
| POST `/api/security/jobs/{id}/decision` | `{approved:true/false}`. Consome decisão uma vez, prazo 300 s; revalida escopo/revisão antes de executar. |
| GET `/api/security/reports` | `{reports:[]}`, cem resumos recentes sem carregar evidências completas em Python. |
| GET `/api/security/reports/{id}?format=json` | Relatório completo exportável. `format=md` exporta Markdown com evidências JSON. |

Decisões pendentes ficam só no processo, até 32 e por cinco minutos; reiniciar invalida essas decisões. Escopos/amostras/relatórios persistem. JSON de POST/PUT/PATCH tem limite real de 2.500.000 bytes, inclusive chunked; upload binário tem limite próprio em streaming. Relatório persistido tem limite de 2 MiB.

## Ferramentas e modos

| Família | Nomes | Permissão |
| --- | --- | --- |
| Contexto e relatórios | `security_context`, `security_report` | Modos com ferramentas; acesso local. |
| Estática | `security_static_file`, `security_rea`, `security_investigate`, `security_code_audit`, `security_windows`, `security_dork` | PLAN/CODE/AGENT/REVIEW/RESEARCH; sem execução do alvo. |
| Pesquisa pública | `security_osint`, `security_cve` | RESEARCH/CODE/AGENT. OSINT exige escopo e aprovação com consulta completa. |
| Sondagens | `security_http`, `security_tls`, `security_tcp`, `security_nmap` | AGENT; escopo + revisão + aprovação individual. |

CHAT e modos desconhecidos não oferecem ferramentas Security. Cada papel recebe um subconjunto dessa tabela. O modelo nunca recebe uma ferramenta para cadastrar escopos, fazer upload, aprovar operações ou configurar VM. As rotas humanas são protegidas pela sessão local; não há isolamento entre programas já executados com a mesma conta do Windows.

A autorização informa os mesmos argumentos que serão executados. O backend acrescenta `scope_revision`, usa cópia dos argumentos, digest e prazo; não aceita mudanças após a aprovação. OSINT constrói a mesma consulta na prévia e na execução, revalida a revisão e envia somente termos públicos ao mecanismo de pesquisa. `keywords` e `exclusions` aceitam string ou lista de strings; operadores aceitam `intitle`, `inurl`, `intext` com valores não vazios.

## Resultados e falhas

Uma análise executada retorna `ok`, `tool`, `code`, `source`, `created_at`, `data`, `findings`, `executed_target:false` e `report_id`. Contexto/recuperação não criam relatórios redundantes. Para consultas de rede, `executed_target:false` significa que nenhum programa do alvo foi executado; conexões aprovadas podem ter sido feitas. Consulte `data.evidence` para método e destino reais.

HTTP 400/403/413/429 indica entrada, permissão, limite de bytes ou excesso de decisões pendentes. Falhas de adaptador também podem retornar HTTP 200 com `ok:false`; o cliente precisa ler esse campo. Exemplos: `scope_revoked`, `scope_changed`, `sample_changed`, `TOOL_UNAVAILABLE`, `TLS_CERTIFICATE_INVALID`, `TIMEOUT`, `SEARCH_FAILED`, `rea_unavailable`, `permission_denied`. Não reinterpretar essas falhas como recusa de conteúdo do modelo ou resultado positivo de análise.

Os resultados externos são redigidos antes da apresentação/persistência. Para PowerShell, JSON é interpretado antes da redação recursiva, preservando sua validade. Redação por padrões não garante detectar todo segredo. Metadados de assinatura ausentes nunca são convertidos em “fornecedor verificado”.

## Estender com outro motor

Adicione adaptador com argumentos estruturados, origem verificável, timeout, limite de saída, retorno explícito de indisponibilidade e testes com laboratório inofensivo. Descobrir executável no PATH não autoriza executá-lo. Conecte o schema ao modo/papel correto e à aprovação quando houver efeitos; nenhum resultado do próprio motor deve conceder escopo. Nunca permita um comando arbitrário no lugar de parâmetros tipados.

Atualize a matriz de compatibilidade e o guia com o que foi realmente validado. Um motor opcional ausente deve manter os testes offline funcionando. Recursos não implementados devem continuar indisponíveis, sem respostas simuladas atribuídas ao scanner.
