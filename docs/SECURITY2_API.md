# Security Center 2.0 — API humana e ferramentas do chat

Base local: `http://127.0.0.1:8765/api/security/v2`. As rotas usam a autenticação e as proteções Host/Origin já existentes. Na interface, `fetch` usa a sessão de mesma origem; clientes externos locais precisam do Bearer local conforme a configuração da instalação. Não publique nem registre `data/auth.secret`, senhas ou cookies. Os exemplos usam identificadores fictícios; obtenha os IDs reais pelas rotas de consulta.

Todas as decisões são humanas. A API de aprovação não é oferecida como ferramenta do modelo. As prévias congelam a proposta em memória por cinco minutos, vinculam configuração/escopo e são consumidas uma vez. Credenciais de fixtures ficam somente nos argumentos transitórios, sem persistir o objeto de argumentos no histórico das tarefas.

## Rotas

| Método e caminho relativo | Função |
| --- | --- |
| `GET /status` | Módulos, inventário, configuração/digest, limites, formatos de exportação e tarefas recentes. |
| `POST /installations/preview` | Prepara instalação portátil opcional de uma versão fixa oficial do Nuclei; não inicia download. |
| `POST /configuration/preview` | Valida configuração de instalação local e prepara aprovação de caminhos/hashes. |
| `POST /preview` | Prepara uma auditoria com mecanismo e argumentos. Não inicia execução. |
| `POST /approvals/{approval_id}/decision` | `{"approved":true}` ou `false`, booleano estrito. |
| `GET /runs` | Até cem execuções recentes, sem a saída completa. |
| `GET /runs/{run_id}` | Estado, eventos, resultado, recursos e relatório de uma execução. |
| `POST /runs/{run_id}/cancel` | Solicita cancelamento cooperativo. Corpo `{}`. |
| `GET /assets?scope_id=...` | Até trinta snapshots de inventário de ativos; filtro opcional. |
| `GET /reports/{report_id}?format=json` | Exporta `json`, `md`, `html` ou `pdf` quando disponível. |
| `POST /reports/correlate` | Correlaciona de um a dez relatórios do mesmo alvo/projeto. |
| `POST /reports/{report_id}/delete-preview` | Prepara exclusão somente desse relatório. Corpo `{}`. |
| `POST /retention/preview` | Prepara limpeza por data UTC de tarefas 2.0 encerradas e relatórios elegíveis. |
| `GET /remediation/plans` | Planos recentes com metadados resumidos. |
| `GET /remediation/{plan_id}` | Plano completo, diffs, histórico e revalidação. |
| `POST /remediation/preview` | Prepara proposta de cópia/branch e diffs selecionados. |
| `POST /remediation/{plan_id}/apply-preview` | Prepara escrita na cópia e testes selecionados. Corpo `{}`. |
| `POST /remediation/{plan_id}/revalidate-preview` | Prepara nova auditoria SQLi/AUTH em alvo aprovado. |
| `POST /remediation/consult` | Consulta local do Coder: proposta sem leitura/escrita automática. |

Escopos, upload de amostras e relatórios anteriores continuam nas rotas `/api/security` da [API anterior](SECURITY_API.md). Modelos e agentes continuam independentes nas APIs de suas bibliotecas.

## Escopo humano

`POST /api/security/scopes`:

```json
{
  "name": "NEXUS_LAB aplicação fictícia",
  "targets": ["127.0.0.1"],
  "allowed_ports": [8899, 8900],
  "allowed_tests": ["appsec_sqli", "appsec_auth", "tcp_connect", "http_headers"],
  "environment": "lab",
  "environment_class": "lab",
  "hosting": "own",
  "purpose": "Regressão em dados fictícios preparados",
  "include_subdomains": false,
  "provider_authorization": false,
  "authorization_confirmed": true
}
```

`environment_class`: `lab | staging | production`; `hosting`: `own | shared | vercel | other`. São até cem alvos, até 64 portas explícitas e tipos de teste reconhecidos. Os tipos adicionais são `nuclei`, `zap`, `nmap_service`, `appsec_sqli`, `appsec_auth` e `asset_inventory`; os anteriores permanecem `http_headers`, `tls_certificate`, `tcp_connect`, `nmap_basic` e `osint`. `DELETE /api/security/scopes/{id}` revoga o escopo e altera sua revisão. Nome, descrição ou escopo cadastrado não autorizam uma operação sem aprovação.

## Configuração de ferramenta existente

`POST /configuration/preview`:

```json
{"engine":"nuclei","config":{"path":"C:\\Ferramentas\\nuclei.exe"}}
```

Outras configurações:

```json
{"engine":"zap","config":{"jar":"C:\\Ferramentas\\ZAP\\zap.jar","java":"C:\\Java\\bin\\java.exe"}}
```

```json
{"engine":"ghidra","config":{"install_dir":"C:\\Ferramentas\\ghidra","java_home":"C:\\Java","isolation_acknowledged":true}}
```

Nmap usa `engine:"nmap_service"` e `config.path`. `sha256` e `java_sha256` podem ser informados para comparação; o servidor calcula os valores observados quando omitidos. Ghidra aceita os limites documentados no [guia](SECURITY_CENTER_2.md). Campos desconhecidos são recusados. Caminhos absolutos, arquivos regulares e ausência de aliases/hardlinks são verificados. A aprovação vincula a instalação local e seus pontos de entrada; não autentica toda a distribuição.

### Instalação portátil opcional do Nuclei

`POST /installations/preview` aceita somente o motor previsto pelo instalador:

```json
{"tool":"nuclei"}
```

A prévia informa versão fixa, URL oficial, tamanho aproximado de 46 MB, referência de integridade e destino local. Não aceita URL, caminho de download, versão ou comandos arbitrários fornecidos pelo cliente. A resposta usa o mesmo `approval_id`/prazo e o fluxo `POST /approvals/{id}/decision`. Apenas a decisão humana positiva cria uma tarefa de download. Consulte `/runs/{id}` para os eventos e solicite cancelamento pela rota normal.

Versão fixada: Nuclei `3.11.1`, ZIP Windows AMD64 de `46067128` bytes, SHA-256 `bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2`. Eventos `stage:"download"` fornecem `downloaded_bytes`, `total_bytes` e `total_source`; a interface usa esses contadores, sem estimar percentuais pelo tempo. `archive_verified`, `extract` e `installed` distinguem verificação, bytes extraídos e conclusão. O `exe_sha256` observado no final não é o hash do ZIP, e `version_verified:false` indica que o executável não foi iniciado pelo instalador.

`GET /status` inclui `installation`, com versão, `installed`, caminho e hash quando existentes. `installed:true` não implica `scanners.tools[].configured:true`: é necessária outra prévia/decisão de configuração com o caminho/hash instalado. O download não executa o scanner. ZAP/Ghidra/Nmap/JDK não possuem instaladores automáticos nesta API. Nenhum download nativo foi executado durante a validação desta entrega; testes com respostas instrumentadas não comprovam transferência real do pacote.

## Prévia, decisão e tarefa

`POST /preview` aceita somente os campos superiores `engine`, `args`, `scope_id`, `project_id` e `sample_id`.

```json
{
  "engine": "appsec_sqli",
  "scope_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "project_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "args": {
    "target": "http://127.0.0.1:8899/sqli",
    "parameter": "name",
    "baseline": "NEXUS_LAB_A",
    "marker": "NEXUS_LAB_SQLI_MARKER_A",
    "lab_confirmation": true
  }
}
```

Resposta resumida:

```json
{
  "ok": true,
  "requires_approval": true,
  "approval_id": "cccccccccccccccccccccccccccccccc",
  "expires_seconds": 300,
  "preview": {"engine":"appsec_sqli","scope":{},"detail":{}}
}
```

Confira a prévia e envie `POST /approvals/cccccccccccccccccccccccccccccccc/decision` com `{"approved":true}`. Uma auditoria aprovada retorna `{"ok":true,"queued":true,"job":{"id":"...","state":"queued"}}`; consulte `/runs/{id}`. Negar retorna `approval_denied`, sem iniciar o adaptador. Configuração/exclusão podem ser concluídas diretamente na decisão, sem tarefa longa.

Estados: `queued`, `running`, `cancelling`, `cancelled`, `completed`, `failed` e `interrupted`. `completed` significa conclusão do adaptador; cobertura parcial, indícios e limitações continuam no resultado. Cancelar não reverte efeitos anteriores. Não há endpoint SSE nesta entrega: a interface consulta o estado e os eventos registrados.

## Mecanismos e argumentos

| `engine` | Campos do corpo |
| --- | --- |
| `http_headers`, `tls_certificate` | `scope_id`; `args.target`. |
| `tcp_connect` | `scope_id`; `args.target`, `args.ports` até oito. |
| `nmap_service` | `scope_id`; `args.target`, `ports`, `level`, `service_detection`, `expanded_ports_approved`, `duration_seconds`, `rate_limit`. |
| `nuclei` | `scope_id`; `args.target`, `level`, `templates`, `duration_seconds`, `rate_limit`. |
| `zap` | `scope_id`; `args.target`, `level`, `endpoints`, `openapi`, `duration_seconds`, `rate_limit`. |
| `appsec_sqli` | `scope_id`; `args.target`, `parameter`, `baseline`, `marker`, `lab_confirmation`. |
| `appsec_auth` | `scope_id`; `args.target`, `fixture`, `synthetic_accounts_confirmed`, `lab_confirmation`. |
| `asset_inventory` | `scope_id`; `args.target`, `known_subdomains` até cinco nomes explícitos. |
| `osint` | `scope_id`; `args.domain`, operadores e limites do construtor de dorks anterior. |
| `cve` | `args.cve_id`. Consulta fonte pública; não envia código. |
| `code_audit` | `project_id`; `args:{}`. |
| `static_file`, `investigate`, `rea`, `ghidra` | `sample_id`; `args:{}`. Ghidra usa somente a configuração aprovada. |
| `windows` | `args.section`: `overview`, `defender`, `processes`, `connections`, `startup`, `tasks` ou `events`. |

`level`: `PASSIVE | SAFE ACTIVE | STAGING FULL`. Para scanners: duração entre 5 e 180 segundos; taxa entre 1 e 5 requisições/s; Nmap recebe no máximo oito portas ou 64 com aprovação ampliada. Nuclei/ZAP aceitam somente HTTP em IP literal de laboratório local/privado, com proxy limitado, sem redirects/CONNECT. Não recebem comandos livres ou templates externos.

Exemplo ZAP, **somente depois de configurar o motor nativo**:

```json
{
  "engine":"zap",
  "scope_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "args":{
    "target":"http://127.0.0.1:8899/",
    "level":"PASSIVE",
    "duration_seconds":60,
    "rate_limit":1,
    "endpoints":["/health"],
    "openapi":{"openapi":"3.0.3","info":{"title":"Lab","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}}}}
  }
}
```

O documento é um objeto fornecido explicitamente, não uma URL a buscar. Referências remotas, servidores externos, operações de escrita e parâmetros obrigatórios não são transformados em requisições arbitrárias. A prévia informa quais GET/HEAD foram planejados. Nenhum spider completo é executado.

AUTH padrão:

```json
{"engine":"appsec_auth","scope_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","args":{"target":"http://127.0.0.1:8899/","synthetic_accounts_confirmed":true,"lab_confirmation":true}}
```

A fixture opcional e os estados de SQLi estão descritos em [SECURITY_APPSEC.md](SECURITY_APPSEC.md). Use somente credenciais fictícias prefixadas; as prévias não incluem senhas.

## Relatórios e correlação

`GET /reports/{id}` retorna o envelope do armazenamento: `id`, `operation`, `created_at` e `result`. Relatórios 2.0 usam `result.schema:"nexus-security-report/2"`, com `engine`, `run_id`, `scope`, `target`, `project_id`, `duration_seconds`, `configuration_digest`, `findings`, `coverage`, `limitations`, `tools_used`, `result` do adaptador e histórico de correção quando aplicável.

Achados possuem ID normalizado, título, gravidade, confirmação, local, evidência e origem. CWE/CVE/referências aparecem quando fornecidos pelo mecanismo; não são inventados para preencher o relatório. Correlação é conservadora e conserva ocorrências e fontes.

```json
{"report_ids":["dddddddddddddddddddddddddddddddd","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]}
```

Envie esse corpo para `POST /reports/correlate`. São aceitos somente relatórios do mesmo alvo/projeto. `POST /reports/{id}/delete-preview` prepara exclusão e usa o mesmo fluxo de decisão. A remoção limpa também o resultado duplicado da tarefa associada, mantendo metadados; planos, arquivos e backups podem conservar outras evidências. `format=pdf` retorna HTTP 424 se `reportlab` estiver ausente; consulte `status.export_formats`.

Limpeza supervisionada `POST /retention/preview`:

```json
{"before":"2026-01-01"}
```

A data é interpretada como corte UTC. A prévia lista tarefas 2.0 em estados finais anteriores ao corte e seus relatórios elegíveis. Usa aprovação de cinco minutos e a mesma decisão humana; nenhuma exclusão começa na prévia. Preserva tarefas ativas, relatórios usados por planos, registros do painel anterior e arquivos/amostras/branches/backups. Não é apagamento forense ou limpeza automática integral de uma investigação.

## Remediação: três aprovações independentes

Primeiro, prepare um plano a partir de um relatório 2.0 concluído:

```json
{
  "report_id":"dddddddddddddddddddddddddddddddd",
  "project_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "finding_ids":["0123456789abcdef01234567"],
  "edits":[{"path":"queries.py","content":"def lookup_name(db, name):\n    return db.execute(\"SELECT marker FROM records WHERE name = ?\", (name,)).fetchall()\n"}],
  "tests":[["python","-m","unittest","discover","-s",".","-p","test_regression.py"]],
  "tests_authorized":true
}
```

`POST /remediation/preview` responde com aprovação de preparação. Os IDs devem corresponder aos achados existentes do relatório. Até dez alterações atingem arquivos existentes; a cópia tem até mil arquivos/20 MiB e omite segredos/dependências/bancos. Os testes opcionais são até três comandos argv começando por `python -m pytest` ou `python -m unittest`, sempre com `tests_authorized:true`. Executam código do projeto com as permissões da conta.

Depois da primeira decisão, consulte a tarefa e `/remediation/{plan_id}` para obter `branch_path`, branch Git quando disponível, diffs e estado `prepared`. `POST /remediation/{id}/apply-preview` retorna a segunda aprovação, que escreve somente na cópia e executa as verificações aprovadas. Hashes/revisão são revalidados para impedir aplicar um diff sobre arquivos alterados.

Inicie manualmente a cópia corrigida em laboratório e prepare a terceira aprovação:

```json
{"scope_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target":"http://127.0.0.1:8900/sqli"}
```

Envie para `POST /remediation/{id}/revalidate-preview`. `args` opcional substitui os argumentos do teste e precisa conter os mesmos campos obrigatórios do adaptador; use-o para fixtures personalizadas, preservando parâmetro/marcador da auditoria original. A revalidação dinâmica integrada aceita SQLi/AUTH. Planos originados no `code_audit` aceitam `{}` para reexecutar somente o Code Auditor estático na cópia, sem rede ou execução do projeto. O resultado compara `absent_in_revalidated_coverage`, `still_present` ou `inconclusive`. Referência ausente ou regressão falha não confirma correção. A comparação refere-se à cópia/alvo revalidado; nenhum deploy ou merge é realizado.

Consulta opcional `POST /remediation/consult`:

```json
{"task":"Revise a correção SQL e proponha testes de regressão.","context":"Trecho autorizado do projeto e evidências fictícias."}
```

São até 2.000 caracteres de tarefa, 4.000 de contexto e 5.000 no conjunto. A rota usa o consultor local configurado e a vaga compartilhada de inferência. Retorna proposta/métricas; não abre arquivos, executa código ou aplica sugestões. A interface usa até 3.500 caracteres de contexto e informa esse limite.

## Ferramentas do chat

`security_workbench({})` consulta inventário e retorna `configuration_digest`. Não instala nem aprova mecanismos. É oferecida nos modos com ferramentas de segurança; o modo CHAT não executa ferramentas.

`security_audit_v2` é oferecida **somente em AGENT** e aceita:

```json
{
  "scope_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "scope_revision":1,
  "target":"http://127.0.0.1:8899/sqli",
  "engine":"appsec_sqli",
  "configuration_digest":"DIGEST_ATUAL_RETORNADO_POR_SECURITY_WORKBENCH",
  "arguments":{"parameter":"name","baseline":"NEXUS_LAB_A","marker":"NEXUS_LAB_SQLI_MARKER_A","lab_confirmation":true}
}
```

Mecanismos disponíveis nessa ferramenta: `nuclei`, `zap`, `nmap_service`, `appsec_sqli`, `appsec_auth` e `asset_inventory`. `scope_revision` e `arguments` são opcionais conforme o contrato; os demais campos exibidos são obrigatórios. O alvo superior é o alvo autorizado; argumentos não podem substituí-lo por outro. Digest alterado, escopo revogado e dependência ausente interrompem a proposta/execução. O executor solicita aprovação humana do efeito; chamar a ferramenta não concede aprovação. As rotas antigas e os demais modos/ferramentas permanecem disponíveis conforme suas permissões anteriores.

## Erros, limites e persistência

Erros de entrada/permissão retornam JSON com `ok:false`, `error`, `code` e `source:"operational"`, normalmente HTTP 400. Decisão com booleano inválido ou campos extras gera validação HTTP 422. Uma tarefa pode retornar HTTP 200 na consulta e conter `state:"failed"`; verifique estado, `ok`, código e resultado. São falhas operacionais, não respostas de recusa do modelo.

Há uma execução por vez, fila de até quatro, até 32 aprovações pendentes, 2 MiB por registro de tarefa, limite de 500 execuções/banco de 256 MiB e verificação geral de 3 GiB livres para ZAP/Ghidra. Aprovações/argumentos transitórios somem após expiração/reinício; tarefas persistentes não concluídas são marcadas como interrompidas.

Persistência: `data/security/security.sqlite3` reúne tabelas anteriores e `v2_runs`, `v2_assets`, `v2_plans`; configuração humana fica em `data/security/modules.json`. Cópias/branches estão sob `data/security/remediation/{plan_id}/workspace`. Backup SQLite inclui as tabelas 2.0, mas copiar somente o banco não preserva os arquivos dessas branches ou instalações externas. Consulte [backup e retenção](SECURITY_CENTER_2.md#backup-e-restauração).
