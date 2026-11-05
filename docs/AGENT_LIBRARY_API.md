# Agent Library — especialistas configuráveis

A Agent Library administra instruções e limites de especialistas. A AI Library administra os modelos do Ollama. Vários agentes podem usar o mesmo modelo; cadastrar ou selecionar um agente não baixa nem carrega pesos.

Os especialistas internos continuam no registro original e nos arquivos `profiles/`. São somente leitura na biblioteca. Use **Duplicar** para criar uma cópia editável. A configuração de cada agente personalizado fica no novo banco `data/library/agents.sqlite3`, separado da memória, dos projetos e das autorizações existentes.

## Contrato HTTP

As rotas reutilizam a autenticação local e a verificação de origem do aplicativo. Não são ferramentas expostas ao modelo.

| Método e rota | Entrada e resultado |
| --- | --- |
| `GET /api/library/agents` | Catálogo `{agents, modes, tools, limits, permission_notice}`. |
| `POST /api/library/agents` | Configuração abaixo; retorna o agente criado. |
| `GET /api/library/agents/{id}` | Retorna o agente. |
| `PUT /api/library/agents/{id}` | Configuração completa mais `revision`; retorna o agente atualizado. |
| `DELETE /api/library/agents/{id}?revision=1` | Exclui apenas um agente personalizado cuja revisão ainda coincide. |
| `POST /api/library/agents/{id}/duplicate` | Corpo opcional `{"name":"Meu especialista"}`; retorna uma nova cópia. |
| `GET /api/library/agents/{id}/export` | Download JSON versionado, sem identificador nem autorizações do computador. |
| `POST /api/library/agents/import` | Envelope JSON exportado; valida e cria um novo identificador. |

```json
{
  "name": "Meu revisor Python",
  "description": "Revisa o projeto selecionado com evidências por arquivo e linha.",
  "icon": "◈",
  "workspace_mode": "developer",
  "prompt": "Leia os arquivos antes de opinar. Distinga evidências de hipóteses.",
  "default_model": "qwen3.5:4b-q4_K_M",
  "tool_allowlist": ["list_files", "read_file", "grep_files"],
  "memory": {"read": true, "write": false, "scope": "project"},
  "permissions": {
    "file_read": true,
    "file_write": false,
    "terminal": false,
    "external_network": false
  },
  "search": {"provider": "auto", "max_results": 5, "tor_enabled": false}
}
```

O catálogo fornece modos como `{id, name, ...}` e ferramentas como `{name, description, available?, reason?}`. Os modos associados são `chat`, `search`, `tor`, `pentest`, `developer` e `security`. Eles permanecem separados dos modos operacionais `CHAT`, `PLAN`, `CODE`, `AGENT`, `REVIEW` e `RESEARCH`.

Cada registro também contém `id`, `builtin`, `revision`, `created_at` e `updated_at`. Agentes personalizados recebem `custom_` seguido de um UUID; especialistas internos têm revisão zero. A revisão obrigatória na edição e na exclusão impede sobrescrever silenciosamente mudanças de outra aba.

O envelope de exportação tem este formato:

```json
{"format":"nexus-agent","version":1,"agent":{"name":"...","prompt":"..."}}
```

O exemplo é abreviado; a exportação real inclui todos os campos editáveis. Importações não podem incluir `id`, `builtin`, `revision`, scripts, pastas autorizadas, escopos de rede nem campos desconhecidos. JSON é interpretado como dados; prompts não são executados como Python, JavaScript ou comandos.

## Limites e permissões

O validador confere nomes de ferramentas com o registro real recebido do servidor e revalida o agente antes de ativá-lo. Uma ferramenta registrada pode continuar indisponível por plataforma, modo, ausência de dependência, modelo incompatível ou falta de autorização operacional.

As permissões e a lista de ferramentas de um agente são limites adicionais. Marcar `terminal: true` permite que o gerenciador considere a ferramenta; isso não aprova comandos. Marcar acesso a arquivos não autoriza novas pastas. Ativar Tor na configuração de pesquisa não liga o proxy nem supera a ativação explícita da interface. Um prompt não concede escopos de pentest, acesso a credenciais, download de modelos ou execução de amostras. O executor compõe a interseção entre modo operacional, modo associado, ferramentas do agente e autorizações vigentes.

Os padrões de um agente personalizado são: modo `chat`, ferramentas vazias, leitura de memória permitida, escrita de memória desativada, leitura de arquivos permitida como teto, escrita/terminal/rede desativados e Tor desativado. Configure apenas os recursos necessários. O modelo padrão vazio usa a seleção do aplicativo; preencher o campo não instala o modelo. A validação final de existência e compatibilidade do modelo ocorre no fluxo de execução.

`memory.read: false` impede recuperação de memória e contexto anterior para o modelo. `memory.write: false` impede criar resumos derivados e memórias automáticas. **O histórico e a auditoria da conversa continuam persistidos**, conforme a configuração de histórico do NEXUS. `scope: conversation` limita o contexto à conversa; `scope: project` permite o projeto selecionado e contexto global permitido, sem recuperar conteúdo de outro projeto.

São aceitos até 200 agentes personalizados, configuração de 64 KiB, prompt de 24.000 bytes UTF-8 e até 160 nomes de ferramentas. O ícone é texto curto ou emoji, sem HTML. Os únicos provedores configuráveis nesta versão são `auto`, `duckduckgo` e `searxng`; `max_results` fica entre 1 e 10. Não há execução de código de plug-ins importados nem carregamento de scripts distribuídos com agentes.

## Persistência, erros e validação

As gravações usam transações SQLite, bloqueio por banco e revisão otimista. Pastas com symlinks/junctions, banco com hardlinks e links em arquivos auxiliares SQLite são rejeitados. Os nomes e identificadores não são usados para montar caminhos de arquivo.

Erros retornam `{ok:false,error,code,source:"agent_library"}`: entrada inválida usa HTTP 400, registro ausente usa 404 e conflitos ou edição de especialistas internos usam 409. Os eventos de auditoria registram identificador e revisão, sem copiar o prompt ou sua configuração completa.

`tests/test_agent_library.py` valida CRUD e reinicialização, preservação de um banco anterior, especialistas somente leitura, duplicação/importação/exportação, revisão concorrente, nomes de modelos, ferramentas reais, campos de permissão, JSON inerte, limites UTF-8, banco corrompido e proteção contra links. A proteção de autenticação/origem é fornecida e testada no aplicativo principal; o teste isolado destas rotas não a substitui.
