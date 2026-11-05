# NEXUS UNRESTRICTED — LOCAL

Perfil de conversa local adicionado em 05/11/2026. Não treina nem substitui os modelos instalados.

Nesta instalação, **NEXUS UNRESTRICTED — LOCAL ficou ativo como padrão**. Somente o campo `profile` foi alterado na ativação; modelo, qualidade salva, temperatura, contexto, Tor e acesso ao computador foram preservados.

## Ativar e desativar

Abra **http://127.0.0.1:8765**. Ao lado do modelo, use o seletor:

- **NEXUS PADRÃO:** usa a configuração de qualidade salva, inclusive a revisão automática quando Cuidadoso estiver selecionado.
- **NEXUS UNRESTRICTED — LOCAL:** transmite a resposta original do modelo, sem revisão automática e sem uma segunda geração para substituir uma saída vazia.

A escolha no topo vale para as próximas mensagens desta aba. Para guardar a escolha como padrão, abra **Configurações → Perfil padrão**, selecione o perfil e salve. Para desativar, escolha **NEXUS PADRÃO**. A troca mantém as conversas, memórias, projetos, modelos e permissões.

O modelo e o perfil selecionados aparecem na interface. Quando uma geração começa, o servidor informa também o modelo efetivamente usado e o perfil daquela geração. Os seletores ficam bloqueados enquanto ela estiver em andamento. Uma mudança de configuração em outra aba não muda o perfil já capturado para uma resposta em curso.

## Diferenças entre os perfis

| Comportamento | NEXUS PADRÃO | NEXUS UNRESTRICTED — LOCAL |
| --- | --- | --- |
| Classificador de assuntos ou blacklist de palavras | Não há | Não há |
| Instruções de resposta | Perfil padrão configurável | Perfil técnico direto configurável |
| Revisão automática Cuidadoso | Conforme configuração | Não aplicada; configuração salva é preservada |
| Recuperação de geração vazia com thinking | Uma tentativa sem thinking | Não repete; aviso técnico separado |
| Recusa escrita pelo modelo | Pode passar pelo revisor se Cuidadoso | Preservada integralmente |
| Modelo selecionado explicitamente | Pode preservar o controlador principal quando o consultor não serve para ferramentas | Respeitado; incompatibilidade gera erro técnico |
| Aprovação de escrita, comandos e instalação | Obrigatória | Obrigatória |
| Proteção de credenciais, caminhos e rede | Ativa | Ativa |
| Quantidade de mensagens | Sem cota no aplicativo | Sem cota no aplicativo |

O nome UNRESTRICTED significa ausência de filtro temático adicional e de reescrita automática neste perfil. Não significa acesso irrestrito ao computador nem eliminação de recusas aprendidas pelo modelo. Uma resposta do modelo pode conter erro, recusa ou advertência própria.

## O que é preservado na resposta

Os fragmentos de texto recebidos do modelo são enviados na ordem original. O perfil não troca uma resposta técnica por uma mensagem genérica, não reescreve uma recusa e não faz uma segunda geração editorial. A formatação Markdown e os links seguros são renderizados sem executar HTML ou JavaScript do texto; a ação Copiar usa o texto da resposta.

Erros de serviço, saída vazia e limite de rodadas são exibidos fora do texto do modelo. Respostas parciais já recebidas permanecem visíveis quando há interrupção. O rastreio interno de raciocínio não é exibido como resposta; as chamadas nativas são eventos de ferramentas.

A cópia persistida no SQLite continua passando pela proteção de credenciais conhecida da memória. Por isso, uma sequência que pareça chave ou token pode ser redigida no histórico ou na exportação, mesmo quando o texto ao vivo era diferente. Essa proteção não é uma classificação de assunto e não foi removida. Não use o chat para guardar senhas.

## Personalizar instruções sem editar Python

Os arquivos UTF-8 ficam em `profiles`:

| Arquivo | Função |
| --- | --- |
| `unrestricted_local.md` | Objetividade, precisão e tratamento contextual dos pedidos no perfil novo |
| `standard.md` | Comportamento do perfil padrão |
| `agents.json` | Instruções das especialidades; a seção `unrestricted_local` sobrescreve somente os itens indicados |
| `operations.md` | Orientação comum de uso das ferramentas e aprovação |
| `coder.md` | Papel do consultor de programação, sem ferramentas próprias |
| `reviewer.md` | Revisão editorial usada no perfil padrão Cuidadoso |

Faça backup, edite o arquivo e mantenha o JSON válido. As instruções do perfil são lidas no começo de cada nova solicitação; uma resposta já iniciada mantém seu snapshot. Arquivos inexistentes, vazios, inválidos ou maiores que 24 KB produzem erro de configuração, sem fallback silencioso para outro perfil. Instruções extensas consomem a janela de contexto.

Editar esses textos não muda as verificações do executor em `tools.py`, `computer.py`, `access.py` ou a autenticação da API. Uma instrução não aprova um comando, não concede uma pasta e não aceita termos de instalação.

Também é possível configurar pela linha de comando, com o servidor parado:

```powershell
.\.venv\Scripts\python.exe -m nexus.setup --profile unrestricted_local
```

Para retornar:

```powershell
.\.venv\Scripts\python.exe -m nexus.setup --profile standard
```

O campo persistido é `profile` em `data/config.json`. A variável opcional `NEXUS_PROFILE` serve como padrão quando o arquivo de configuração não sobrescreve o valor.

## Conteúdo e permissões operacionais

Discutir SQL injection, depurar código, analisar um executável próprio ou propor uma automação é diferente de executar comandos ou enviar dados para uma rede. O perfil não classifica esses assuntos como proibidos. O contexto, os recursos do modelo e as ferramentas disponíveis continuam influenciando a resposta.

As ferramentas de busca mantêm a proteção contra envio de credenciais, caminhos locais e trechos que pareçam código privado. Há falsos positivos possíveis em consultas técnicas com sintaxe de código: reformule a pesquisa como palavras-chave públicas, por exemplo `Python sqlite3 consulta parametrizada documentação oficial`, e analise o trecho no contexto local. Não há SafeSearch temático adicional configurado no aplicativo; provedores externos podem aplicar suas próprias políticas.

As ferramentas HTTP continuam limitadas a destinos públicos e não acessam automaticamente `localhost` ou IPs privados. Isso vale também em um laboratório próprio: a limitação de transporte deve ser identificada como tal, sem chamar o pedido de impróprio. As operações disponíveis no PC continuam exigindo as pastas e aprovações descritas no [guia de acesso ao computador](PROGRAMACAO_E_ACESSO_PC.md).

## Identificar a origem de uma limitação

| Sinal | Interpretação |
| --- | --- |
| Texto de recusa recebido como token | Resposta do modelo; não é automaticamente removida ou reescrita no perfil novo |
| Evento `source=model_service` | Erro técnico do Ollama, protocolo, conexão ou capacidade do modelo |
| Evento de ferramenta `source=tool` | Resultado real, erro ou código de saída da ferramenta |
| `source=application`, como `tool_not_allowed` | Modo, ferramenta ou outra validação operacional do aplicativo |
| `source=permission` | Aprovação recusada ou expirada; não é recusa do modelo |
| `notice` de limite ou resposta vazia | Aviso separado do texto gerado; não substitui a resposta |

Não há classificador de intenção no fluxo de inferência. O script comparativo procura alguns sinais textuais de recusa apenas para diagnóstico do relatório. Esses sinais podem estar citados em uma análise legítima e exigem leitura; não alimentam filtros nem alteram respostas.

## Auditoria, comparação e testes

Leia a [auditoria completa dos mecanismos encontrados](AUDITORIA_DE_CONTEUDO.md). As linhas da auditoria inicial se referem à cópia imutável anterior à alteração, para que a movimentação dos prompts não apague a referência.

A [comparação de modelos e perfis](../reports/comparacao-perfis-modelos.md) e seu [JSON com respostas originais](../reports/comparacao-perfis-modelos.json) separam inventário, ensaios executados, truncamentos, erros e verificações de recursos. Uma capacidade anunciada em `/api/show` não prova uso correto de ferramentas. Um modelo chamado `abliterated` ou `uncensored` não fornece garantia de correção ou ausência de recusas.

O benchmark não baixa pesos nem substitui o modelo padrão. O 9B pode exigir mais RAM e offload de camadas; isso não foi medido neste notebook. O tamanho do download inclui componentes que podem não ser carregados numa conversa textual. O ensaio não força a carga quando a memória livre está abaixo do orçamento preventivo. Não se calcula uma frequência de recusas para um modelo que não foi executado.

Os resultados dos testes automatizados e da integração HTTP ficam em `reports/testes-unrestricted.log` e `reports/integracao-unrestricted.json`. Os testes de interface ficam em `reports/unrestricted-ui.json`, com capturas de tela. Consulte o resultado de cada caso; isso não é uma avaliação geral de inteligência.

### Resultados desta entrega

- **427 testes automatizados e 32 subtestes aprovados; um teste pulado** por requisito de symlink do ambiente Windows. O aviso de depreciação do cliente de testes permanece registrado.
- **API real:** os dois perfis responderam na mesma conversa; o padrão fez uma revisão e o UNRESTRICTED não fez revisão. A preferência salva permaneceu intacta durante esse teste.
- **Interface real:** perfil UNRESTRICTED e modelo 4B confirmados no Chromium, com 25 conversas visíveis. A opção Cuidadoso permaneceu salva e ficou desativada no controle enquanto o perfil novo está selecionado. A verificação foi somente de leitura.
- **Preservação:** os nove arquivos de projeto do backup e as 55 mensagens anteriores ficaram inalterados; nenhum registro anterior de projeto, conversa ou memória foi removido. A validação acrescentou uma conversa e quatro mensagens. Os cinco modelos existentes continuam disponíveis. Veja `reports/preservacao-unrestricted.json`.

| Ensaio do Qwen3.5 4B | Padrão | UNRESTRICTED |
| --- | --- | --- |
| Respostas recebidas | 8/8 | 8/8 |
| Sinais textuais de recusa detectados | 0/8 | 0/8 |
| Respostas cortadas pelo limite de 512 tokens | 4/8 | 3/8 |
| Mediana da geração | 50,47 tokens/s | 51,45 tokens/s |
| Leitura nativa de arquivo | Aprovada | Aprovada |
| Correção aritmética testada | Três assertivas aprovadas | Três assertivas aprovadas |

Essa rodada comparou as instruções com contexto de 2.048 e thinking desativado, sem o revisor editorial; o fluxo de revisão foi verificado separadamente pela API. A diferença pequena de velocidade não demonstra superioridade. Houve erros reais no decorador assíncrono e na explicação de SQLite em ambos os perfis; estão descritos na revisão qualitativa. Texto completo e ausência de recusa não comprovam código correto.

O Huihui 9B foi inventariado, mas **não executado**: havia 1,50 GiB de RAM livre, abaixo do mínimo preventivo de 4 GiB do ensaio. Assim, sua frequência de recusas, qualidade, velocidade e consumo em execução continuam sem medida nesta instalação. O modelo permanece instalado e não há evidência suficiente para substituir o 4B ou pedir outro download.

Para reproduzir, copie antes os relatórios que deseja guardar, evite outras gerações e execute na pasta principal:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\validar_perfis_http.py
.\.venv\Scripts\python.exe scripts\comparar_perfis_modelos.py --run --max-tokens 512
```

A prova HTTP cria uma conversa de teste e recusa qualquer solicitação de aprovação. O comparativo substitui seus arquivos de relatório, verifica recursos antes das cargas e não baixa modelos. Se quiser medir o 9B posteriormente, libere memória fechando programas que você escolher e rode novamente; o orçamento é preventivo e não garante ausência de paginação. Não execute um segundo cliente de IA ao mesmo tempo.

## Backup e conservação

O backup anterior às alterações está em:

```text
reports/backup-unrestricted-20261105-014507
```

Contém código, documentação, scripts, testes, projetos locais, configurações e cópias consistentes dos dois bancos SQLite, com manifesto de hashes. Pesos Ollama, ambiente virtual e extensões do VS Code permanecem em seus locais originais e não foram duplicados.

Um erro de gravação durante a elaboração da auditoria atingiu o arquivo novo `profiles/agents.json`; ele foi restaurado antes da retomada do comparativo. O incidente está registrado separadamente e não afetou os arquivos anteriores. A primeira coleta de testes também encontrou as cópias dos testes dentro do backup; `pytest.ini` agora direciona a coleta para `tests`, mantendo os backups preservados.

O comando habitual `python -m nexus.setup --backup DESTINO` agora também inclui `profiles`, além dos bancos e configurações já cobertos. Ele continua sem copiar os projetos e os pesos automaticamente. Para restaurar o backup desta atualização, pare o servidor, preserve uma cópia do estado atual e restaure os arquivos escolhidos; não substitua bancos mais recentes sem decidir quais conversas deseja preservar.

Para iniciar e encerrar, adicionar modelos e manter a instalação, use o [guia geral](GUIA_DE_USO.md).
