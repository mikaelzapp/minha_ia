# Guia de uso do NEXUS AI

**Iniciar, fechar, adicionar modelos e cuidar da sua instalação.**

**Gerenciamento visual novo:** veja [Central multimodal, AI Library e Agent Library](CENTRAL_MULTIMODAL.md) para administrar modelos/especialistas sem editar Python, usar os seis modos e reverter escritas. Os comandos manuais abaixo continuam úteis; o novo gerenciador é a alternativa pela interface.

**Security Center:** o [guia de segurança](SECURITY_CENTER.md) explica agentes, escopos, dorks, arquivos, REA, auditoria de código, Windows e relatórios, com as capacidades e partes pendentes desta instalação.

**Security Center 2.0:** veja [os dez módulos e a correção supervisionada](SECURITY_CENTER_2.md) para auditorias de laboratório, tarefas, diffs, aprovações e revalidação em uma cópia/branch. O painel anterior continua acessível.

**Perfis:** veja [NEXUS UNRESTRICTED — LOCAL](PERFIS_LOCAIS.md) para selecionar ou personalizar o perfil de resposta sem alterar as permissões do computador.

**Recursos adicionados depois deste guia:** veja [Programação, qualidade e acesso ao PC](PROGRAMACAO_E_ACESSO_PC.md) para o consultor Qwen2.5-Coder 7B, revisão adicional, pastas autorizadas e instalação de aplicativos com aprovação.

**Atualização de respostas:** veja [Respostas diretas e melhorias de qualidade](RESPOSTAS_E_QUALIDADE.md) para o novo tratamento de contexto, evidências de testes e recuperação quando o modelo não entrega texto.

Guia conferido com o código desta instalação e com a documentação oficial em **05/11/2026**. Os exemplos de outros modelos são opcionais e não iniciam downloads automaticamente.

Pasta do projeto:

```text
C:\Users\mikae\Downloads\ia\nexus-ai
```

Interface: **http://127.0.0.1:8765**.

## Índice

1. [Começar em um minuto](#1-começar-em-um-minuto)
2. [Iniciar, fechar e reiniciar](#2-iniciar-fechar-e-reiniciar)
3. [Entender modelos, agentes e modos](#3-entender-modelos-agentes-e-modos)
4. [Adicionar outra IA pelo Ollama](#4-adicionar-outra-ia-pelo-ollama)
5. [Escolher o modelo e ajustar o desempenho](#5-escolher-o-modelo-e-ajustar-o-desempenho)
6. [Usar o novo modelo no VS Code](#6-usar-o-novo-modelo-no-vs-code)
7. [Trabalhar em projetos e usar a memória](#7-trabalhar-em-projetos-e-usar-a-memória)
8. [Criar uma variante ou importar GGUF](#8-criar-uma-variante-ou-importar-gguf)
9. [Adicionar um especialista ao NEXUS](#9-adicionar-um-especialista-ao-nexus)
10. [Fazer backup e manutenção](#10-fazer-backup-e-manutenção)
11. [Resolver problemas comuns](#11-resolver-problemas-comuns)
12. [Arquivos e comandos de consulta](#12-arquivos-e-comandos-de-consulta)

## 1. Começar em um minuto

| Quero… | O que fazer |
| --- | --- |
| Abrir o NEXUS | Dê dois cliques em **Iniciar NEXUS.cmd** na pasta do projeto. |
| Voltar para uma interface já aberta | Acesse **http://127.0.0.1:8765** no navegador. |
| Conversar sem alterar arquivos | Selecione **CHAT**, escreva e pressione **Enter**. |
| Escrever uma mensagem com várias linhas | Use **Shift + Enter**. |
| Cancelar a resposta atual | Clique em **Interromper**. Alterações já executadas não são desfeitas. |
| Fechar apenas a tela | Feche a aba do navegador. O servidor continua funcionando. |
| Encerrar o servidor NEXUS | Dê dois cliques em **Parar NEXUS.cmd**. |
| Escolher outra IA já instalada | Use o seletor de modelo no topo da conversa. |
| Salvar um modelo como padrão | Abra **Configurações**, escolha o modelo e clique em **Salvar configurações**. |
| Ver os modelos disponíveis no computador | No PowerShell, execute `ollama list`. |

Para ler este guia com formatação no VS Code, abra o arquivo e pressione **Ctrl + Shift + V**.

## 2. Iniciar, fechar e reiniciar

### Iniciar pelo Explorador de Arquivos

1. Abra a pasta `C:\Users\mikae\Downloads\ia\nexus-ai`.
2. Dê dois cliques em **Iniciar NEXUS.cmd**.
3. Aguarde a interface abrir no navegador.
4. Confira se aparece **Ollama conectado**.
5. Escolha o modelo e envie uma mensagem curta.

O script reutiliza o Ollama se ele já estiver rodando. Quando necessário, tenta iniciar o Ollama instalado. A primeira mensagem pode demorar para carregar o modelo; o diagnóstico inicial registrou aproximadamente 91 segundos em uma situação de pouca RAM livre. Isso é uma medição anterior, não um tempo fixo.

Não é necessário executar novamente o instalador a cada uso. O NEXUS não foi configurado para iniciar automaticamente com o login do Windows.

### Iniciar pelo PowerShell

Abra o PowerShell e execute:

```powershell
cd C:\Users\mikae\Downloads\ia\nexus-ai
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\iniciar.ps1 -Abrir
```

O servidor funciona em segundo plano. Fechar esse terminal ou a aba do navegador não é o comando de encerramento. Se ele já estiver rodando, o script informa o endereço atual.

### Encerrar o NEXUS

Use **Parar NEXUS.cmd** ou:

```powershell
cd C:\Users\mikae\Downloads\ia\nexus-ai
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\parar.ps1
```

O script encerra a árvore de processos identificada como pertencente ao servidor NEXUS. Ele preserva modelos baixados, conversas, projetos e um Ollama que já estivesse rodando antes do NEXUS. Aguarde tarefas e gravações terminarem antes de encerrar.

### Liberar a memória do modelo sem apagar a IA

O modelo pode continuar carregado no Ollama depois de parar o painel. Para verificar e descarregar **somente o modelo que você escolher**:

```powershell
ollama ps
ollama stop qwen3.5:4b-q4_K_M
```

`ollama stop` descarrega o modelo; não apaga seus pesos do disco nem seu histórico. Se você usar outro modelo, substitua pelo nome exato exibido em `ollama ps`. Feche ou pause outros clientes que possam voltar a carregá-lo, como o Continue. [Referência oficial dos comandos Ollama](https://docs.ollama.com/cli).

Existe ainda uma opção para parar o processo Ollama que o próprio NEXUS tenha iniciado:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\parar.ps1 -PararOllamaProprio
```

Ela só afeta o Ollama identificado no registro local do NEXUS. Não encerra um serviço preexistente e não equivale a parar qualquer Ollama do computador. Se necessário, encerre o aplicativo Ollama pelo ícone na bandeja do Windows, depois de terminar de usá-lo nos outros programas.

### Reiniciar

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\parar.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\iniciar.ps1 -Abrir
```

Esse procedimento preserva os dados e é necessário após alterar código ou editar manualmente a configuração carregada pelo servidor.

## 3. Entender modelos, agentes e modos

| Conceito | O que significa | Exemplo |
| --- | --- | --- |
| **Modelo** | A IA cujos pesos o Ollama executa. | `qwen3.5:4b-q4_K_M` |
| **Agente / especialista** | Instruções e ferramentas para determinada função, usando o modelo selecionado. | NEXUS CODER ou NEXUS RESEARCHER |
| **Modo** | Define o tipo de trabalho e as operações permitidas. | CHAT, PLAN ou AGENT |
| **Modelo de embeddings** | Converte textos em vetores para procurar conteúdo relacionado na memória. | `embeddinggemma` |

Adicionar um modelo ao Ollama não cria um especialista novo. Selecionar outro especialista não baixa outro modelo. Os nove especialistas existentes compartilham o motor local.

| Modo | Quando usar |
| --- | --- |
| **CHAT** | Perguntas e explicações, sem ferramentas de alteração de arquivos. |
| **PLAN** | Ler o projeto e preparar um plano. |
| **CODE** | Propor e aplicar alterações de código mediante aprovação. |
| **AGENT** | Realizar etapas de leitura, implementação e testes com ferramentas autorizadas. |
| **REVIEW** | Inspecionar código e procurar problemas sem escrever arquivos. |
| **RESEARCH** | Pesquisar e consultar fontes públicas. |

O modo e o especialista trabalham juntos: o modo permite operações e o especialista seleciona um subconjunto de ferramentas. Use **RESEARCH + NEXUS RESEARCHER** para pesquisa e **AGENT + NEXUS BROWSER** para interagir com páginas. Nem todo especialista recebe todas as ferramentas.

## 4. Adicionar outra IA pelo Ollama

### Passo 1 — Verificar o que já está instalado

```powershell
ollama list
```

No momento da conferência deste guia, estavam instalados:

| Modelo | Tamanho aproximado em disco | Situação |
| --- | --- | --- |
| `qwen3.5:4b-q4_K_M` | 3,4 GB | Modelo principal testado. |
| `qwen2.5-coder:7b` | 4,7 GB | Consultor de programação instalado com autorização; veja o guia de programação. |
| `qwen35-zode-4b:latest` | 3,4 GB | Variante já existente; não foi validada como substituto. |
| `huihui_ai/qwen3.5-abliterated:9b-q4_K` | 6,6 GB | Já existente; excede a VRAM de 6 GB e não foi selecionado automaticamente. |
| `embeddinggemma:latest` | 622 MB | Usado pela memória; não é modelo de conversa. |

Se o modelo desejado já estiver nessa lista, não precisa baixá-lo novamente: vá ao passo 4.

### Passo 2 — Escolher uma versão adequada

Consulte a [biblioteca oficial do Ollama](https://ollama.com/library) e abra a página da **tag exata** desejada. Confira tamanho, quantização, requisitos de versão e capacidades.

Para este notebook, comece avaliando modelos pequenos, em torno de 3B–4B e quantizações como Q4. Isso é uma orientação baseada na RTX 4050 de 6 GB e na RAM observada nesta instalação. O tamanho do download não representa toda a memória usada: contexto, cache e processamento também consomem recursos. Modelos maiores podem usar RAM/CPU e ficar muito mais lentos.

Para usar CODE, AGENT e outros modos com ferramentas, escolha um modelo com suporte efetivo a **tools**. Um modelo que conversa bem pode não executar chamadas de ferramenta corretamente. Prefira pesos locais; variantes cloud não atendem à proposta de inferência local/offline desta instalação.

### Passo 3 — Baixar explicitamente

Exemplo opcional: a página oficial de [`qwen3:4b`](https://ollama.com/library/qwen3:4b) listava aproximadamente **2,5 GB**, com ferramentas e raciocínio, na data da consulta. É um candidato para comparação, não uma promessa de melhoria em relação ao Qwen3.5 já instalado.

**Execute o bloco abaixo somente se quiser realizar esse download e tiver espaço disponível:**

```powershell
$modeloNovo = 'qwen3:4b'
ollama pull $modeloNovo
```

Para outro modelo, troque apenas o valor de `$modeloNovo` pelo nome e tag da biblioteca. Aguarde o término. Não é necessário usar `ollama run` para fazer o download; `pull` prepara o modelo sem iniciar uma conversa. [Comando de download](https://docs.ollama.com/cli).

Depois confirme a instalação e examine as capacidades:

```powershell
ollama list
ollama show $modeloNovo
```

Se fechar o PowerShell, a variável `$modeloNovo` deixa de existir; defina-a novamente ou use diretamente o nome completo nos próximos comandos.

### Passo 4 — Fazer aparecer no NEXUS

1. Abra o NEXUS normalmente.
2. Mantenha a aba visível e aguarde até aproximadamente 10 segundos, ou pressione **F5** quando não houver geração em andamento.
3. Abra o seletor de modelo no topo da conversa.
4. Escolha o nome recém-instalado.
5. Abra uma **Nova conversa** e teste em **CHAT** com uma pergunta curta.

A lista vem do Ollama automaticamente. Não precisa editar `app.py`, criar uma chave de API ou reinstalar o NEXUS para adicionar um modelo compatível. Modelos identificados como exclusivos de embeddings são filtrados do seletor de chat.

### Passo 5 — Salvar como padrão, se desejar

Abra **Configurações → Modelo padrão**, escolha a IA e clique em **Salvar configurações**. O seletor do chat muda o modelo das mensagens seguintes nesta aba; salvar nas configurações grava o padrão para os próximos acessos.

O histórico e as memórias do NEXUS continuam no mesmo armazenamento. A troca de modelo não cria automaticamente uma memória separada para cada IA.

### Passo 6 — Testar as ferramentas antes de confiar no modelo

1. Selecione **PLAN + NEXUS CODER** e peça para ler `exemplo-calculadora/README.md`.
2. Confira se há uma chamada real de `read_file` e um resultado no painel de atividade.
3. Em **CODE + NEXUS CODER**, peça um pequeno arquivo de teste dentro do projeto.
4. Verifique se aparece um diff real e um pedido de aprovação. Texto dizendo “vou criar” não significa que um arquivo foi gravado.
5. Recuse uma alteração para verificar o fluxo de recusa. Aprove apenas quando o caminho e o conteúdo estiverem corretos.

Opcionalmente, compare modelos já instalados no PowerShell, com outras gerações locais pausadas:

```powershell
cd C:\Users\mikae\Downloads\ia\nexus-ai
.\.venv\Scripts\python.exe -m nexus.benchmark --quick --model qwen3.5:4b-q4_K_M --model qwen3:4b
```

Use esse exemplo somente depois de instalar `qwen3:4b`; substitua os nomes se estiver comparando outros modelos. O benchmark não baixa pesos. O relatório `reports/benchmark-quick.json` é substituído a cada execução: copie o anterior se quiser preservar a comparação. Examine o array `models`, pois os campos resumidos em `tests` podem refletir o último modelo avaliado. O benchmark verifica resposta, chamada de ferramenta, raciocínio básico e recursos, mas não comprova qualidade geral de programação.

## 5. Escolher o modelo e ajustar o desempenho

Em **Configurações**:

| Ajuste | Orientação para começar |
| --- | --- |
| Modelo padrão | Mantenha o Qwen3.5 4B testado até validar uma alternativa. |
| Janela de contexto | Comece com **4.096**. Use **2.048** se faltar memória. A interface atual permite até **8.192**. |
| Temperatura | O valor configurado é **0,2**. Valores menores costumam tornar a resposta menos variável; não garantem correção. |
| Raciocínio aprofundado | Ativo nesta instalação. Pode ajudar em tarefas difíceis e aumentar o tempo de resposta. |

O controle de raciocínio só é enviado quando o modelo anuncia a capacidade `thinking`. Marcar a opção não adiciona essa capacidade a um modelo que não a tenha. Da mesma forma, o suporte a imagens anunciado pelo modelo não habilita upload visual no painel atual, que recebe anexos textuais.

Para consultar os recursos:

```powershell
ollama ps
nvidia-smi
```

`ollama ps` permite conferir modelos carregados e a distribuição de processamento. O monitor do NEXUS mostra RAM e GPU. Evite gerar respostas no Continue e no painel ao mesmo tempo: ambos usam o mesmo Ollama, mas a fila interna do NEXUS não controla o outro cliente.

### Modelos de embeddings

Mantenha `embeddinggemma` enquanto estiver satisfeito com a busca. Ele serve para memória, não para responder no chat.

Alterar `embedding_model` é uma operação avançada: exige editar `data/config.json`, reiniciar o NEXUS e planejar a migração do índice. **A versão atual não reprocessa automaticamente todos os vetores antigos ao trocar esse campo.** Arquivos sem mudança de conteúdo são pulados pela indexação incremental. A busca ignora vetores incompatíveis e mantém a parte textual. Apenas clicar em Indexar não constitui uma migração completa para outro modelo de embeddings.

## 6. Usar o novo modelo no VS Code

### Abrir o perfil certo

```powershell
cd C:\Users\mikae\Downloads\ia\nexus-ai
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\vscode.ps1
```

Para abrir um projeto específico:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\vscode.ps1 -Projeto 'workspaces\exemplo-calculadora'
```

Esse comando abre o perfil NEXUS com Continue separado do seu perfil habitual. Abra a barra lateral do Continue ou pressione **Ctrl + L**. Mudar o modelo no painel web não altera a configuração do Continue.

### Adicionar um modelo ao Continue

Primeiro, baixe o modelo pelo Ollama e teste suas capacidades. Depois:

1. Edite `integrations\continue.yaml`, o arquivo-base da configuração.
2. Adicione o novo bloco dentro da lista `models`, alinhado com o bloco do Qwen3.5 já existente.
3. Aplique a mesma alteração em `data\continue\config.yaml`, a configuração ativa.
4. Recarregue a janela do perfil NEXUS no VS Code e selecione o novo modelo no Continue.

Exemplo de **bloco adicional**, para `qwen3:4b` já instalado:

```yaml
  - name: NEXUS Qwen 3 4B
    provider: ollama
    model: qwen3:4b
    apiBase: http://127.0.0.1:11434
    roles:
      - chat
      - edit
      - apply
    capabilities:
      - tool_use
    defaultCompletionOptions:
      contextLength: 4096
      maxTokens: 1024
      temperature: 0.3
```

Não crie uma segunda chave `models:` no mesmo arquivo. O campo `model` deve corresponder exatamente ao nome instalado. Só declare `tool_use` quando houver suporte real; essa configuração não ensina ferramentas ao modelo. [Configuração Ollama no Continue](https://docs.continue.dev/customize/model-providers/top-level/ollama).

O script `scripts\configurar-vscode.ps1` copia o arquivo-base sobre o ativo. Por isso, alterar só `data\continue\config.yaml` pode perder suas mudanças na próxima reconfiguração. Se quiser reaplicar o arquivo-base, faça cópia do ativo antes de substituí-lo:

```powershell
$copiaContinue = 'data\continue\config-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.yaml.bak'
Copy-Item -LiteralPath 'data\continue\config.yaml' -Destination $copiaContinue
Copy-Item -LiteralPath 'integrations\continue.yaml' -Destination 'data\continue\config.yaml'
```

O Continue tem histórico, ferramentas e aprovações próprios. Ele não herda automaticamente a memória nem as decisões de aprovação do painel NEXUS. Fechar o VS Code também não encerra o servidor NEXUS.

## 7. Trabalhar em projetos e usar a memória

### Adicionar um projeto

1. Crie ou copie seu projeto para `workspaces\meu-projeto` dentro da pasta NEXUS.
2. No painel, abra **Projetos**.
3. Informe um nome e o caminho, por exemplo `meu-projeto` ou o caminho absoluto dessa pasta dentro de `workspaces`.
4. Clique em **Adicionar projeto** e depois em **Indexar arquivos**.
5. Selecione o projeto no painel da conversa.
6. Comece com **PLAN** e peça uma explicação dos arquivos.

Depois de alterações externas, clique novamente em Indexar para atualizar o conhecimento. A indexação ignora segredos conhecidos, dependências, links e outros arquivos protegidos; não é uma cópia irrestrita do repositório.

### Pedidos que você pode usar

```text
PLAN: Leia a estrutura do projeto e proponha três etapas para implementar uma API.

REVIEW: Revise os arquivos do projeto e indique bugs com caminhos e explicações.

CODE: Proponha uma alteração pequena no arquivo indicado e mostre o diff para aprovação.

AGENT: Leia o código, proponha a correção e solicite a execução dos testes.

RESEARCH: Consulte a documentação oficial de Python sobre pathlib e cite as fontes.
```

Selecione o modo correspondente na interface; escrever o nome do modo na mensagem não muda as permissões por si só.

### Guardar uma preferência ou decisão

Abra **Memória → Adicionar uma memória**, escreva o conteúdo e escolha o tipo. Exemplo: “Neste projeto, usar type hints e testes unittest”. Prefira contexto claro sobre a qual projeto a decisão se aplica. Para recuperar, use a busca da memória ou faça uma pergunta com o projeto selecionado.

**Exportar** gera JSON local. Excluir uma conversa ou memória na interface remove o item correspondente. A exportação JSON não equivale a backup completo e a interface atual não oferece importação desse JSON.

Anexos do painel são de texto, até 20 mil caracteres por arquivo. Para arquivos maiores e repositórios, use a indexação dentro dos limites documentados em `README.md`.

## 8. Criar uma variante ou importar GGUF

Esta seção é opcional e mais técnica. Para uso comum, instalar uma tag da biblioteca oficial é o caminho mais simples.

### Criar uma variante local de um modelo já instalado

Crie um arquivo de texto chamado `Modelfile` na pasta de trabalho, por exemplo:

```dockerfile
FROM qwen3.5:4b-q4_K_M
PARAMETER num_ctx 4096
PARAMETER temperature 0.2
```

Depois execute na pasta que contém esse arquivo:

```powershell
ollama create nexus-coder-local -f .\Modelfile
ollama show nexus-coder-local
```

O novo nome aparecerá no seletor após atualizar a lista. Isso cria uma configuração derivada e não treina uma IA nova. [Referência de Modelfile](https://docs.ollama.com/modelfile).

No NEXUS, os valores de contexto e temperatura enviados pelo painel prevalecem sobre os padrões do Modelfile. O aplicativo também envia suas próprias instruções de sistema. Para personalizar o comportamento de um especialista no painel, siga a seção 9, em vez de depender apenas de `SYSTEM` no Modelfile.

### Importar um GGUF

Com um arquivo compatível e de procedência conhecida já baixado, coloque-o junto de um `Modelfile` contendo:

```dockerfile
FROM ./meu-modelo.Q4_K_M.gguf
PARAMETER num_ctx 4096
```

Troque o nome pelo arquivo real e execute:

```powershell
ollama create meu-modelo-local -f .\Modelfile
ollama show meu-modelo-local
```

A arquitetura e a versão do Ollama precisam ser compatíveis. Importar um GGUF não garante template de conversa, ferramentas ou raciocínio corretos; valide cada capacidade. Essa importação também não reduz automaticamente a quantização de um GGUF já preparado. [Importação oficial de modelos](https://docs.ollama.com/import).

## 9. Adicionar um especialista ao NEXUS

Para criar um especialista como **NEXUS DOCUMENTADOR**, sem baixar mais pesos:

1. Faça backup e pare o NEXUS.
2. Abra `nexus\engine.py` no editor.
3. Na lista `AGENTS`, acrescente um identificador único e um nome:

```python
{"id": "documentador", "name": "NEXUS DOCUMENTADOR"},
```

4. Abra `profiles\agents.json` e acrescente a instrução para o mesmo identificador dentro do objeto `standard`:

```json
"documentador": "Explique a arquitetura e escreva documentação em português, com exemplos verificáveis."
```

5. Preserve as vírgulas e a estrutura dos arquivos; esses trechos são entradas dentro das estruturas existentes, não programas completos. O objeto `unrestricted_local` pode sobrescrever a instrução de uma especialidade; os demais itens herdam de `standard`.
6. Inicie novamente e atualize a página. O novo nome aparecerá no seletor de agentes.
7. Teste primeiro em CHAT e PLAN.

O especialista compartilha o modelo escolhido e continua sujeito às permissões do modo. Sem outra alteração, recebe o conjunto padrão de ferramentas selecionado em `select_schemas`, em `nexus\app.py`. Criar um nome novo não concede ferramentas de navegador nem acesso adicional. Modificar o roteamento Automático ou os conjuntos de ferramentas é desenvolvimento do aplicativo e deve ser revisado e testado.

## 10. Fazer backup e manutenção

### Backup dos bancos e da configuração

Pare o NEXUS e execute, na pasta principal:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\parar.ps1
$backupNexus = Join-Path $PWD ('reports\backup-manual-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
.\.venv\Scripts\python.exe -m nexus.setup --backup $backupNexus
```

O destino precisa estar dentro da pasta NEXUS. O utilitário cria backup consistente de SQLite e copia a configuração e o lock de dependências.

| Incluído nesse comando | Não incluído |
| --- | --- |
| Banco de memória e conversas | Projetos de `workspaces` |
| Banco de atividade | Código do aplicativo |
| `data/config.json` | Perfil e configuração do Continue |
| `data/computer-access.json` e instruções em `profiles` | Pesos e ambientes de execução |
| `requirements-lock.txt` | `auth.secret`, `.env` e pesos gerenciados pelo Ollama |

Para um backup mais completo, copie também os projetos, o código e as configurações que você personalizou para um local privado. Guarde uma cópia fora do disco do notebook se precisar de proteção contra falha física. Os pesos do Ollama ficam fora da pasta NEXUS na instalação padrão; registre os nomes/tags para baixá-los novamente. Não há restauração automática de uma instalação inteira pelo exportador de memória.

### Manutenção com as versões atuais

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\atualizar.ps1
```

O script para o NEXUS, cria backup e revalida a instalação. Ele não baixa nova versão do código nem atualiza modelos. Ao terminar, inicie o NEXUS novamente.

Para atualizar intencionalmente as dependências Python:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\atualizar.ps1 -AtualizarDependencias
```

Esse segundo comando pode baixar pacotes e mudar versões. Ele testa as dependências antes de gravar o novo lock. A atualização de pesos é separada e pode exigir download grande; confira o tamanho da tag antes de usar `ollama pull` novamente.

### Remover um modelo do disco — somente se você quiser apagá-lo

`ollama stop` apenas libera memória. `ollama rm` apaga o modelo local selecionado e afeta outros aplicativos que usem o mesmo modelo. Para remover deliberadamente o exemplo opcional `qwen3:4b`, primeiro escolha outro padrão no NEXUS e no Continue, encerre seu uso e então execute:

```powershell
ollama stop qwen3:4b
ollama rm qwen3:4b
```

Não use esses comandos para “fechar” o NEXUS. Eles não são necessários na operação diária. Conversas do NEXUS continuam no SQLite, mas os pesos removidos precisam ser baixados novamente para usar esse modelo. [Referência de remoção](https://docs.ollama.com/cli).

### Desinstalar componentes do NEXUS

O script `desinstalar.ps1` sem opções apenas encerra o NEXUS. As opções `-RemoverAmbiente` e `-RemoverDados` solicitam confirmação para apagar os componentes correspondentes. **`-RemoverDados` inclui histórico, memórias, configurações e o perfil local do Continue.** Faça backup primeiro. O script preserva código, projetos em `workspaces`, pesos do Ollama e containers.

## 11. Resolver problemas comuns

### A página não abre

1. Execute **Iniciar NEXUS.cmd**.
2. Use o endereço exibido pelo script; o padrão é `http://127.0.0.1:8765`.
3. Se ainda falhar, confira o log:

```powershell
Get-Content -LiteralPath '.runtime\server.err.log' -Tail 60
```

Se precisar usar outra porta, pare o servidor antes:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\parar.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\iniciar.ps1 -Porta 8766 -Abrir
```

Nesse caso, use `http://127.0.0.1:8766`. Se o NEXUS já estiver rodando, executar iniciar com outra porta reutiliza a instância existente; não muda a porta dela.

### Aparece “Ollama desconectado”

Confira o serviço local:

```powershell
Invoke-RestMethod 'http://127.0.0.1:11434/api/version'
```

Abra o Ollama no Windows se necessário. Alternativamente, execute `ollama serve` em um terminal separado e mantenha-o aberto. Se a porta já estiver ocupada por um Ollama funcional, reutilize-o. Não altere a escuta para `0.0.0.0` para resolver um problema local.

### O modelo novo não aparece

- Confira se o download terminou e o nome consta em `ollama list`.
- Aguarde a atualização da aba visível ou pressione F5 sem geração em andamento.
- Verifique se o NEXUS usa o mesmo Ollama em `127.0.0.1:11434`.
- Modelos exclusivos de embeddings ficam fora do seletor. O filtro da interface também usa palavras do nome, como `embed`, para identificá-los.
- Se o nome mudou de tag, selecione exatamente o nome instalado.

### O modelo responde em CHAT, mas falha em AGENT

Execute `ollama show NOME:TAG`, trocando `NOME:TAG` pelo nome instalado, e confira **Capabilities**. O NEXUS exige `tools` quando envia esquemas de ferramentas. Use CHAT com um modelo sem ferramentas ou escolha outro modelo com suporte efetivo. Adicionar `tool_use` ao YAML do Continue não corrige a falta de suporte nos pesos/template.

### A IA pede “SIM/NÃO” em texto, mas não aparece aprovação

Texto de confirmação não é a aprovação operacional. Peça: “Use a ferramenta correspondente para propor a alteração e mostrar o diff na interface”. Confira o painel de atividade. Se o modelo não chamar a ferramenta, use o Qwen3.5 4B testado ou compare outro candidato.

### Está muito lento ou falta memória

- Aguarde a primeira carga antes de concluir que travou.
- Confira RAM e VRAM no monitor.
- Reduza contexto para 2.048 ou 4.096 e use um modelo menor.
- Evite geração simultânea no VS Code e no painel.
- Termine tarefas desnecessárias em outros aplicativos.
- Se não precisar, desligue o raciocínio aprofundado; respostas podem perder qualidade.
- Use `ollama ps` para verificar o que continua carregado. Descarregue apenas os modelos que você terminou de usar.

### A edição manual de configuração não teve efeito

O `data\config.json` salvo prevalece sobre os valores padrão de `.env`. Para modelo, contexto, temperatura e raciocínio, prefira **Configurações → Salvar**. Para editar JSON manualmente, pare o NEXUS, faça uma cópia, preserve a sintaxe e reinicie. Não substitua o arquivo inteiro por um trecho de exemplo.

### O PowerShell diz que scripts foram desabilitados

Use os arquivos `.cmd` ou os comandos deste guia com `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File ...`. A opção vale para o processo iniciado e não modifica a política global. Uma política administrativa da máquina pode continuar impedindo a execução; registre a mensagem de erro em vez de desativar a segurança do sistema.

### Os dados sumiram depois de uma mudança de pasta

Os dados são locais à instalação em `data`; projetos ficam em `workspaces`. Confira se abriu a mesma cópia do NEXUS. Não mova apenas o código esperando que bancos, perfil Continue e ambiente virtual sejam encontrados em outra pasta. Faça backup antes de reorganizar a instalação.

### Quero usar sem internet

Com os pesos e dependências já presentes, chat, código e busca na memória podem funcionar localmente. Download de modelos, pesquisa pública, navegação e atualizações dependem de rede. O Tor continua opcional, desativado por padrão e depende de instalação e proxy funcionais próprios.

## 12. Arquivos e comandos de consulta

| Caminho | Conteúdo |
| --- | --- |
| `README.md` | Visão técnica, instalação e limites da versão. |
| `ENTREGA.md` | Evidências e resultados da instalação inicial. |
| `data\config.json` | Configuração persistida do NEXUS. |
| `data\memory.sqlite3` | Conversas, memórias e índice local. |
| `data\activity.sqlite3` | Auditoria e controle de resumos. |
| `data\auth.secret` | Token de acesso local; não compartilhe. |
| `data\continue\config.yaml` | Configuração ativa do Continue isolado. |
| `integrations\continue.yaml` | Arquivo-base reaplicado na configuração do Continue. |
| `workspaces` | Projetos autorizados para as ferramentas de arquivo. |
| `.runtime` | Logs e identificação dos processos iniciados. |
| `reports` | Diagnósticos, testes, screenshots de validação e backups. |

Comandos de consulta e diagnóstico:

```powershell
cd C:\Users\mikae\Downloads\ia\nexus-ai
ollama list
ollama ps
ollama show qwen3.5:4b-q4_K_M
nvidia-smi
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\diagnosticar.ps1
```

O último comando grava/atualiza `reports\diagnostico.json`. Os anteriores consultam o estado e não baixam modelos.

### Referências

As instruções específicas do NEXUS foram conferidas em `iniciar.ps1`, `parar.ps1`, `nexus/config.py`, `nexus/engine.py`, `nexus/app.py`, `nexus/memory.py`, `nexus/setup.py`, `nexus/static/app.js`, `vscode.ps1` e nos scripts de manutenção desta instalação.

- [CLI oficial do Ollama](https://docs.ollama.com/cli)
- [Biblioteca oficial de modelos](https://ollama.com/library)
- [Exemplo Qwen3 4B](https://ollama.com/library/qwen3:4b)
- [Modelfile](https://docs.ollama.com/modelfile)
- [Importação de GGUF](https://docs.ollama.com/import)
- [Ollama no Continue](https://docs.continue.dev/customize/model-providers/top-level/ollama)
- [Configuração YAML do Continue](https://docs.continue.dev/reference)
