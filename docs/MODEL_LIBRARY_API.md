# AI Library — API local de modelos

A AI Library usa o Ollama já instalado. Modelos, agentes e permissões são recursos separados. Nenhuma rota de aprovação é disponibilizada como ferramenta para o modelo. As rotas herdam a autenticação local, a verificação de origem e as proteções HTTP do NEXUS.

## Operações e aprovação

O prefixo é `/api/library/models`.

| Método e caminho | Função |
| --- | --- |
| `GET /api/library/models` | Inventário real: `/api/tags`, `/api/show` e `/api/ps`; recursos, uploads e histórico. |
| `POST .../preview` | Valida e prepara uma operação; não baixa, carrega ou remove pesos. |
| `POST .../jobs` | Consome a aprovação e inicia uma tarefa na fila compartilhada. |
| `GET .../jobs` e `GET .../jobs/{id}` | Estado e eventos reais de progresso. |
| `POST .../jobs/{id}/cancel` | Solicita cancelamento do cliente e fecha a conexão ativa. |
| `POST .../uploads?name=modelo.gguf&sha256=...` | Upload binário em streaming; SHA-256 esperado opcional. |
| `DELETE .../uploads/{id}` | Remove apenas a cópia recebida pelo NEXUS; mantém modelos Ollama. |

A prévia recebe um JSON com `action`, `model` e os campos específicos. Retorna `approval_id`, `expires_in: 300` e `preview`. A aprovação recebe apenas `approval_id`, `approved` booleano e `confirmation`, obrigatório na remoção e igual ao nome completo com tag. Argumentos não podem ser substituídos na decisão; a prévia é consumida uma única vez. Há até 32 aprovações pendentes e oito tarefas em execução/fila. Esses limites controlam recursos, sem limitar mensagens de conversa.

```json
{"action":"pull","model":"smollm2:135m"}
```

```json
{"approval_id":"identificador_de_32_caracteres_hex","approved":true}
```

| `action` | Campos adicionais | Comportamento |
| --- | --- | --- |
| `pull` | — | Consulta manifesto oficial e baixa pela API `/api/pull`. |
| `variant` | `base`, `system`, `context`, `temperature` | Base instalada; cria com `/api/create`, sem treinar pesos. |
| `import` | `upload_id`, `system`, `context`, `temperature` | Revalida hash e GGUF; envia blob e chama `/api/create`. |
| `hf` | `repo`, `filename`, `revision`, parâmetros de variante | Resolve referência pública Hugging Face para commit fixo; baixa somente o GGUF selecionado. |
| `delete` | — | Requer confirmação digitada; bloqueia modelos referenciados nas configurações. |
| `unload` | — | Solicita `keep_alive: 0`, sem remover pesos. |
| `default` | — | Seleciona modelo local que declare capacidade de conversação. |
| `test` | `prompt` opcional, até 1000 caracteres | Teste curto real, 2048 de contexto e até 48 tokens, descarregando ao terminar. |

Os nomes são normalizados com `:latest` quando a tag não é informada. URLs, caminhos, nomes cloud e comandos não são nomes válidos. Adições nunca sobrescrevem uma tag instalada. Base, destino, hash e referências de configuração são revalidados ao executar. A aplicação preserva os modelos existentes; para alterar uma variante, escolha outro nome e remova a anterior somente depois de conferir o resultado.

## Metadados, progresso e recursos

O inventário expõe `name`, `size`, `digest`, `quantization`, `parameter_size`, `capabilities`, `tools`, `vision`, `context_length`, `loaded`, `size_vram`, `default` e `local`. Ausência de metadados permanece explícita. Uma capacidade declarada não garante qualidade, precisão ou suporte perfeito em todos os prompts.

O tamanho apresentado na prévia Ollama é a soma dos blobs do manifesto oficial. O cache pode reduzir o tráfego real. Falhas temporárias ao consultar o manifesto deixam o tamanho como desconhecido; tags inexistentes são indicadas como erro. Se um manifesto conhecido mudar depois da aprovação, uma nova prévia será exigida.

As tarefas exibem `queued`, `running`, `completed`, `failed`, `cancelled` ou `interrupted`. `progress` contém os bytes realmente informados pelo Ollama ou transferidos pelo NEXUS. O percentual se refere ao blob/evento atual, não a uma estimativa inventada da operação inteira. Etapas sem total exibem progresso indeterminado. A conclusão exige a confirmação `success` do Ollama.

Cancelar fecha a conexão do NEXUS. Downloads compartilhados por outro cliente podem continuar no Ollama e arquivos parciais podem permanecer em cache. A API não promete apagar parciais nem desfazer uma criação já concluída no servidor. Consulte a biblioteca após o cancelamento.

Downloads, criação, remoção, descarregamento e testes usam a mesma fila do chat e Security Center. O teste não carrega um segundo modelo se outro estiver ativo. RAM/GPU/armazenamento são medidos; contexto alto e pesos grandes geram avisos, sem inventar estimativa exata de KV cache. A importação reserva 2 GiB de armazenamento e pode demandar duas cópias dos pesos. A API Ollama não informa o caminho físico de armazenamento remoto; o disco medido é o do projeto NEXUS.

Para o teste curto, a margem preventiva local de RAM livre é 0,5 GiB para pesos até 512 MiB, 4 GiB para pesos acima de 5 GiB e 1 GiB nos demais casos. Quando a GPU é detectada, pesos que excedam sua VRAM livre podem ampliar essa margem. A prévia mostra o cálculo e a checagem é repetida após a fila. Esses números são uma precaução deste equipamento, não requisitos oficiais nem garantia de que um modelo cabe em todos os contextos. O NEXUS não encerra aplicativos para liberar memória.

## Importação GGUF e Hugging Face

O assistente aceita GGUF completo little-endian versões 2 e 3, até 16 GiB. O arquivo fica em `data/library/uploads`, com nome interno aleatório. O NEXUS confere assinatura, limites de metadados, arquitetura permitida, quantidade e tabela de tensores e SHA-256. Essa validação não certifica todos os pesos; o Ollama decide a compatibilidade final ao importar/carregar. Arquiteturas novas precisam de atualização da lista do importador; arquivos divididos em shards ainda não são suportados. O cabeçalho e a tabela de tensores devem caber em 16 MiB.

A referência Hugging Face exige `autor/repositório` e um arquivo `.gguf` explícito. A prévia mostra publicador, commit, licença disponível, tamanho e hash LFS quando presentes. Não há selo de confiança atribuído automaticamente ao publicador. O download usa commit fixo e compara o hash disponibilizado pelo provedor; sem hash externo, informa apenas o hash calculado. Redirecionamentos aceitos ficam limitados a HTTPS em hosts de entrega Hugging Face/Xet/CloudFront. Não há login privado, execução de código remoto, instalação de dependências do repositório ou execução de scripts.

A prévia de Modelfile é informativa. Os campos `system`, `temperature` e `num_ctx` são enviados separadamente à API; um prompt contendo `FROM` ou outros textos não cria comandos adicionais. Criar uma variante não realiza treinamento ou fine-tuning de pesos.

## Persistência e evidências

`data/library/jobs.json` mantém as últimas 100 operações, sem copiar os prompts de configuração para o histórico. Credenciais reconhecíveis são redigidas. Operações interrompidas por reinício ficam como `interrupted`; não retomam automaticamente. Os eventos de aprovação e resultado também entram no registro de atividade existente. Uploads e seus hashes persistem separadamente. Links, junções e hardlinks são rejeitados nesse armazenamento.

Os testes automatizados usam transporte HTTP isolado e arquivos GGUF sintéticos para validar controles e contratos; isso não substitui testes reais de importação e inferência com pesos compatíveis. Os testes reais autorizados devem ser descritos separadamente no relatório de entrega.

Fontes primárias consultadas em 05/11/2026:

- [API oficial Ollama: tags, show, ps, pull, create, blobs e delete](https://github.com/ollama/ollama/blob/main/docs/api.md).
- [Importação GGUF no Ollama](https://docs.ollama.com/import).
- [GGUF no Hugging Face com Ollama](https://huggingface.co/docs/hub/en/ollama).
- [Especificação GGUF](https://github.com/ggml-org/ggml/blob/master/docs/gguf.md).
