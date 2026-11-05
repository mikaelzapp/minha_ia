# Modelos locais para o Security Center

**Recomendação nesta máquina: manter Qwen3.5 4B como executor de ferramentas e Qwen2.5-Coder 7B como consultor de programação, sequencialmente.** Não há evidência local que justifique substituir modelos ou baixar outro agora. O Huihui 9B permanece preservado, com desempenho e frequência de recusas ainda não medidos neste computador.

Este documento combina um inventário somente de leitura de **5 de novembro de 2026**, os benchmarks anteriores preservados e pesquisa nas fichas dos publicadores. **Não foi feita nova inferência de comparação entre modelos para o Security Center nesta etapa.** Testes dos novos adaptadores de segurança são uma evidência separada da qualidade do LLM.

Após a integração, o [ensaio curto de ferramenta Security](../reports/security-model-smoke.json) tentou pré-verificar ambos: havia **0,917 GiB de RAM livre**, abaixo das margens preventivas de 1 GiB para 4B e 4 GiB para 9B. Ambos ficaram `not_run_resources`, sem inferência ou download. O [script reproduzível](../scripts/validar_security_model.py) permite repetir com folga de memória; esses limites são do ensaio, não requisitos oficiais. A consulta local de inventário Ollama foi validada na integração real.

## Inventário e recursos observados

O registro completo está em [`security-model-inventory.json`](../reports/security-model-inventory.json). Foram consultados `GET /api/version`, `GET /api/tags`, `GET /api/ps` e `POST /api/show` somente para metadados, além de psutil e `nvidia-smi`. `show` é uma operação de metadados do [contrato oficial do Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md#show-model-information), embora use POST. Não foram enviados pedidos de geração, embeddings, download ou descarregamento neste inventário.

| Recurso | Observação instantânea |
| --- | --- |
| Ollama | **0.40.6**, API em loopback |
| Sistema | Windows 11, AMD64, 8 núcleos físicos / 16 lógicos |
| RAM utilizável | **15,31 GiB** |
| RAM disponível | **329 MiB**, uso de **97,9%** no instante consultado |
| GPU | NVIDIA GeForce RTX 4050 Laptop GPU, **6.141 MiB** totais |
| VRAM livre informada | **5.920 MiB** no instante consultado |
| Disco livre do projeto | **46,71 GiB** |
| Modelos residentes no Ollama | Nenhum antes e depois deste inventário |

A RAM já estava muito ocupada mesmo sem modelo residente no Ollama. Isso não identifica qual aplicativo é responsável e não autoriza encerrá-lo. É um motivo concreto para evitar ensaios do 9B ou sessões concorrentes neste momento. A folga de disco não resolve falta de RAM.

| Tag instalada | Tamanho informado por `/api/tags` | Quantização / capacidade declarada | Papel recomendado |
| --- | ---: | --- | --- |
| `qwen3.5:4b-q4_K_M` | 3,157 GiB | Q4_K_M; completion, vision, tools, thinking | Principal para os seis agentes de segurança e operações autorizadas. |
| `qwen2.5-coder:7b` | 4,361 GiB | Q4_K_M; completion, tools, insert | Consultor textual para propostas e revisão de código; não executor de ferramentas. |
| `huihui_ai/qwen3.5-abliterated:9b-q4_K` | 6,142 GiB | Q4_K_M informado pelos metadados; completion, vision, tools, thinking | Opção experimental preservada; sem benchmark local concluído. |
| `qwen35-zode-4b:latest` | 3,157 GiB | Derivado local do Qwen3.5 4B; as mesmas capacidades declaradas | Tag local preservada; não é evidência de novos pesos ou maior inteligência. |
| `embeddinggemma:latest` | 0,579 GiB | BF16; somente embedding | Busca semântica local; não gera respostas nem executa ferramentas. |

Esses tamanhos são os registros das tags, não consumo medido de RAM nem total de armazenamento exclusivo. Tags derivadas podem compartilhar blobs. O inventário preserva os digests das cinco tags. A tag Huihui termina em `q4_K`, mas o campo efetivo `quantization_level` retornou **Q4_K_M**; o relatório registra ambos sem renomear o modelo.

A configuração encontrada era: modelo principal 4B, consultor 7B, contexto **4.096**, temperatura **0,2**, thinking habilitado e concorrência **1**. O perfil ativo era `unrestricted_local`; a preferência de qualidade armazenada era `careful`. O comportamento efetivo de revisão depende do perfil; este levantamento não alterou nenhuma dessas configurações.

## Evidência de desempenho já existente

O [comparativo anterior de perfis](../reports/comparacao-perfis-modelos.md) usou oito pedidos legítimos de programação, depuração, engenharia reversa, laboratório de vulnerabilidade, testes, pesquisa técnica, revisão e automação. Cada perfil usou **contexto 2.048, temperatura zero, máximo 512 tokens e thinking desligado**, sem memória nem ferramentas na fase textual. O teste nativo de `read_file` foi separado. Esses resultados não medem a cadeia nova de HTTP, REA, YARA ou Blue Team.

| Modelo e ensaio histórico | Resultado observado | Limite da interpretação |
| --- | --- | --- |
| 4B, perfil padrão | 8 respostas; 0 sinais textuais de recusa; 4 truncadas; mediana **50,47 tokens/s** | Oito pedidos benignos não demonstram ausência de recusas em geral. |
| 4B, perfil unrestricted local | 8 respostas; 0 sinais textuais de recusa; 3 truncadas; mediana **51,45 tokens/s** | Diferença pequena de velocidade não demonstra aumento de inteligência. |
| 4B, chamadas nativas | `read_file` passou nos dois perfis | Não prova acerto em toda ferramenta ou operação. |
| Huihui 9B | **Não executado por recursos** | Não há velocidade, qualidade, uso em execução nem frequência de recusa medidos. |
| Coder 7B, geração e correção mínimas | Duas funções aritméticas passaram três assertivas cada; **21,28 e 23,47 tokens/s**, respectivamente | Saídas de 17 e 10 tokens: amostra pequena, sem tarefas complexas de segurança. |
| Coder 7B, chamada nativa de ferramenta | **Falhou**: retornou JSON como texto comum, sem chamada nativa | Não converter esse texto em comando; preservado como consultor. |

No comparativo anterior, só a depuração aritmética foi executada, num subconjunto restrito por AST. A revisão qualitativa identificou erros técnicos nas duas versões do perfil: decoradores assíncronos incorretos, confusões sobre SQLite/WAL, respostas incompletas e exemplos que pediam aprovação depois de já propor escrita temporária. Resposta sem recusa e texto completo não equivalem a código correto.

O 4B teve uma residência observada de **2,80 GiB total / 2,80 GiB GPU**, com contexto 2.048. No ensaio anterior do Coder 7B, `/api/ps` informou aproximadamente **4,66 GiB de residência total e 3,93 GiB na GPU**, contexto 4.096: houve residência parcial fora da GPU. A RAM do sistema chegou a **99,2%** ao final daquele ensaio. São medições pontuais, não requisitos universais ou garantias de desempenho. Os valores integrais estão em [`coder-pc.json`](../reports/coder-pc.json).

O 9B foi impedido pelo précheque anterior com **1,50 GiB de RAM livre**, abaixo do orçamento preventivo de **4 GiB** escolhido pelo ensaio. Esse orçamento era uma regra de prudência do benchmark, não uma especificação oficial de memória mínima do modelo. Não foram atribuídas recusas ou falhas de qualidade a um modelo que não chegou a ser executado. O inventário atual encontrou ainda menos RAM livre.

As taxas de tokens/s excluem carregamento e não devem ser apresentadas como latência total de uma investigação. Leitura dos arquivos, consulta das ferramentas, prefill, troca de modelo e eventual revisão acrescentam tempo.

## Procedência, licença e capacidades

O **Qwen3.5 4B** é publicado por Qwen sob **Apache 2.0**, e a [tag Ollama exata](https://ollama.com/library/qwen3.5:4b-q4_K_M) anuncia ferramentas, visão e thinking. A [ficha original](https://huggingface.co/Qwen/Qwen3.5-4B) descreve integração com agentes. As tabelas de desempenho de outros tamanhos da família não são resultados do 4B quantizado desta máquina.

O **Qwen2.5-Coder 7B Instruct**, também **Apache 2.0**, é especializado em geração, raciocínio e correção de código segundo o [publicador Qwen](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct). A [tag Ollama](https://ollama.com/library/qwen2.5-coder:7b) anuncia tools, mas o ensaio local de chamada nativa falhou. A capacidade declarada é metadado; o teste operacional é evidência mais forte para escolher o executor.

O **Huihui 9B** é um derivado de Qwen3.5 publicado por um terceiro. A [ficha do publicador](https://huggingface.co/huihui-ai/Huihui-Qwen3.5-9B-abliterated) declara **Apache 2.0** e descreve abliteration para reduzir recusas. Isso não comprova maior correção técnica, menor alucinação ou melhor interpretação de relatórios de segurança. A [tag exata](https://ollama.com/huihui_ai/qwen3.5-abliterated:9b-q4_K) anuncia ferramentas, mas essa combinação não foi validada por inferência local aqui. Nenhuma promessa de eliminação de comportamentos aprendidos nos pesos é feita.

O **EmbeddingGemma** é publicado pelo Google sob **termos Gemma**, distintos de Apache 2.0. Produz vetores para recuperação de texto, com contexto de 2.048 e dimensão 768 na instalação observada. Não é outro gerador de respostas. [Ficha oficial do Google](https://huggingface.co/google/embeddinggemma-300m). A tag local derivada do Qwen3.5 preserva metadados Apache; seu nome particular não comprova uma especialização nova em segurança.

## Alternativas pesquisadas, sem downloads

São candidatos para um ensaio futuro, não substituições aprovadas nem modelos demonstradamente superiores nesta instalação. Tamanho de download não equivale a RAM/VRAM mínima.

| Candidato | Procedência, licença e tamanho publicado | Avaliação para esta instalação |
| --- | --- | --- |
| `qwen2.5-coder:1.5b` | Qwen, **Apache 2.0**, cerca de **986 MB**, Q4_K_M. [Ollama](https://ollama.com/library/qwen2.5-coder:1.5b), [ficha original](https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B-Instruct). | Alternativa menor para código curto; qualidade, português e chamadas nativas precisam de teste. Não há evidência de que supere o 7B. |
| `qwen2.5-coder:3b` | Qwen, **Qwen Research License**, cerca de **1,9 GB**, Q4_K_M. [Ollama e licença](https://ollama.com/library/qwen2.5-coder:3b), [ficha original](https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct). | Candidato intermediário de programação. Sua licença difere da dos tamanhos 1,5B/7B e precisa ser examinada para o uso pretendido. Sem teste local. |
| `qwen3.5:2b-q4_K_M` | Qwen, **Apache 2.0**, cerca de **1,9 GB** na tag exata; tools/vision/thinking. [Ollama](https://ollama.com/library/qwen3.5:2b-q4_K_M), [ficha original](https://huggingface.co/Qwen/Qwen3.5-2B). | Mesmo ecossistema do executor atual, com menos parâmetros. Pode reduzir o custo de recursos, mas não foi demonstrado ganho de qualidade ou confiabilidade. |
| `phi4-mini` | Microsoft, **MIT**, 3,8B, cerca de **2,5 GB**; function calling anunciado. [Ollama](https://ollama.com/library/phi4-mini), [ficha original](https://huggingface.co/microsoft/Phi-4-mini-instruct). | Alternativa de raciocínio/integração. A exigência publicada de Ollama ≥0.5.13 é anterior à versão local 0.40.6, mas compatibilidade real de tools ainda exigiria teste. Não é um modelo de baixa recusa comprovada. |
| `qwen3-coder:30b` | Qwen, **Apache 2.0**, 30,5B totais/3,3B ativos, cerca de **19 GB**. [Ollama](https://ollama.com/library/qwen3-coder), [ficha original](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct). | **Não recomendado nesta máquina no estado atual.** Pesos de todos os experts continuam precisando de residência; 3,3B ativos não tornam seu uso de memória equivalente a um modelo de 3B. Sem margem de RAM e VRAM para esse ensaio. |

Foi examinado também o [CyberSec-Assistant-3B](https://huggingface.co/AYI-NEDJIMI/CyberSec-Assistant-3B), cujo publicador descreve um adaptador QLoRA especializado em segurança sobre Qwen2.5-3B-Instruct. A ficha mostra uso por PEFT, não uma integração Ollama validada neste projeto. Há uma divergência de procedência a resolver: a ficha declara Apache 2.0 inclusive para a base, enquanto a [ficha oficial da base Qwen2.5-3B-Instruct](https://huggingface.co/Qwen/Qwen2.5-3B-Instruct) declara **Qwen Research**. Não foi instalada a pilha PEFT/Transformers, convertido o adaptador ou tratado esse fine-tune como melhoria comprovada.

Não foi encontrada, nesta pesquisa delimitada, evidência suficiente para recomendar um novo modelo leve especializado em engenharia reversa acima da combinação existente com evidências reais do REA. Nomes de treinamento como “cyber”, “uncensored” ou “reasoning” não substituem validação de instruções, programação, fontes e resultados das ferramentas.

## Uso recomendado e próximo ensaio possível

Os seis agentes podem compartilhar o 4B, mudando instruções e ferramentas conforme a tarefa. Preserve a sequência: obter evidências limitadas por ferramenta, resumir com o principal e consultar o especialista de código quando necessário. Uma chamada MCP do analisador não exige carregar outro LLM.

Mantenha **um modelo de geração por vez** e concorrência 1 no NEXUS. Isso não controla outros clientes do Ollama, como Continue ou processos externos. O Ollama documenta que contexto e requisições paralelas aumentam memória, e que a residência pode ser CPU, GPU ou compartilhada; consulte a [FAQ oficial](https://docs.ollama.com/faq). O contexto declarado de 262.144 tokens nas tags Qwen3.5 é capacidade teórica da arquitetura, não orçamento viável deste computador. Não foi alterado o limite local de 4.096.

Para um comparativo novo, primeiro recuperar folga de memória e registrar o estado sem encerrar aplicativos sem autorização. Depois usar as mesmas amostras inofensivas de relatório REA, cabeçalhos HTTP, achados estáticos e eventos, fixando contexto/temperatura/saída e verificando: fatos suportados pela evidência, alucinações, patch que passa nos testes, chamadas nativas válidas, recusas e erros de ferramenta em categorias separadas. Só então comparar o 9B. Esses passos são metodologia proposta, não testes já realizados.

**Nenhum download é solicitado nesta entrega**, porque não foi demonstrada uma alternativa melhor que justifique a troca. Se um futuro ensaio exigir outro modelo, apresentar a tag exata, licença, tamanho, orçamento de RAM/VRAM e plano de validação, e obter autorização antes de baixá-lo. As limitações atuais são principalmente falta de RAM livre, erros técnicos possíveis do modelo, contexto reduzido e ferramentas anunciadas que nem sempre funcionam na prática.
