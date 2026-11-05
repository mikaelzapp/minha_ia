# Respostas diretas e melhorias de qualidade

Atualização de 05/11/2026. Este guia complementa o [guia geral](GUIA_DE_USO.md) e o [guia de programação e acesso ao PC](PROGRAMACAO_E_ACESSO_PC.md).

**Atualização posterior:** o [perfil NEXUS UNRESTRICTED — LOCAL](PERFIS_LOCAIS.md), agora disponível no seletor, preserva a resposta original e não aplica a revisão ou recuperação descritas aqui. Este guia descreve o comportamento do perfil padrão.

## Como o NEXUS responde agora

As instruções do assistente foram ajustadas para:

- Responder diretamente, respeitando requisitos, idioma e formato pedidos.
- Tratar temas controversos, críticas e ficção sem recusar somente pela sensibilidade do assunto e sem sermões desnecessários.
- Avançar em pedidos claros, usando hipóteses razoáveis e declarando as relevantes.
- Perguntar quando faltar uma informação indispensável, evitando confirmações redundantes no texto.
- Dividir tarefas complexas em passos verificáveis e conferir os requisitos antes de concluir.
- Distinguir proposta, ação executada, teste aprovado e falha real.

O aplicativo não usa um serviço externo de moderação nem uma lista de palavras ou assuntos proibidos para filtrar as conversas. Isso não torna os modelos irrestritos: o comportamento aprendido nos pesos e o template do modelo continuam influenciando as respostas, inclusive possíveis recusas. Esta atualização não removeu o alinhamento dos pesos nem treinou um novo modelo. Não existe garantia de que a IA fará qualquer pedido ou responderá sempre corretamente.

Os controles de acesso ao computador continuam ativos. Autorizar uma pasta, aprovar um diff, executar um comando e instalar um aplicativo são decisões sobre ações no Windows. Escrever “faça tudo sem perguntar” no chat não concede essas permissões. A IA chama a ferramenta adequada e a interface apresenta a operação concreta para sua aprovação.

## O que melhora a precisão

### Pedidos longos preservam requisitos

Antes, um pedido que ultrapassasse o espaço disponível podia perder seu começo. Agora, o NEXUS preserva o começo e o fim e identifica o trecho intermediário omitido. O pedido atual tem prioridade sobre o histórico antigo e os documentos recuperados.

O histórico completo continua no SQLite; somente o contexto enviado ao modelo é reduzido. A estimativa usa bytes UTF-8 e não substitui o tokenizer real. Um requisito que apareça apenas no meio de uma mensagem muito extensa ainda pode ficar fora da janela. Divida documentos grandes e destaque os requisitos essenciais no começo e no fim.

### Evidências de ferramentas permanecem legíveis

As chamadas nativas e seus argumentos permanecem intactos. Resultados extensos são compactados como JSON válido, com avisos de omissão, preservando primeiro informações como erro, sucesso e código de saída. A rodada recente tem prioridade; uma chamada e seu resultado são mantidos juntos.

Na revisão final, cada um dos quatro resultados mais recentes recebe uma parcela do espaço. Assim, uma leitura extensa de arquivo não apaga a falha de um teste que veio depois. O começo e o fim da proposta também são preservados. Isso reduz perdas de informação; não comprova por si só a correção do código.

Memória, resumos e documentos recuperados são apresentados como dados de contexto, separados das instruções de sistema. Conteúdo de um arquivo ou página não pode conceder novas permissões.

### Raciocínio sem resposta tem recuperação

Quando um modelo compatível usa raciocínio, confirma o fim da geração e não entrega texto nem chamada de ferramenta, o NEXUS tenta **uma única vez sem raciocínio adicional**. As mensagens, ferramentas e permissões continuam as mesmas.

Uma recusa escrita pelo modelo é uma resposta visível e não dispara essa tentativa. Texto já entregue, chamadas de ferramentas, erros de rede e transmissões interrompidas também não são repetidos automaticamente. Uma nova resposta vazia gera um erro explícito.

### Revisão entrega texto diretamente

No modo **Cuidadoso**, a primeira geração pode usar raciocínio aprofundado. A revisão final solicita texto sem uma segunda etapa de raciocínio, para evitar gastar todo o limite sem entregar uma resposta. O controle depende da compatibilidade do modelo. Consulte a [documentação oficial de thinking do Ollama](https://docs.ollama.com/capabilities/thinking).

As métricas registram o motivo do encerramento (`done_reason`) e a tentativa, conforme o [contrato da API de chat do Ollama](https://docs.ollama.com/api/chat). Esses dados ajudam a distinguir limite de geração, resposta concluída e recuperação.

## Configuração deste notebook

O Qwen3.5 4B continua como modelo principal e o Qwen2.5-Coder 7B como consultor de programação. Nenhum modelo adicional foi baixado nesta atualização. Mantêm-se contexto de 4.096, temperatura de 0,2, modo Cuidadoso e uma geração por vez.

Com raciocínio e ferramentas, o orçamento principal de geração é de até 1.536 tokens para deixar mais espaço aos arquivos e resultados. Sem ferramentas, pode usar até 2.048; o valor também depende da janela escolhida. A revisão tem até 2.048 e não dispõe de ferramentas. Esses são limites técnicos de geração, não uma cota de mensagens.

O Coder 7B ainda exige bastante RAM e pode aumentar o tempo de resposta. Contexto maior, um prompt mais longo ou uma segunda revisão não significam automaticamente mais inteligência. Não foi medido um ganho geral de capacidade nem substituído o treinamento dos modelos.

## Como pedir tarefas

Para implementar um sistema:

```text
No projeto selecionado, implemente uma API de tarefas.
Requisitos: criar, listar, concluir e excluir tarefas; persistência SQLite.
Leia os arquivos existentes, proponha etapas e use o consultor de programação.
Mostre os diffs para aprovação, execute os testes após aprovação e corrija falhas.
No final, informe arquivos alterados, testes realmente executados e pendências.
```

Use **NEXUS CODER + AGENT**. Para instalar aplicativos, use **NEXUS DEVOPS + AGENT**. Para discutir um assunto sem alterar arquivos, use **CHAT** e indique o formato e o nível de detalhe desejados.

## Validação e manutenção

Nesta atualização, **353 testes automatizados e 32 subtestes passaram; um teste foi pulado**. As verificações reais passaram em raciocínio numérico, formato JSON, preservação do pedido longo e leitura de arquivo. O exemplo sobre censura de ficção recebeu os dois argumentos solicitados sem recusa; esse resultado qualitativo permanece identificado como `manual_review`, sem transformar um único exemplo em garantia geral. A revisão final entregou texto nas cinco conversas.

- `reports/testes-respostas-diretas.log`: suíte automatizada, incluindo contexto, recuperação, revisão e regressões das aprovações.
- `reports/respostas-diretas.json`: verificação pequena com o modelo real, incluindo cálculo, formato JSON, pedido longo, tema controverso e leitura de arquivo. Consulte os resultados individuais; o teste de discussão exige revisão humana.
- `nexus/context.py`: seleção e compactação do contexto.
- `nexus/quality.py`: preparação da revisão final.
- `nexus/engine.py`: instruções e recuperação de geração vazia.

Para repetir a verificação com o servidor iniciado e sem outras gerações em andamento:

```powershell
.\.venv\Scripts\python.exe scripts\validar_respostas.py
```

Ela cria conversas de validação no histórico e substitui `reports/respostas-diretas.json`. Recusa qualquer pedido de aprovação; não instala aplicativos nem autoriza comandos ou escrita propostos pelo modelo. Um conjunto pequeno de exemplos não prova inteligência geral nem ausência de recusas em todos os assuntos.

Para abrir, encerrar, adicionar outras IAs e fazer backup, siga o [guia geral](GUIA_DE_USO.md). Para conceder ou revogar pastas, siga [acesso ao PC](PROGRAMACAO_E_ACESSO_PC.md#autorizar-pastas-do-computador).
