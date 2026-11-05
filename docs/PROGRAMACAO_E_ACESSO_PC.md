# Programação, qualidade e acesso ao computador

Atualização de 05/11/2026 para a instalação em `C:\Users\mikae\Downloads\ia\nexus-ai`.

Veja também [Respostas diretas e melhorias de qualidade](RESPOSTAS_E_QUALIDADE.md) para as correções posteriores de contexto e revisão, o comportamento em temas controversos e os resultados de validação.

**Perfis de conversa:** consulte [NEXUS UNRESTRICTED — LOCAL](PERFIS_LOCAIS.md). Ele mantém as permissões do PC deste guia e entrega a resposta original, sem a revisão automática do perfil padrão.

## O que foi adicionado

- **Qwen2.5-Coder 7B Q4_K_M**, aproximadamente 4,7 GB, instalado localmente com sua autorização.
- Ferramenta **consult_coder**, para consultar o especialista sobre código sem executar suas propostas.
- Qualidade **Cuidadoso**, com uma revisão adicional da resposta antes da entrega.
- Ferramentas para consultar o computador e o catálogo oficial WinGet, propor instalações e trabalhar em pastas que você autorizar.
- Controles para ativar/desativar acesso e autorizar/revogar pastas na interface.

O Qwen3.5 4B continua responsável pelas ferramentas e aprovações. O Coder 7B gera propostas e revisa respostas de programação. Os testes reais mostraram que o 7B devolveu JSON de ferramenta como texto, sem gerar chamadas nativas válidas. O NEXUS não converte esse texto em comandos: as operações continuam passando pelo modelo e pelo executor já preparados para isso.

## Como abrir

Abra **Iniciar NEXUS.cmd** na pasta principal ou execute nela:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\iniciar.ps1 -Abrir
```

Acesse **http://127.0.0.1:8765**. Para fechar o servidor, use **Parar NEXUS.cmd**. Fechar apenas a aba não encerra o servidor.

## Pedir programação

1. Coloque seu projeto em `workspaces`, registre-o e indexe-o em **Projetos**.
2. Selecione o projeto e o agente **NEXUS CODER**.
3. Use **PLAN** para estudar, **CODE** para propor alterações ou **AGENT** para implementar e testar por etapas.
4. Descreva os requisitos e o resultado que espera.
5. Revise o diff e os comandos apresentados antes de aprovar.

Exemplo:

```text
Use o especialista de programação para propor uma API de tarefas em Python.
Primeiro leia o projeto, explique as dependências e proponha a estrutura.
Depois crie os arquivos com diffs e solicite a execução dos testes.
Não publique nada na internet.
```

Para uma segunda opinião sobre código:

```text
Leia o arquivo indicado e use consult_coder para revisar o tratamento de erros.
Mostre problemas concretos e uma proposta de correção antes de alterar.
```

O consultor recebe somente a tarefa e os trechos que o orquestrador fornecer, usando inferência local. Ele não abre arquivos nem executa comandos por conta própria. O orquestrador deve ler os arquivos relevantes, revisar a proposta, solicitar a aprovação de escrita e testar a implementação.

### Qualidade das respostas

Abra **Configurações → Qualidade das respostas**:

| Opção | Comportamento |
| --- | --- |
| **Cuidadoso** | Prepara uma proposta e faz revisão adicional. Em CODE/AGENT/REVIEW com Coder, Debugger ou Database, o especialista configurado participa da revisão final sem ferramentas. |
| **Equilibrado** | Entrega a resposta sem a revisão adicional automática. O consultor ainda pode ser usado como ferramenta. |

O modo Cuidadoso prioriza coerência, requisitos, código e evidências. Ele aumenta a latência. Uma revisão de modelo não substitui testes de software, verificação de cálculos ou conferência das fontes. Nenhuma configuração garante sempre a melhor resposta.

As respostas devem distinguir proposta de execução e não declarar um teste, arquivo ou instalação como concluído sem resultado de ferramenta. Sugestões novas na revisão final não são aplicadas automaticamente aos arquivos: podem exigir outro ciclo de edição e aprovação.

O modelo padrão continua sendo o Qwen3.5 4B. A opção **IA de programação** configura o consultor, sem substituir o controlador de ferramentas. Se selecionar diretamente o consultor como modelo de conversa, use CHAT; em modos com ferramentas, o NEXUS preserva o modelo principal para a execução.

### Recursos medidos

O Coder 7B passou em geração e correção de uma função Python, com três verificações executadas em cada caso. Mediu aproximadamente **20–25 tokens/s** nos testes desta sessão, com parte do modelo na GPU e parte na CPU. A RAM total do computador chegou perto de **99%** no teste, incluindo outros programas.

Por isso, a configuração usa contexto de **4.096**, temperatura **0,2**, uma geração por vez e descarga do especialista ao terminar. As trocas entre modelos podem demorar. Feche aplicativos desnecessários se houver paginação; escolha Equilibrado se priorizar tempo de resposta.

O Qwen3.5 usa o controle de raciocínio quando compatível. O Coder instalado não anuncia `thinking`; o NEXUS não força esse recurso nele. Modelos remotos/cloud são bloqueados para evitar enviar contexto privado a inferência externa.

## Autorizar pastas do computador

1. Abra **Configurações → Acesso ao computador**.
2. Confira se **Permitir ferramentas no meu computador** está ativo.
3. Digite o caminho completo de uma pasta de projeto existente, por exemplo `C:\Projetos\MeuSistema`.
4. Clique em **Autorizar pasta**.
5. No chat, diga qual pasta autorizada deseja usar. O agente consulta `computer_info` para obter os identificadores disponíveis.

Exemplo:

```text
Consulte computer_info e leia os arquivos da pasta autorizada MeuSistema.
Prepare um plano para corrigir os testes, sem alterar nada ainda.
```

O NEXUS oferece listagem, leitura, escrita com diff e execução de comandos nas pastas concedidas. Para usar os controles de PC, mencione o computador, a pasta autorizada ou seu caminho no pedido. A pasta `workspaces` continua funcionando pelas ferramentas habituais, independentemente dos grants extras.

Uma autorização de pasta não adiciona automaticamente esse projeto ao índice de memória: o gerenciador de Projetos continua restrito a `workspaces` nesta versão.

### Revogar acesso

Na mesma seção, clique em **Revogar** ao lado da pasta. Você também pode desativar o acesso ao computador por completo. A execução revalida as permissões atuais; uma aprovação pendente não restaura uma pasta revogada. Operações que já começaram não são desfeitas pela revogação.

São bloqueados perfil inteiro, raiz de disco, pastas do sistema, credenciais conhecidas, links/junctions e grants que incluam os dados internos do NEXUS. Escolha pastas específicas de projetos.

Os controles limitam as ferramentas de arquivo e o diretório de execução. **Um programa aprovado roda com as permissões da sua conta do Windows; isso não equivale a uma sandbox do sistema operacional.** O NEXUS não guarda senha de administrador nem confirma UAC por você.

## Instalar aplicativos

Use **AGENT + NEXUS DEVOPS**. Exemplo de pedido:

```text
Pesquise o aplicativo desejado no catálogo oficial WinGet.
Confira se já está instalado e consulte a versão, fornecedor e licença.
Prepare a instalação para meu usuário e mostre o comando para aprovação.
```

O fluxo é:

1. Consultar o computador, procurar o pacote em `search_apps` e conferir a instalação existente com `list_apps` pelo ID exato.
2. Consultar `app_details` para revisar os metadados e identificar uma versão.
3. Propor `install_app` com **ID e versão exatos** e escopo definido.
4. Exibir pacote, fornecedor, licença, detalhes completos e comando.
5. Aguardar sua aprovação na interface.
6. Executar pelo WinGet e conferir a saída real.

O escopo padrão é `user`. Quando um pacote só aceita `machine`, isso precisa ser apresentado e aprovado, e o Windows pode exigir UAC. Alguns pacotes ou políticas locais podem impedir a instalação.

A aprovação inclui os termos do pacote mostrados no cartão. O sistema não aceita automaticamente novos termos da fonte WinGet, não eleva privilégios e não ignora verificações de integridade. A URL e o tipo da fonte são conferidos para usar o catálogo oficial; isso não é garantia de ausência de defeitos em todo aplicativo publicado.

Nesta atualização foram testadas consultas reais ao catálogo e os fluxos de aprovação/recusa com instalador simulado. **Nenhum aplicativo de terceiros foi instalado como teste**, pois você ainda não escolheu um programa concreto. Um cartão aprovado também não prova sucesso: é preciso examinar o código de saída e a mensagem do instalador.

### Se o WinGet falhar

Confira no PowerShell:

```powershell
winget --version
winget source export --name winget --disable-interactivity
```

Se estiver ausente ou inacessível, verifique o **Instalador de Aplicativo** no Windows/Microsoft Store. Se houver termos da fonte pendentes, leia e decida no próprio WinGet. O NEXUS informa o bloqueio, sem aceitar termos ou alterar a fonte silenciosamente.

## VS Code

Abra o perfil NEXUS:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\vscode.ps1
```

O Continue mantém permissões e histórico próprios. A configuração inclui o Coder 7B para propostas e edição; prefira o Qwen3.5 para Agent com chamadas nativas de ferramentas. Essa atualização não certifica execução de instalações dentro da janela do Continue.

## Manutenção e dados

| Configuração | Local |
| --- | --- |
| Modelo, consultor e qualidade | `data/config.json` |
| Pastas autorizadas | `data/computer-access.json` |
| Histórico e índice | `data/memory.sqlite3` |
| Auditoria | `data/activity.sqlite3` |
| Código do módulo PC | `nexus/computer.py` |
| Consultor de programação | `nexus/coding.py` |

O backup por `python -m nexus.setup --backup ...` agora inclui `computer-access.json`, além dos bancos, configuração e lock. Projetos e pesos do Ollama continuam exigindo proteção separada.

Para reproduzir o download do consultor em outra instalação, após conferir o espaço necessário:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\instalar.ps1 -BaixarCoder
```

Para ajustar os novos recursos pela linha de comando, pare o servidor, execute e depois inicie novamente:

```powershell
.\.venv\Scripts\python.exe -m nexus.setup --coding-model qwen2.5-coder:7b --quality-mode careful --computer-access --context 4096 --temperature 0.2
```

Esse comando configura o NEXUS; não baixa pesos, não autoriza pastas extras nem instala aplicativos.

## Evidências da atualização

O ciclo real pelo chat passou: consultar o especialista, aprovar o diff, criar `workspaces/validacao-coder/sistema_demo.py`, aprovar a execução dos asserts e revisar o resultado com o Coder 7B. A leitura da pasta autorizada e a consulta ao catálogo também passaram. A autorização temporária de teste foi revogada; nenhuma pasta extra ficou concedida.

A suíte automatizada terminou com **305 testes aprovados, 32 subtestes aprovados e um teste pulado** por limitação de criação de symlink no Windows. A interface viva foi conferida no Chromium sem alterar configurações: consultor selecionado, qualidade Cuidadoso e acesso ao PC ativo.

- `reports/coder-pc.json`: geração/correção e incompatibilidade de chamadas nativas do especialista; consulta real ao WinGet.
- `reports/integracao-coder-pc.json`: ciclo completo pelo agente principal e pelo consultor, com os resultados reais das ferramentas.
- `reports/inventario-apps.json`: consulta real a um aplicativo já instalado, sem instalação ou atualização.
- `reports/testes-coder-pc.log`: testes automatizados da atualização.
- `reports/computer-ui.json`: interface testada em Chromium com respostas simuladas, sem instalação real.
- `reports/computer-ui-live.json` e `reports/computer-ui-live.png`: verificação somente de leitura da interface conectada ao servidor real.
- `reports/backup-coder-pc-20261105`: backup anterior às alterações.

O [guia geral](GUIA_DE_USO.md) continua cobrindo início, encerramento, projetos, memória e manutenção.

Referências: [Qwen2.5-Coder 7B](https://ollama.com/library/qwen2.5-coder:7b), [instalação WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget/install), [consulta WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget/show).
