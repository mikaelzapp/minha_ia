# Security Center 2.0 — uso, evidências e correção supervisionada

Atualização local de **05/11/2026**. O Security Center 2.0 amplia o NEXUS existente: mantém chat, projetos, memórias, AI Library, Agent Library e o painel de segurança anterior. O perfil **NEXUS UNRESTRICTED — LOCAL** e os controles operacionais existentes foram preservados. Um perfil de resposta não concede permissões de rede, arquivos ou execução.

## Abrir, iniciar e encerrar

1. Abra **Iniciar NEXUS.cmd** na pasta `C:\Users\mikae\Downloads\ia\nexus-ai`.
2. Acesse **http://127.0.0.1:8765**.
3. Clique em **Security Center** e, na navegação do painel, em **Security Center 2.0 ↗**.
4. Use **Dashboard**, **Alvos e escopos**, **Ferramentas**, **Tarefas e eventos** ou um dos dez módulos.

**Painel anterior** retorna às funcionalidades anteriores. **Fechar** encerra somente o diálogo. Para desligar o servidor, use **Parar NEXUS.cmd**; fechar a aba não encerra o NEXUS. Os comandos completos permanecem no [Guia de uso](GUIA_DE_USO.md).

## O que está disponível nesta instalação

Os estados abaixo incluem a instalação portátil autorizada de Nuclei, ZAP, Ghidra e OpenJDK 25. **Instalado**, **configurado** e **validado por execução** são estados diferentes. O [relatório da instalação e dos testes nativos](../reports/SECURITY_RUNTIME_ENTREGA.md) registra o estado atual e as limitações de RAM; a [entrega original 2.0](../reports/SECURITY2_ENTREGA.md) permanece como evidência histórica.

| Módulo | Funcional agora | Limites e dependências |
| --- | --- | --- |
| WEB PENTEST | HEAD HTTP com evidências; Nuclei 3.11.1 validado nativamente no pack local de três templates; ZAP 2.17.0 instalado e configurado por hash | ZAP aguarda RAM para validação nativa. O ensaio Nuclei comprova somente três GETs e suas indicações no laboratório autorizado; não cobre o catálogo geral de CVEs. |
| NETWORK SECURITY | TCP limitado e certificado TLS; adaptador Nmap para serviços | Nmap ausente. Uma porta aberta não confirma serviço, versão ou vulnerabilidade. |
| AUTH & DATABASE SECURITY | SQLi com marcador fictício; matriz A/B, cookies, CORS e logout | Somente laboratório/homologação, contas/registros fictícios e cobertura descrita abaixo. |
| CODE SECURITY | Code Auditor existente, AST Python, padrões e inventário limitado de dependências | Achados estáticos são hipóteses; não há scanner completo de dependências ou fluxo de dados entre todas as funções. |
| MALWARE ANALYSIS | Hashes, formato, entropia, strings, YARA-X e sequência estática com REA | Nenhuma amostra é executada. Correspondência YARA não confirma malware. |
| REVERSE ENGINEERING | REA estático existente; Ghidra 12.2 e OpenJDK 25.0.5+8 portáteis instalados e configurados; visualizador de resultados | A análise nativa Ghidra aguarda RAM. Nenhum pseudocódigo Ghidra foi produzido nesta validação. |
| OSINT & INVESTIGATION | DNS A/AAAA, HEAD, TLS, até cinco subdomínios informados, dorks, pesquisa pública e consulta CVE | Sem enumeração por força bruta, CT, MX/TXT ou descoberta automática de todos os subdomínios. |
| BLUE TEAM | Consultas anteriores de Windows, Defender, processos, conexões, inicialização, tarefas e eventos | Diagnóstico somente leitura, sob as permissões da conta atual; não é monitoramento contínuo. |
| AUTO-REMEDIATION | Seleção de achados, diffs, cópia verificada, branch Git quando disponível, aplicação aprovada, testes e revalidação SQLi/AUTH/Code Auditor | Não aplica automaticamente propostas do modelo, não integra alterações ao original nem publica. |
| REPORT CENTER | Histórico, evidências redigidas, correlação e exportação JSON/Markdown/HTML | PDF depende de `reportlab`, ausente nesta validação. Exclusão de relatório exige aprovação. |

O inventário consulta novamente a disponibilidade. Ferramenta ausente, configuração inválida, bloqueio de escopo e falha de execução aparecem como estados operacionais; não são recusas do modelo nem resultados de auditoria bem sucedidos.

## Cadastrar um alvo autorizado

Abra **Alvos e escopos** e informe nome, domínio/IP, portas, ambiente, hospedagem, finalidade e tipos de teste. O consentimento é explícito. Um exemplo de laboratório usa `127.0.0.1`, porta `8899`, ambiente `lab`, hospedagem própria e testes `appsec_sqli`, `appsec_auth`, `tcp_connect` e `http_headers`.

Os novos testes exigem portas explicitamente cadastradas. A classificação estruturada é `lab`, `staging` ou `production`; SQLi/AUTH e os scanners web externos desta versão aceitam somente laboratório/homologação. Uma descrição contendo “lab” não transforma uma classificação de produção em laboratório.

Domínio autorizado não concede automaticamente acesso a um IP privado resolvido por DNS. As requisições incorporadas validam as respostas DNS e conectam ao IP verificado. URLs com credenciais, fragmentos e escapes ambíguos são rejeitadas. Os adaptadores não seguem redirecionamentos. Escopos podem ser revogados; revisão, permissão e configuração são verificadas novamente antes da execução e durante as operações que suportam essa verificação.

Hospedagem compartilhada, Vercel ou outro provedor exige confirmação de autorização do provedor para testes ativos. Essa declaração não comprova que determinado plano autoriza pentest. Ela também não amplia a cobertura atual: Nuclei/ZAP continuam limitados a HTTP em IP literal local/privado de laboratório. A infraestrutura compartilhada do provedor não faz parte automaticamente do seu alvo.

## Escolher perfil e aprovar uma operação

| Perfil de auditoria | Comportamento |
| --- | --- |
| PASSIVE | Observação delimitada pelo adaptador. Pode enviar HEAD, GET ou conexão TCP; não significa ausência de tráfego. No ZAP utiliza somente regras passivas. |
| SAFE ACTIVE | Interação ativa revisada e limitada. Detecção de versão Nmap e SQLi/AUTH precisam de autorização ativa apropriada. |
| STAGING FULL | Cobertura ativa limitada em laboratório/homologação; não habilita regras destrutivas. No proxy de scanners, amplia o orçamento de 40 para 80 requisições. |

Esses perfis são independentes de **NEXUS PADRÃO / NEXUS UNRESTRICTED — LOCAL** e de **CHAT / PLAN / CODE / AGENT / REVIEW / RESEARCH**. Na interface, SQLi/AUTH exigem perfil ativo e confirmação de dados fictícios; o backend também valida ambiente, escopo e consentimentos.

Selecione mecanismo, escopo, alvo e parâmetros. **Preparar auditoria** produz uma prévia com impacto e limites. **Aprovar esta operação** autoriza somente essa proposta. **Negar** não inicia o adaptador. A aprovação expira em cinco minutos, é consumida uma vez e fica vinculada à configuração e ao escopo. Uma alteração exige preparar novamente.

Em **Tarefas e eventos**, acompanhe fila, execução, eventos, resultado e recursos. A interface consulta o histórico enquanto há tarefas ativas; percentuais de progresso não são inventados. **Interromper tarefa** pede cancelamento cooperativo e não desfaz conexões, gravações ou efeitos já concluídos. Reinício do servidor marca tarefas não concluídas como `interrupted`, sem atribuir sucesso.

## Configurar Nuclei, ZAP, Nmap ou Ghidra

Abra **Ferramentas**. A detecção não executa programas encontrados. Configure caminhos absolutos para uma distribuição que você já instalou e revisou, depois clique em **Revisar configuração e hash** e confira a aprovação.

O hash observado identifica os bytes de pontos de entrada e permite detectar alterações posteriores. Ele **não autentica o fornecedor, a assinatura ou todas as dependências da instalação**. A execução também verifica o contrato/versão suportados. Nuclei usa contrato 3.x, ZAP 2.x e Nmap 7.x; versões incompatíveis geram falha técnica.

Após autorização explícita, foram instalados **Nuclei 3.11.1**, **ZAP 2.17.0 Crossplatform**, **Ghidra 12.2** e **Eclipse Temurin OpenJDK 25.0.5+8**. Os arquivos vieram das releases oficiais com tamanho/SHA-256 fixados, em subpastas de `data/security/tools`. O Java global, PATH, serviços, Defender, firewall e UAC foram preservados. Os caminhos/hashes foram aprovados pela API humana de configuração. Cada auditoria continua exigindo sua própria prévia e aprovação.

Em outra instalação, o botão **Revisar instalação portátil do Nuclei (46 MB)** apresenta a versão fixa, fonte oficial, tamanho, integridade e destino. Somente a aprovação explícita inicia o download, acompanhado em **Tarefas e eventos**, com cancelamento e limites. Instalar não configura nem inicia o scanner: preencha o caminho instalado no formulário e aprove separadamente **Revisar configuração e hash** antes de executar uma auditoria.

O pacote previsto é **Nuclei 3.11.1, Windows AMD64**, com ZIP de **46.067.128 bytes**. A referência fixada do arquivo é SHA-256 `bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2`. A transferência apresenta os bytes efetivamente recebidos; o arquivo verificado é extraído de forma limitada em `data/security/tools/nuclei/3.11.1`. O hash observado do executável é separado do hash do ZIP. Instalação não verifica a versão executando o programa, não altera PATH e não dispensa a aprovação da configuração.

ZAP, Ghidra e JDK possuem o instalador de manutenção `scripts/install_security_runtime.py`, com pacotes fixados e extração limitada. A chamada sem opções de instalação apenas verifica o inventário local e os hashes dos arquivos; não acessa a rede nem inicia Java. Downloads precisam das opções explícitas `--install --authorized-download` e de autorização prévia. Nmap permanece opcional e não foi baixado. Não há atualização silenciosa nem instalador genérico que aceite URLs/comandos livres. Não é necessário baixar outro modelo Ollama para usar os especialistas de segurança.

```powershell
.\.venv\Scripts\python.exe scripts\install_security_runtime.py java ghidra zap
```

Os caminhos desta instalação e a reprodução dos testes estão no [relatório atual](../reports/SECURITY_RUNTIME_ENTREGA.md). Guarde os diretórios portáteis separadamente se desejar incluí-los no backup: `nexus.setup --backup` não copia essas instalações.

### Nuclei

Há três templates locais revisados, versionados e identificados por SHA-256: `nexus-http-baseline`, `nexus-exposed-openapi` e `nexus-lab-synthetic-exposure`. Eles verificam resposta HTTP, documento OpenAPI legível e marcador fictício do laboratório. **Esse catálogo não é uma base geral de CVEs.** Templates externos, código arbitrário, OAST/cloud e atualização automática não são aceitos.

A saída JSONL preserva identificador do template, severidade, referências e evidência resumida/redigida. Uma correspondência de exposição requer contexto; resultado vazio significa “nenhum achado nesta cobertura”. A instalação e a configuração atuais estão registradas no [relatório de runtime](../reports/SECURITY_RUNTIME_ENTREGA.md), que separa os ensaios nativos dos testes com saídas instrumentadas.

O [ensaio Nuclei real](../reports/security-runtime-nuclei-real.json) verificou a versão 3.11.1 por processo, executou os três templates no servidor de loopback do próprio ensaio e persistiu três indicações. O proxy observou exatamente três GETs; uma aprovação negada não gerou tráfego. O escopo temporário foi revogado. Essa evidência é por tarefa: a descoberta em **Ferramentas** não executa o binário e pode continuar exibindo versão não verificada nesse inventário.

### OWASP ZAP

O adaptador gera um plano Automation Framework com Requestor, regras passivas e, quando aprovado, regras ativas revisadas de XSS refletido e SQLi. Aceita caminhos explícitos e um documento OpenAPI fornecido como objeto JSON. A extração é limitada a GET/HEAD em caminhos literais; não preenche parâmetros de consulta/corpo e ignora caminhos que exigem substituição de parâmetros. Não segue `$ref` remoto, não busca servidores externos e não faz spider, login automático ou importação completa de todos os fluxos de uma API.

O proxy de cada execução limita origem/caminho, métodos, taxa, resposta e quantidade de requisições. HTTPS e alvos públicos/domínios ficam indisponíveis nesse adaptador até existir isolamento de saída compatível; não é instalado certificado local para contornar esse limite. ZAP 2.17.0 e seus addons estão instalados, mas sua execução nativa ainda aguarda a margem de RAM exigida. A presença dos addons não comprova que o plano AF foi executado.

### Nmap e rede

O TCP incorporado continua funcionando sem Nmap, com até oito portas. Nmap usa conexões TCP e, mediante autorização ativa, `-sV --version-light`. O padrão permite até oito portas; `expanded_ports_approved:true` permite até 64 portas explicitamente presentes no escopo. Não há NSE, UDP, detecção de SO, evasão, exploração automática ou varredura indiscriminada.

A tabela diferencia host, porta, protocolo, estado, serviço/versão comprovados, risco/recomendação e evidência. Serviço inferido somente pelo número da porta permanece não comprovado. Consulta de CVE é uma referência técnica; não confirma que o serviço identificado está vulnerável.

### Ghidra e REA

Configure `install_dir` da distribuição Ghidra e `java_home` de JDK compatível. O adaptador usa análise headless e o exportador local `integrations/ghidra/NexusExport.java`, sem scripts livres ou execução da amostra. Aceita amostras cadastradas PE/ELF/Mach-O, registra arquitetura/formato, imports, exports, entradas, funções, referências, strings e pseudocódigo quando o decompilador efetivamente o produzir.

Há limites de 10 MiB por entrada, 180 segundos por padrão, 100 funções, 300 strings e 500 referências. Os limites configuráveis continuam sujeitos aos tetos do adaptador. Ghidra ausente ou parser REA básico não são apresentados como decompilação profunda. O visualizador mostra a origem das funções e do pseudocódigo.

Diretório, perfil privado e processo com orçamento **não são uma VM nem sandbox do Windows**. A execução estática do parser requer ciência e aprovação específicas. Entradas hostis devem ser tratadas em infraestrutura isolada apropriada. A análise dinâmica de executáveis permanece desabilitada: não há VM com snapshots e isolamento verificados. Defender, firewall, UAC e outras proteções não são desativados.

## SQLi e autenticação: cobertura real

Veja o [guia AppSec](SECURITY_APPSEC.md) para a fixture completa e os contratos Python. Os nomes, senhas, recursos e marcadores preparados usam o prefixo `NEXUS_LAB_`; não use credenciais ou dados de clientes.

SQLi envia seis GETs: referência, valor com aspas e pares `AND` verdadeiro/falso repetidos. A confirmação exige o marcador sintético na referência e nos controles verdadeiros, ausente nos falsos, com respostas válidas. Não usa expansão `OR`, `UNION`, temporização, enumeração de tabelas ou escrita. Um erro com aspas é somente indício. Referência não comprovada é `inconclusive`; não conta como correção demonstrada.

AUTH usa até doze requisições para acesso anônimo, login A/B, acesso próprio e cruzado, origem CORS não confiável, atributos de cookies, logout e reutilização da sessão antiga. Login e recurso próprio precisam ser comprovados antes de confirmar BOLA. Os relatórios guardam endpoints, status, presença de marcadores e atributos; omitem senhas, valores de cookies/tokens e corpos HTTP.

O módulo não cobre completamente CSRF, recuperação de senha, enumeração de contas, expiração temporal de tokens, armazenamento/hash de senhas ou separação administrador/usuário. Essas lacunas aparecem em `not_tested`. O cliente HTTP não reproduz todas as regras de cookies do navegador; o laboratório HTTP não valida a exigência `Secure` de produção.

## Correção supervisionada de um achado

1. Execute a auditoria e abra o relatório concluído no **Report Center**.
2. Selecione os achados e o projeto cadastrado. Clique em **Deseja que o NEXUS prepare as correções selecionadas?**.
3. Informe arquivo relativo e conteúdo completo proposto. Para vários arquivos ou comandos de teste, use os parâmetros JSON avançados. O consultor local pode revisar uma proposta; não lê o projeto automaticamente nem aplica sua saída.
4. **Preparar plano e diffs** mostra achados, alterações, cópia e testes previstos. A primeira aprovação cria uma cópia verificada e uma branch Git local quando Git estiver disponível. Nenhum arquivo original é modificado.
5. Abra o plano e clique em **Revisar aprovação de escrita**. A segunda aprovação escreve somente os diffs na cópia e executa as verificações de sintaxe e os comandos de teste explicitamente autorizados.
6. Inicie manualmente a aplicação corrigida da cópia em uma porta autorizada de laboratório/homologação.
7. Informe esse escopo/alvo em **Revisar testes e revalidação**, confira a prévia e aprove a nova auditoria.
8. Consulte a comparação: ausente na cobertura revalidada, ainda presente ou inconclusivo. Teste de referência ausente, regressão falha ou sessão não comprovada não confirma resolução.

Nesta versão, as alterações precisam atingir arquivos existentes, com conteúdo UTF-8 e diffs não vazios; são até dez arquivos, cópia de até mil arquivos/20 MiB. Pastas de dependências, credenciais, arquivos sensíveis e bancos são omitidos da cópia. Testes do projeto executam código com sua conta, mesmo dentro de uma cópia. Não há isolamento de sistema operacional.

O consultor Qwen2.5-Coder 7B funciona localmente e em sequência com as demais operações. A API aceita contexto de até 4.000 caracteres e tarefa de até 2.000, com limite conjunto de 5.000. A interface envia no máximo os primeiros 3.500 caracteres do contexto exibido e informa o truncamento. A proposta exige revisão; nenhuma inferência do Coder foi necessária para os testes de integração desta expansão.

A revalidação dinâmica integrada é SQLi/AUTH. Há também revalidação estática do Code Auditor diretamente na cópia, sem iniciar um servidor. Para os demais mecanismos, reexecute o adaptador separadamente e compare/correlacione os relatórios. Integrar a branch ao projeto original, fazer merge e publicar continuam sendo ações separadas; **não existe deploy automático**.

### Demonstração real incluída

O [ensaio de integração](../reports/security2-integration.json) confirmou SQLi no laboratório fictício, preparou uma cópia em branch e aplicou um patch real em `queries.py`: concatenação SQL foi substituída por consulta parametrizada. Dois testes unitários aprovados passaram e a revalidação HTTP deixou de confirmar SQLi na cópia. O servidor e o arquivo originais continuaram vulneráveis no laboratório, comprovando a preservação dos originais.

`scripts/security_lab.py --root CAMINHO --port PORTA` aceita nesse laboratório somente os bytes/SHA-256 de duas implementações SQL fictícias conhecidas. Código desconhecido é recusado; isso não é um carregador genérico de projetos. `settings.json` controla separadamente as fixtures de autenticação/sessão. O exemplo de `{"fixed":true}` da interface é apenas uma configuração didática; não substitui uma correção específica de código.

## Especialistas e chat

Foram acrescentados dez especialistas configuráveis em `profiles/security_specialists.json`: Security Orchestrator, Web Auditor, Network Analyst, Auth Auditor, Database Auditor, Malware Analyst, Reverse Engineer, OSINT Analyst, Remediation Engineer e Report Analyst. Os agentes anteriores são preservados. Vários especialistas podem usar o mesmo modelo principal; não é carregado um modelo por agente.

O chat consulta capacidades por `security_workbench`. Em modo operacional **AGENT**, `security_audit_v2` pode propor uma auditoria permitida, vinculada ao digest atual da configuração e à aprovação humana. O modelo não cria escopos, não configura executáveis nem aprova sua própria execução. A interface pode ser usada independentemente da orquestração do chat. Os contratos estão na [API 2.0](SECURITY2_API.md).

## Relatórios, retenção e recursos

Relatórios registram escopo, alvo/projeto quando informado, data, duração, mecanismos efetivos, configuração, achados, evidências, cobertura e limitações. Correlação usa fraqueza, local e parâmetro; uma pista semelhante em locais desconhecidos não é fundida automaticamente. Não há garantia de unificar todo resultado semanticamente equivalente entre motores.

JSON, HTML e Markdown estão disponíveis. HTML é escapado e exportado sem recursos externos. PDF textual é opcional e fica oculto enquanto `reportlab` não estiver instalado. Não houve instalação dessa dependência.

A retenção é supervisionada, com recomendação exibida de 30 dias. Em **Report Center**, escolha a data UTC e clique em **Revisar limpeza por data**. A prévia lista somente tarefas 2.0 em estado final anteriores ao corte e seus relatórios elegíveis; a decisão humana confirma a remoção. Tarefas ativas, evidências usadas por planos, registros do painel anterior, arquivos, amostras, branches e backups são preservados. Não há exclusão automática pelo calendário.

**Revisar exclusão deste relatório** remove o relatório aprovado e limpa a cópia do resultado da tarefa associada, mantendo seus metadados. Planos, arquivos e backups ainda podem conter evidências relacionadas; a exclusão não é apagamento forense. Novas tarefas são bloqueadas ao atingir 500 execuções ou banco de 256 MiB; o histórico lista até cem execuções recentes. Exporte e revise a limpeza disponível antes de fazer manutenção manual do banco.

O executor compartilha uma única vaga com inferência, tem fila de até quatro tarefas e registra RAM antes/depois. ZAP e Ghidra exigem pelo menos 3 GiB livres na verificação geral, além dos controles próprios. Scanners possuem timeout, saída limitada, monitoramento de RSS e encerramento de processos. Monitoramento de memória e diretório privado não oferecem uma garantia rígida de isolamento. Em falta de RAM, descarregue modelos pela AI Library ou feche aplicativos e prepare novamente; o NEXUS não encerra aplicativos pessoais para liberar recursos.

## Backup e restauração

Antes das alterações foi criado o [backup inicial verificável](../reports/backup-security2-20261105-033342/manifest.json): 154 arquivos, seis bancos SQLite consistentes e manifestos SHA-256. O [estado inicial](../reports/security2-initial-state.json) registra os cinco modelos e a suíte de referência de 949 testes aprovados/3 ignorados. Modelos, ambiente virtual e caches não foram duplicados.

Para um novo backup de dados/configurações, use uma pasta nova dentro do projeto:

```powershell
.\.venv\Scripts\python.exe -m nexus.setup --backup reports\backup-security2-manual
```

O comando inclui os seis bancos SQLite; o banco de segurança contém também as tabelas de tarefas, ativos e planos 2.0. Inclui amostras, `security/modules.json` quando existir, jobs da AI Library, configurações, perfis e lock de dependências. **Não é uma cópia completa do código, workspaces, branches de correção, instalações de ferramentas, ambiente virtual ou pesos Ollama.** O banco pode referenciar arquivos de uma cópia que não foi incluída nesse backup.

Para retornar ao estado anterior da aplicação, use o backup inicial e seu manifesto para restaurar os arquivos e bancos selecionados, com o servidor encerrado e uma cópia separada do estado atual. Não sobrescreva o projeto inteiro indiscriminadamente nem remova modelos. A restauração não é automatizada pelo botão de exclusão de relatórios. As branches e instalações externas devem ser copiadas separadamente quando forem necessárias à recuperação.

## Evidências de validação e pendências

| Evidência | O que comprova |
| --- | --- |
| [Integração nativa: 16 cenários aprovados](../reports/security2-integration.json) | API autenticada, SQLi, AUTH/BOLA/sessão, TCP, aprovação negada, revogação, escopo, cancelamento de fila, exportação, cópia/branch, patch SQL real, testes, revalidação HTTP e estática, ciclo do Code Auditor, ponte aprovada de especialistas e correlação. Sem acesso público, downloads ou inferência. |
| [AppSec nativo](../reports/security2-appsec-runtime.json) | HTTP/SQLite de laboratório, comportamento vulnerável e corrigido. |
| [Interface: 15 cenários com fixtures](../reports/security2-ui-fixture.json) | Formulários, aprovações, prévias negadas de instalação/retenção, progresso por bytes informados, cancelamento, seleção/diffs, visualizadores Ghidra/rede e telas móveis com APIs interceptadas. Não executa motores externos, downloads ou exclusões reais. |
| [Interface real somente leitura](../reports/security2-ui-live.json) | Inventário real, dez módulos, relatórios, formatos disponíveis e preservação do painel/chat em desktop e 390/320 px. Não aprova tarefas, baixa ferramentas ou carrega modelos. |
| [Instalação portátil e validação atual dos motores](../reports/SECURITY_RUNTIME_ENTREGA.md) | Downloads autorizados, integridade dos arquivos, configuração aprovada, tentativas nativas e impedimentos reais de memória. Não altera os relatórios históricos acima. |

A suíte automatizada e os detalhes da expansão estão no [relatório original](../reports/SECURITY2_ENTREGA.md); os resultados da instalação posterior estão no [relatório de runtime](../reports/SECURITY_RUNTIME_ENTREGA.md). ZAP/Ghidra ainda precisam de validação nativa com RAM suficiente e Nmap continua ausente. Não foram produzidos resultados de CVEs gerais por Nuclei, pentest completo ZAP ou decompilação Ghidra nesta máquina. Também permanecem pendentes VM dinâmica, cobertura completa de autenticação, descoberta ampla de ativos e remediação automática genérica de projetos reais.
