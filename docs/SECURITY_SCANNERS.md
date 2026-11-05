# Scanners opcionais — Nuclei, OWASP ZAP e Nmap

O adaptador `nexus/security/scanners.py` executa ferramentas locais quando a instalação, os bytes, o escopo e a operação foram explicitamente aprovados. Não instala programas, não atualiza regras e não transforma ferramentas ausentes em resultados fictícios. O adaptador TCP e o Nmap básico anteriores continuam disponíveis pelos fluxos existentes.

## Situação e cobertura

| Motor | Implementação | Cobertura do contrato |
| --- | --- | --- |
| Nuclei 3.x | Adaptador real de processo e JSONL | Três templates HTTP GET locais revisados: resposta HTTP, documento OpenAPI legível e marcador sintético de exposição do laboratório. Sem templates arbitrários ou cobertura geral de CVEs. |
| OWASP ZAP 2.x | Plano estruturado do Automation Framework, processo Java e relatório JSON | Endpoints HTTP explícitos ou GET/HEAD literais extraídos de OpenAPI JSON local, com regras passivas. Níveis ativos têm apenas XSS refletido `40012` e SQLi `40018`, em baixa intensidade. Sem spider, browser, login automático ou importação remota de OpenAPI. |
| Nmap 7.x | Processo e parser XML | Um ativo individual, TCP connect; até oito portas por padrão. Detecção `-sV --version-light` somente após selecionar nível ativo. Até 64 portas exige a aprovação adicional refletida no preview. |

Implementação do adaptador não equivale a validação com o binário real. A evidência de integração produzida para a entrega identifica separadamente motores instalados e executados. A suíte deste módulo usa saídas de scanner controladas; ela também exercita processos Python inofensivos e um proxy HTTP real sobre loopback. Nenhum teste automatizado necessita de sites públicos.

Nesta instalação, **Nuclei 3.11.1 e ZAP 2.17.0 estão instalados e configurados por caminhos/hashes aprovados**, com OpenJDK 25.0.5+8 portátil para o ZAP. Nmap permanece ausente. Consulte o [relatório atual de instalação e execução](../reports/SECURITY_RUNTIME_ENTREGA.md): disponibilidade por arquivo/metadados não equivale a versão verificada por processo nem a auditoria concluída. O teste nativo ZAP foi interrompido pela guarda de RAM antes de iniciar Java.

O [ensaio Nuclei nativo](../reports/security-runtime-nuclei-real.json) passou: versão 3.11.1 verificada, três templates locais, três GETs observados no proxy e três indicações esperadas do laboratório; relatório persistido e escopo temporário revogado. A prévia negada gerou zero requisições. A descoberta continua sem executar ferramentas: a prova da versão por processo pertence ao resultado daquela tarefa, não a uma promessa de validação permanente de todo o catálogo.

Um resultado vazio é **nenhum achado nesta cobertura**, nunca garantia de segurança. A exposição intencional de um documento OpenAPI não é, por si só, vulnerabilidade. Um marcador fictício confirma apenas a regra do laboratório.

## Escopo e aprovação

O integrador chama `ScannerAdapters(data_dir, config=None)` e usa:

```python
adapters.inventory()  # somente descoberta; não executa o PATH
adapters.templates()  # IDs, versão, hash e cobertura do pack revisado
preview = adapters.preview(engine, scope, args)
# A interface obtém aprovação humana vinculada ao preview e à revisão do escopo.
result = adapters.run(engine, scope, preview["args"], cancel_event=event,
                      emit=progress, scope_loader=lambda: store.scope(scope_id))
```

`engine` aceita `nuclei`, `zap` ou `nmap_service`, que também precisam constar em `allowed_tests` do escopo. Todas as portas solicitadas precisam estar explicitamente cadastradas em `allowed_ports`. `scope_loader()` deve consultar o estado atual, sem cache de uma autorização revogada. O adaptador verifica a revisão antes do processo, periodicamente e antes de aceitar o resultado.

Argumentos aceitos: `target`, `level`, `duration_seconds`, `rate_limit`; Nuclei também aceita `templates`; Nmap aceita `ports`, `service_detection` e `expanded_ports_approved`; ZAP aceita `endpoints` e `openapi`. Campos de comando, argumentos livres, planos externos ou URLs de templates são rejeitados. O preview declara efeito, cobertura, limites, revisão e hash da configuração.

### Descoberta limitada e OpenAPI local no ZAP

`endpoints` é uma lista de até dez caminhos literais iniciados por `/`, pertencentes à origem e ao caminho base aprovados. Por exemplo, alvo `http://127.0.0.1:8080/api/` permite `/api/health`, e rejeita `/admin`, URLs absolutas, consultas, fragmentos e segmentos ambíguos.

`openapi` aceita um objeto JSON local já analisado, de até **128 KiB**, OpenAPI 3.x ou Swagger 2.0. O NEXUS deriva até dez operações GET/HEAD sem parâmetros no path e gera requests explícitos do job `requestor`. Não utiliza o job importador OpenAPI do ZAP, não busca uma definição por URL, não resolve schemas e não envia exemplos, corpos, definições de autenticação ou valores de parâmetros ao motor.

`servers`, `callbacks`, `webhooks`, autoridade Swagger alternativa e `$ref` externo são recusados. Referências locais `#/...` podem constar no documento, mas não são resolvidas. POST/PUT/PATCH/DELETE e paths como `/users/{id}` são registrados como fora da cobertura; o sistema não inventa IDs nem altera registros. Há no máximo 21 requisições iniciais: alvo base, dez endpoints e dez operações do documento, antes da deduplicação. O orçamento global de 40/80 requisições também engloba os probes ativos.

O preview e o relatório incluem contagem, caminhos/métodos derivados, operações ignoradas, tamanho, versão e hash da especificação. O documento original e seus exemplos não são copiados para a configuração persistida no resultado nem para o plano AF. Este recurso é descoberta por inventário explícito; não representa crawl completo de formulários, autenticação ou validação de todos os contratos de API.

```json
{
  "target": "http://127.0.0.1:8080/",
  "level": "PASSIVE",
  "endpoints": ["/health"],
  "openapi": {"openapi": "3.0.3", "paths": {"/metadata": {"head": {}}}}
}
```

Nuclei/ZAP estão limitados a **HTTP, IP literal local/privado e ambiente de laboratório/homologação** nesta versão. A classificação estruturada `environment_class` deve ser `lab` ou `staging`; quando ausente, o nome do ambiente precisa ser exatamente `lab`, `laboratório`, `laboratorio`, `laboratory`, `staging`, `homologação` ou `homologacao`. Um domínio, HTTPS ou produção retorna `isolation_requirement`/`environment_not_allowed`. Isso evita anunciar proteção contra rebinding que um scanner externo sem isolamento de rede não oferece. O Nmap conecta somente ao IP resolvido e verificado pelo ScopePolicy, sem resolver novamente pelo próprio scanner.

## Três níveis

- **PASSIVE:** ZAP envia GET/HEAD aos endpoints aprovados e analisa passivamente essas respostas. Nuclei ainda envia seus GETs de templates, e o Nmap ainda realiza conexões TCP; a interface deve informar esse tráfego, pois não é captura passiva de pacotes.
- **SAFE ACTIVE:** ZAP habilita somente as duas regras revisadas, força baixa intensidade, uma thread, atraso por requisição e um minuto de scan. A detecção de serviços Nmap pode ser autorizada neste nível.
- **STAGING FULL:** continua restrito a laboratório/homologação. Amplia o orçamento a 80 requisições e dois minutos do job ativo; **não** habilita todo o catálogo ZAP nem regras destrutivas. O nome do nível não significa pentest completo.

O contrato inicial não aceita cookies, senhas, cabeçalhos de autenticação ou contas reais. Auditorias entre contas fictícias usam o módulo específico de aplicações. Nenhum dado privado é enviado a nuvem, OAST ou marketplace por este adaptador.

## Guardas de rede e recursos

Cada execução Nuclei/ZAP recebe um proxy HTTP próprio em loopback, com destino fixo ao IP e porta aprovados. O proxy conecta ao endereço literal, admite GET/HEAD/OPTIONS, recusa CONNECT e métodos de escrita, limita concorrência a um, frequência a 1–5 requisições/s e total a 40/80. Cada corpo tem até 256 KiB, cabeçalhos até 16 KiB. `Location` é removido, portanto não há seguimento de redirecionamentos; essa alteração também limita a cobertura de auditoria de redirects. Cookies sintéticos retornados pelo laboratório são vistos pelo ZAP para análise, mas não são registrados nos relatórios NEXUS.

Após três erros/negações repetidos no proxy, a tarefa é interrompida. HTTPS fica desabilitado porque um túnel CONNECT cego não permitiria aplicar esses limites por requisição; o NEXUS não instala uma autoridade certificadora local para contornar isso.

Há somente um scanner externo por processo NEXUS. A execução tem 5–180 segundos, saída combinada de até 2 MiB, até 200 achados e RSS observado de até 768 MiB para a árvore do processo. O adaptador exige ao menos 512 MiB de RAM livre, ou 1 GiB para ZAP; no fluxo completo do Security Center 2.0, a guarda geral exige **3 GiB livres para ZAP/Ghidra**, além dos controles próprios. O heap Java ZAP é limitado a 512 MiB. O monitoramento de RSS é amostrado e encerra a árvore quando excede o orçamento; **não constitui limite rígido do Windows nem VM**. Cancelamento, timeout, revogação e exceções encerram os processos conhecidos.

O perfil temporário não herda chaves de API, proxies, perfis pessoais, `JAVA_TOOL_OPTIONS` ou variáveis de credenciais. Nuclei recebe flags para impedir atualizações, Interactsh, redirecionamentos, requests/responses completos e downloads de templates. A pasta temporária é removida ao terminar. A instalação ZAP precisa conter Automation Framework, Report Generation e as regras utilizadas; ausência de relatório ou addon é erro operacional explícito.

## Configuração local e instalação opcional

A descoberta no PATH é informativa. A configuração efetiva contém caminhos absolutos e SHA-256 dos executáveis aprovados:

```json
{
  "nuclei": {"path": "C:/caminho/nuclei.exe", "sha256": "64 caracteres hexadecimais", "approved": true},
  "nmap_service": {"path": "C:/caminho/nmap.exe", "sha256": "64 caracteres hexadecimais", "approved": true},
  "zap": {"jar": "C:/caminho/zap-2.17.0.jar", "sha256": "hash do JAR",
          "java": "C:/caminho/bin/java.exe", "java_sha256": "hash do Java", "approved": true}
}
```

Essa configuração é uma permissão humana de executar a instalação local. O hash identifica os bytes do executável/JAR, não comprova assinatura do fornecedor, integridade de todas as bibliotecas/addons ou segurança do programa. Links, junctions, hardlinks, `.bat` e `.cmd` são recusados. Mudança de hash exige revisar e aprovar novamente. A versão só é anunciada como verificada após uma chamada limitada de versão do caminho aprovado; descoberta mantém `version: null` e `version_verified: false`.

Fontes oficiais conferidas em 5/11/2026:

- [Nuclei estável v3.11.1](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1): ZIP Windows amd64 de 46.067.128 bytes; SHA-256 do **arquivo ZIP** `bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2`. O hash do executável extraído é diferente e deve ser registrado separadamente. [API oficial de releases](https://api.github.com/repos/projectdiscovery/nuclei/releases/latest).
- [OWASP ZAP 2.17.0](https://www.zaproxy.org/download/): pacote Cross Platform completo anunciado como 273 MB; instalador Windows como 244 MB. Requer Java 17 ou superior. O pacote core de 103 MB não fornece todos os addons esperados. Os [metadados oficiais de versões](https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml) e a página do release fornecem checksums. O projeto informa que as releases estão sem assinatura; SHA identifica o download, sem substituir essa limitação.
- [Nmap oficial](https://nmap.org/download.html): instalação permanece opcional. O adaptador incorporado de TCP não depende dele.

### Instalação portátil opcional do Nuclei

`nexus/security/installers.py` fornece `NucleiInstaller(data_dir)`: `inventory()` faz descoberta local sem rede ou execução; `preview()` apresenta versão, tamanho, hash, destino e orçamento; `run(cancel=None, emit=None)` realiza o efeito aprovado. A API humana deve vincular a decisão ao preview e usar o semáforo compartilhado. O adaptador não concede aprovação a si próprio.

O instalador do painel suporta **somente Nuclei 3.11.1 para Windows AMD64**, pela URL e SHA-256 fixados acima. Não recebe URL, versão, comando ou destino do usuário. ZAP, Ghidra e Java/JDK não são baixados como consequência da instalação do Nuclei. Eles possuem o instalador separado de manutenção `scripts/install_security_runtime.py`, com releases, bytes e SHA-256 fixados; a instalação real autorizada e os caminhos estão no [relatório de runtime](../reports/SECURITY_RUNTIME_ENTREGA.md).

O download usa HTTPS, sem proxies/credenciais herdados (`trust_env=False`), permite no máximo cinco redirecionamentos entre `github.com`, `release-assets.githubusercontent.com` e `objects.githubusercontent.com`, e verifica o tamanho exato e SHA-256 antes de abrir o ZIP. URLs assinadas de CDN não são registradas: a proveniência guarda apenas os hosts percorridos e a URL pública fixada. O processo tem duração total de até 180 segundos, timeout de rede de dez segundos e exige espaço para o arquivo, até 200 MiB descomprimidos e 64 MiB de margem, aproximadamente 323 MB no total.

O ZIP é lido como contêiner não confiável, sem `extractall`: caminhos, links, streams, entradas duplicadas, criptografia, formatos inesperados e proporção acima de 100:1 são recusados. Até 16 entradas planas são aceitas; somente `nuclei.exe` é extraído, e os demais nomes permitidos são documentos de licença/readme/changelog. O total declarado é limitado a 200 MiB; cada byte extraído também é contado. O cabeçalho MZ é verificado, mas o arquivo não é iniciado e isso não comprova versão de execução ou assinatura digital.

O destino final é `data/security/tools/nuclei/3.11.1/nuclei.exe`, com `installation.json` contendo fonte, versão da release, bytes e hashes do ZIP/executável. A publicação final é feita por rename atômico no Windows e não sobrescreve destino existente. Cancelamento/falha remove somente o temporário pertencente àquela operação; uma instalação ou arquivo conflitante é preservado. Não há alteração global de PATH, serviço, Registro, Defender, firewall ou UAC. Configurar e executar o scanner continuam sendo permissões separadas.

Eventos de progresso mostram bytes efetivamente recebidos/escritos. O total do download vem dos metadados oficiais fixados e o total da extração do ZIP cuja integridade foi verificada; não há porcentagem de scan inventada. Instalação bem-sucedida ainda mantém `version_verified: false` até o adaptador executar a verificação explícita do binário aprovado.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_security_installers.py -q
```

Esses testes utilizam HTTP mockado e ZIPs sintéticos, sem baixar ou executar Nuclei. Cobrem redirecionamentos, cancelamento, tamanho/hash, limites, nomes perigosos, links e preservação de destinos existentes. Consulte o relatório da entrega para saber se o usuário autorizou um download real e se a validação nativa adicional ocorreu. Não há execução de `go install`, `winget`, scripts remotos ou atualização automática.

### Pacote portátil ZAP e Java local

O ZAP completo está em `data/security/tools/zap/2.17.0` e usa `data/security/tools/java/25.0.5+8/bin/java.exe`. O script de manutenção valida os arquivos extraídos contra seu manifesto; não configura nem inicia scanners, não altera `JAVA_HOME`/PATH globais e não remove instalações anteriores. A configuração humana do Security Center vincula o JAR e o Java aos hashes aprovados. Bibliotecas/addons precisam permanecer junto do JAR; copiar somente o ponto de entrada não reproduz a distribuição validada.

Para consultar a instalação sem rede/execução, use `.\.venv\Scripts\python.exe scripts\install_security_runtime.py zap java`. Para ensaiar ZAP em laboratório próprio após liberar pelo menos 3 GiB de RAM, use o [validador nativo documentado no relatório](../reports/SECURITY_RUNTIME_ENTREGA.md). O ensaio cria escopo e servidor HTTP de loopback próprios, aprova operações desse laboratório e revoga o escopo ao terminar; não é uma consulta somente leitura.

## Evidência e erros

JSONL Nuclei é aceito somente para IDs selecionados do pack revisado, com metadados obtidos do catálogo local. O relatório ZAP retém regra, CWE, gravidade, confiança, endpoint sem query e nome do parâmetro; exclui ataque, evidência bruta, corpo, tokens e cookies. Resultados passam pela redação adicional de segredos reconhecíveis, que não detecta todo segredo arbitrário. Saída de scanner nunca entra como instrução executável.

O XML Nmap rejeita entidades e DTDs externos, valida IP/portas e distingue `method=probed` de nomes inferidos pela tabela de portas. Produto/versão só aparecem quando houve probe comprovado. A associação automática com CVEs permanece ausente: porta ou versão isolada não confirma exploração.

Códigos comuns: `tool_unavailable`, `scanner_integrity`, `version_check_failed`, `unsupported_tool_version`, `resource_budget`, `scanner_busy`, `scope_revoked`, `isolation_requirement`, `environment_not_allowed`, `cancelled`, `tool_timeout`, `output_limit`, `memory_limit`, `missing_zap_report`. Eles são falhas/permissões de ferramenta, não recusas do modelo.

## Reprodução dos testes

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_security_scanners.py -q
```

As verificações cobrem versão/contrato, argv fixo, ausência real de ferramenta, integridade dos bytes, escopo/revogação, produção/domínios/HTTPS, limites, redação, parsers, cancelamento de processo e proxy real em loopback. Também cobrem OpenAPI local sem fetch, referências externas/servidores recusados, limite de endpoints/operações e exclusão de POST, paths parametrizados e exemplos sensíveis do plano e resultado. Saídas Nuclei/ZAP/Nmap nos testes são fixtures explicitamente identificadas. Consulte os relatórios da entrega para saber quais binários tiveram validação real adicional.

Documentação primária usada no contrato: [Nuclei running](https://docs.projectdiscovery.io/opensource/nuclei/running), [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/), [requestor](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/), [activeScan](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/), [report](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/) e [Nmap version detection](https://nmap.org/book/man-version-detection.html).
