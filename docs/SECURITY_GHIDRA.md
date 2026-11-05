# Engenharia reversa: Ghidra headless e REA

O Security Center 2.0 preserva o adaptador REA MCP existente e adiciona um adaptador independente de Ghidra. Uma inspeção PE/ELF simples ou o REA básico não é apresentada como descompilação profunda. Cada relatório informa sua origem e o hash da amostra.

## Disponibilidade neste computador

**Atualização de 5 de novembro de 2026:** após autorização explícita, foram adquiridos Ghidra 12.2 e OpenJDK 25.0.5+8 portáteis, dentro do NEXUS, sem substituir o Java global. Instalação de arquivos, configuração aprovada e execução nativa são etapas distintas. O inventário do painel informa a configuração atual; a auditoria inicial abaixo permanece como histórico.

O ZIP Ghidra foi verificado com o tamanho exato de **569.712.708 bytes** e SHA-256 `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`. O [Eclipse Temurin OpenJDK 25.0.5+8 oficial](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8), Windows x64 HotSpot JDK ZIP, tem **141.285.173 bytes**, SHA-256 `636bdc13dc649ddc7d5921c5c7d23cca6e44fd19d662b45cc9c02135a6c96c42`. Tamanho e hash foram conferidos nos assets e na API oficial do GitHub nesta data. Hash de download não equivale a assinatura digital.

Pastas portáteis desta instalação:

```text
C:\Users\mikae\Downloads\ia\nexus-ai\data\security\tools\ghidra\12.2
C:\Users\mikae\Downloads\ia\nexus-ai\data\security\tools\java\25.0.5+8
```

A aquisição foi feita por [`scripts/install_security_runtime.py`](../scripts/install_security_runtime.py), que fixa URLs e hashes oficiais, verifica todos os membros antes de extrair, registra hashes individuais em `nexus-installation.json` e recusa sobrescrever um destino existente desconhecido. Sem `--install --authorized-download`, o script faz apenas inventário local. Não instala serviços, não escreve `JAVA_HOME`/`PATH` globais e não executa Java, Ghidra ou a amostra. O registro de aquisição está em [`reports/security-runtime-install.jsonl`](../reports/security-runtime-install.jsonl).

O primeiro ensaio de integração nativa foi interrompido **antes de iniciar Java**, porque a RAM disponível estava abaixo dos **3 GiB** exigidos pela fila. Esse estado está em [`reports/security-runtime-ghidra-real.json`](../reports/security-runtime-ghidra-real.json) como `resource_budget`; não comprova funcionamento headless nem decompilação. O validador está preparado para um ELF de laboratório conhecido, com duas funções aritméticas, sem executar o binário. Nenhum aplicativo pessoal foi encerrado e os limites de memória foram preservados.

Na auditoria inicial desta entrega não havia Ghidra nem JDK compatível configurados. Foi encontrado somente o JRE Oracle 1.8 em `C:\Program Files\Java\jre-1.8`, sem `javac`. Um JRE antigo não atende aos requisitos do Ghidra atual. O adaptador informa `ghidra_unavailable` ou `jdk_unavailable` e não fabrica funções ou pseudocódigo.

A versão estável consultada em 5 de novembro de 2026 foi o [Ghidra 12.2 oficial](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build). O [asset oficial](https://github.com/NationalSecurityAgency/ghidra/releases/expanded_assets/Ghidra_12.2_build) `ghidra_12.2_PUBLIC_20261016.zip` foi anunciado com 543 MB e SHA-256 `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`. Seu [arquivo de requisitos](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/application.properties) exige **JDK 25**. O adaptador lê os requisitos da distribuição instalada, em vez de assumir que todas as versões usam o mesmo Java.

Instalação e aquisição são opcionais e precisam de aprovação específica. Este módulo não baixa Ghidra, JDK, scripts, extensões nem dependências por conta própria. A validação real de Ghidra depende de uma distribuição e de um JDK compatível efetivamente disponíveis; consulte também o relatório geral da entrega para eventuais instalações aprovadas após a auditoria inicial.

## Configurar e executar pelo painel

1. Em **SECURITY CENTER → REVERSE ENGINEERING**, consulte o inventário.
2. Na configuração do motor Ghidra, informe a pasta da distribuição extraída e a pasta do JDK, ambas com caminhos absolutos. Exemplo: `C:\Tools\ghidra_12.2_PUBLIC` e `C:\Tools\jdk-25`.
3. Leia o aviso de isolamento. A execução estática usa um diretório privado e limites de recursos; **não dispõe de uma VM nem de sandbox de arquivos/rede do Windows**. A confirmação `isolation_acknowledged: true` registra ciência dessa condição e é separada da autorização da amostra.
4. Revise os caminhos, hashes, requisitos, limites e impacto da configuração. Aprove a configuração proposta.
5. Envie um binário próprio ou autorizado ao armazenamento de amostras existente. O registro de amostra mantém o SHA-256 e limita uploads a 10 MiB.
6. Prepare a tarefa Ghidra, revise a amostra e aprove sua análise estática. A fila compartilha o orçamento dos outros motores e modelos.
7. Acompanhe o estado e os eventos. Use **Cancelar** para interromper o processo e seus descendentes.
8. Consulte o relatório, com linguagem/arquitetura identificada pelo Ghidra, funções, strings, imports, exports, pontos de entrada, referências de chamadas e pseudocódigo quando o decompilador funcionar.

O painel não deve prometer que a mera presença da pasta comprova funcionamento. `inventory()` não executa programas; `validate()` executa somente `java -version` e não equivale a uma análise headless completa. Uma análise bem-sucedida de um binário de laboratório é a evidência de integração de ponta a ponta.

## Contrato de integração

Para repetir o ensaio nativo após liberar RAM, com o motor já configurado:

```powershell
.\.venv\Scripts\python.exe scripts/validar_ghidra_real.py
```

O script aplica o mesmo mínimo de 3 GiB antes de enviar a amostra. Quando houver memória, usa a API autenticada real para upload, prévia, aprovação e fila; exige funções e pseudocódigo realmente produzidos pelo Ghidra e verifica exportação JSON/Markdown/HTML. O ELF sintético tem SHA-256 `cd800515b30da4102720f9eb905dcc569c7416156f039c97da1883b845191c16`. Relatório `resource_budget` significa teste não iniciado, e não teste aprovado.

O adaptador está em [`nexus/security/ghidra.py`](../nexus/security/ghidra.py). O único exportador permitido está em [`integrations/ghidra/NexusExport.java`](../integrations/ghidra/NexusExport.java).

```python
from pathlib import Path
from nexus.security.ghidra import Ghidra

engine = Ghidra(Path("data").absolute(), {
    "install_dir": r"C:\Tools\ghidra_12.2_PUBLIC",
    "java_home": r"C:\Tools\jdk-25",
    "isolation_acknowledged": True,
})
inventory = engine.inventory()       # Metadados e hashes; não inicia Java.
validation = engine.validate()       # Apenas em fluxo humano autorizado.
# O orquestrador resolve o arquivo por SecurityStore.sample(sample_id).
# Não exponha caminhos arbitrários como parâmetros de ferramentas do modelo.
```

O método `analyze(path, expected_sha256=..., cancel=event, on_event=callback)` só aceita arquivo regular diretamente em `data/security/samples`. Rejeita links, junctions, hardlinks, alterações de hash e formatos fora da cobertura. Aceita PE, ELF e Mach-O simples; arquivos raw, fat Mach-O, arquivos compactados e loaders escolhidos livremente ficam fora da cobertura deste adaptador.

A configuração humana aprovada vincula `install_dir`, `java_home`, `utility_sha256`, `launcher_sha256`, `java_sha256` e `exporter_sha256`. A análise confere novamente os hashes que foram vinculados. Hash observado identifica bytes e não comprova assinatura ou autoria de toda a instalação: `signature_verified` e `installation_verified` permanecem falsos. Extensões instaladas no Ghidra não são certificadas por esses hashes.

O NEXUS chama Java diretamente com `shell=False`, `GhidraLauncher` e `AnalyzeHeadless`, sem interpolar comandos em `.bat`, sem `npx` e sem scripts fornecidos pelo binário/modelo. Uma cópia com hash conferido entra em um projeto novo e descartável; a amostra original não é passada ao processo, modificada, executada ou depurada. Credenciais e opções Java herdadas do ambiente não são repassadas. O processo não recebe o perfil pessoal do usuário.

## Limites e evidências

| Recurso | Padrão | Máximo configurável e mecanismo |
| --- | --- | --- |
| Entrada | 10 MiB | 10 MiB; conferência antes da cópia |
| Duração total | 180 s | 300 s; watchdog e encerramento do Job Object |
| Autoanálise | 150 s no padrão | `-analysisTimeoutPerFile`, sempre subordinado ao limite total |
| Heap Java | 768 MiB | 768 MiB; `-Xmx` |
| Memória do grupo | 1536 MiB | 1536 MiB; Windows Job Object, com processos filhos incluídos |
| Processos no grupo | 8 | Limite do Windows Job Object |
| RSS | 1536 MiB | Watchdog adicional a cada cerca de 50 ms |
| CPU da análise | 1 | `-max-cpu 1` e limite de pools; não é cota de CPU do Windows |
| Funções exportadas/descompiladas | 100 | 200; seleção limitada no exportador |
| Strings definidas | 300 | 500; no máximo 512 caracteres por valor |
| Chamadas exportadas | 500 | 1000; somente funções selecionadas |
| Pseudocódigo | 4096 caracteres/função | 5 s por função e limite global |
| Log capturado | 512 KiB | Watchdog de saída e leitura limitada |
| JSON de resultado | 2 MiB | Validação antes de leitura/interpretação |
| Workspace | 256 MiB / 10 mil entradas | Monitorado a cada cerca de 500 ms; não é quota de disco do Windows |

O processo nasce suspenso, é associado ao Job Object e só então é retomado. Se o Windows recusar esse limite, a tarefa falha sem iniciar a análise. Encerrar o Job Object mata também o decompilador nativo filho. Fora do Windows este runner informa `resource_boundary_unavailable`; não presume limites de sistema inexistentes.

O limite de funções controla **exportação e descompilação explícita**. A autoanálise nativa do arquivo pode identificar mais funções; seu limite é tempo/memória, não um contador exato de funções processadas internamente. Os totais e truncamentos ficam em `coverage`. As referências são chamadas estáticas das funções selecionadas; chamadas indiretas podem permanecer desconhecidas. Strings não definidas pelo Ghidra podem não aparecer.

Se a autoanálise atingir seu tempo mas o exportador terminar, o resultado é `partial`, com `analysis_timed_out: true`. Falha de ferramenta, cancelamento, RAM insuficiente, saída inválida e ferramenta ausente são estados operacionais, não recusas do modelo. Nenhum deles comprova ausência de vulnerabilidade.

A correlação com inspeção estática/YARA-X e REA deve usar o **mesmo SHA-256** e preservar as origens. Uma assinatura YARA é um indício; uma string ou import não prova que a chamada foi executada. Pseudocódigo é reconstrução do decompilador, não o código-fonte original.

## Testes reproduzíveis e limites da validação

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_security_ghidra.py tests/test_security_rea.py -q
```

Os testes do adaptador usam instalações/saídas controladas para testar descoberta, requisitos, permissões, limites, integridade, ausência de ferramentas, truncamento e limpeza sem baixar Ghidra. Isso é informado como **fixture**, não análise nativa.

Quatro testes executam de fato o runner Windows com um processo Python inofensivo: conclusão/limpeza, timeout, cancelamento e recusa de alocação acima do limite de memória do Job Object. Eles validam o runner; não provam funcionamento do Ghidra ou de seu decompilador. Um teste Ghidra real exige a instalação opcional e um binário de laboratório autorizado. O relatório geral distingue essas evidências.

Referências técnicas oficiais: [analisador headless](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md), [configuração da JVM](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/launch.properties), [HeadlessScript](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessScript.html) e [DecompInterface](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html).
