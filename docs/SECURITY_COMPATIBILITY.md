# Security Center — compatibilidade e limites reais

**Ampliação 2.0:** a matriz abaixo registra a entrega anterior. Os novos adaptadores Nuclei/ZAP/Nmap/Ghidra, sua configuração e evidências estão no [guia 2.0](SECURITY_CENTER_2.md) e na [entrega atual](../reports/SECURITY2_ENTREGA.md). A presença de um adaptador não implica instalação ou execução nativa do motor.

Validação local em **5 de novembro de 2026**, Windows, Python do `.venv` do projeto. A disponibilidade exibida na interface é consultada novamente e pode mudar após atualizações ou remoções. Nenhum scanner externo ou decompilador foi instalado para tornar o inventário artificialmente completo.

## Capacidades nesta instalação

| Componente | Situação verificada | O que a integração entrega |
| --- | --- | --- |
| Inspeção estática incorporada | Funcional | Hashes, assinaturas de formato, cabeçalhos, entropia, strings e hipóteses de capacidades. Não executa a amostra. |
| Code Auditor incorporado | Funcional | AST Python e verificações limitadas para outras linguagens/configurações. Achados não confirmados com arquivo, linha e recomendação. |
| YARA-X | Biblioteca Python **1.21.0** | Correspondências reais com regras locais; não substitui um antivírus. Veja [detalhes estáticos](SECURITY_STATIC.md). |
| REA MCP | **6.8.0**, comunicação local validada | Inspeção estática PE/ELF/ZIP, conforme a tabela abaixo. Reutiliza o pacote npm já armazenado. |
| Ghidra | Não configurado no REA desta integração | Nenhum pseudocódigo nativo ou análise profunda de funções foi produzido. |
| Hopper | Indisponível no Windows | Não utilizado. |
| IDA / Kuna | Não configurados | Não utilizados. |
| Microsoft Defender | Consulta nativa validada | Estado da proteção, versão/data/idade de assinaturas e eventos. Sem desativação, alteração, remoção ou quarentena. |
| Processos e conexões | Consultas reais via psutil | Metadados sob demanda. Sem ambiente, linha de comando ou captura de pacotes. |
| Inicialização e tarefas | Consultas nativas validadas | Inventário limitado, com argumentos omitidos para reduzir exposição de credenciais. |
| Nmap | Não encontrado no PATH durante a validação | O adaptador básico informa a ausência; não é um scanner simulado. |
| Nuclei / OWASP ZAP | Não encontrados no PATH | Somente inventário; não há execução automatizada destes motores nesta entrega. |
| capa / FLOSS / Semgrep / Trivy | Não encontrados no PATH | Somente inventário. Não há relatório atribuído a motores que não foram executados. |
| VirusTotal | Não configurado | Nenhum arquivo ou hash enviado automaticamente. |
| Análise dinâmica | Não configurada | Não há VM dedicada com snapshots e isolamento validado. Amostras não são iniciadas no Windows principal. |

Os utilitários incorporados de HTTP, TLS, TCP, OSINT e CVE não dependem de ZAP, Nmap ou Nuclei para fornecer seus próprios resultados. A ausência dessas dependências não transforma uma inspeção de cabeçalhos em um pentest completo.

## REA: integração própria do NEXUS

O servidor REA configurado no Codex e o processo utilizado pelo NEXUS são sessões distintas. O NEXUS usa um cliente MCP stdio em `nexus/security/rea.py`, inicia **Node + caminho absoluto de `rea.mjs` + `mcp`**, sem shell e sem executar `npx`. Não altera a configuração global do Codex, não reutiliza seus alvos abertos e não instala pacotes.

A descoberta aceita o pacote cached `rea-agents` **6.8.0** em locais conhecidos do cache npm. Valida nome, versão, repositório declarado, presença do runtime compilado e registra SHA-256 do ponto de entrada. Esses metadados e esse hash **não comprovam autenticidade criptográfica de toda a distribuição npm**. Se o cache for removido, substituído ou tiver outra versão, o adaptador informa indisponibilidade e preserva o analisador estático incorporado. Atualizar a versão suportada exige revisar o contrato das ferramentas e seus testes.

O `binary_session` real diferencia comunicação MCP, catálogo de operações e provedores profundos. A presença de REA não comprova que Ghidra, Java compatível ou qualquer outro decompilador esteja pronto. A documentação oficial também distingue [instalação e provedores](https://github.com/morluto/rea/blob/main/docs/installation.md); o [projeto Ghidra](https://github.com/NationalSecurityAgency/ghidra) é uma dependência separada.

| Entrada | Ferramentas MCP usadas | Cobertura |
| --- | --- | --- |
| PE identificado por `MZ` | `inspect_pe_imports`, `inspect_managed_artifact` | Imports e resumo da identidade PE/CLI, quando os bytes forem válidos. Não carrega a DLL nem inicia o executável. |
| ELF | `inspect_native_exports` | Resumo de exports, quando o formato for suportado. |
| ZIP identificado por `PK` | `open_binary`, `inspect_artifact`, `close_binary` | Inventário/inspeção de contêiner. Sem extração de seus arquivos. |
| Outros formatos | Resultado explícito `unsupported_static_format` | Usar a análise estática incorporada; nenhum pseudocódigo é inventado. |

O conjunto de ferramentas do adaptador é fixo: as seis operações acima e `binary_session`. Não há acesso genérico a chamadas MCP, ferramentas de execução, anexação a processos, instrumentação, depuração ou automação do desktop. Uma extensão futura de descompilação deverá verificar instalação, contrato, procedência e orçamento do provedor antes de ser anunciada como disponível.

O processo tem diretório de trabalho, perfil de usuário e temporários próprios em `data/security/rea`. Não recebe variáveis de credenciais do ambiente do servidor nem comandos de provedores herdados. Aceita apenas arquivos locais já isolados sob `data/security`, excluindo a própria pasta de runtime, com até 32 MiB e sem links/junctions/hardlinks. O upload da interface tem limite menor, exibido pela API. A amostra permanece dado não confiável.

Cada sessão recebe **45 segundos**, até **512 KiB de stdout MCP no total** e **32 KiB de diagnóstico stderr retido**. O Node recebe `--max-old-space-size=384`. Esse valor limita o heap V8, não toda a memória nativa do processo e não constitui uma VM ou sandbox do sistema operacional. Filhos conhecidos são encerrados ao finalizar a sessão; não há repetição automática de análise após um timeout. O formato resumido evita carregar inventários completos enormes na conversa.

## Blue Team: consultas, não alterações

`nexus/security/platform.py` entrega `blue_status(section)` para `overview`, `processes`, `connections`, `startup`, `tasks`, `defender` e `events`. O sistema executa somente scripts literais de leitura: o usuário e o modelo não podem acrescentar expressões PowerShell aos parâmetros. Os cmdlets utilizados são `Get-CimInstance Win32_StartupCommand`, `Get-ScheduledTask`, `Get-MpComputerStatus` e `Get-WinEvent`.

A consulta do Defender usa a [interface oficial `Get-MpComputerStatus`](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus). Mostra o estado informado pelo Windows, não uma varredura produzida pelo NEXUS. A idade e a data de assinaturas são observadas, sem iniciar atualização. Defender, firewall, UAC, serviços e suas configurações são preservados.

As listagens têm até **150 linhas**, eventos até **50 registros dos últimos sete dias**, timeout nativo de **20 segundos** e saída de até **512 KiB**. O NEXUS não solicita elevação. Processos e conexões refletem a visibilidade da conta atual. Ausência na página limitada não comprova ausência no computador; consulta negada não comprova proteção desativada. Não há serviço de monitoramento periódico instalado.

Erros têm códigos explícitos como `permission_denied`, `native_query_failed`, `tool_timeout`, `output_limit` e `invalid_tool_output`. Eles são falhas operacionais, não recusas temáticas do modelo. Resultados são submetidos à redação de credenciais reconhecíveis, com a limitação usual de que padrões não identificam todo segredo arbitrário.

## Procedência de ferramentas

`provenance_inventory()` identifica caminhos, disponibilidade e tamanho; calcula SHA-256 de arquivos razoavelmente pequenos. A descoberta **não executa** os utilitários encontrados no PATH, nem usa comandos `--version` de programas desconhecidos. Versões não verificadas permanecem `null`. O pacote Python YARA-X e o pacote cached REA têm versões obtidas por seus metadados locais.

`trusted: false` e `signature_verified: false` impedem interpretar descoberta como autenticação do fornecedor. SHA-256 identifica bytes observados, mas só permite confirmar procedência quando comparado a uma referência oficial confiável. Não há atualização silenciosa de regras, bases, scanners ou decompiladores.

## Evidências e reprodução

Os testes automatizados destes dois adaptadores cobrem scripts fixos, limites, omissão de argumentos, ausência de execução durante inventário, erros de permissões, protocolo MCP, ferramentas bloqueadas, fechamento de sessão, isolamento de caminhos e alteração da amostra durante a análise.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_security_platform.py tests/test_security_rea.py -q
```

Resultado inicial: **29 testes passaram**. Os registros reais produzidos no mesmo dia foram:

- [`security-rea-runtime.json`](../reports/security-rea-runtime.json): MCP conectado, versão 6.8.0, provedores e razões de indisponibilidade. Tempo observado de abertura e consulta: cerca de 3 a 5 segundos.
- [`security-rea-lab.json`](../reports/security-rea-lab.json): ZIP inofensivo criado no laboratório local, com um `readme.txt`, analisado via MCP com duas evidências. `target_executed: false`.
- [`security-blue-runtime.json`](../reports/security-blue-runtime.json): processos/conexões/recursos reais e falhas de cmdlets dentro do sandbox de desenvolvimento.
- [`security-blue-native-runtime.json`](../reports/security-blue-native-runtime.json): execução autorizada somente de leitura fora desse sandbox, com 21 entradas de inicialização, 150 tarefas, status do Defender e 50 eventos. Nenhuma mudança de proteção ou instalação foi realizada por esses testes.

Resultados refletem o instante consultado. Não há certificação de segurança do computador nem afirmação de cobertura total de persistência ou malware.
