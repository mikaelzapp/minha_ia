# Análise estática e NEXUS Code Auditor

O Security Center inspeciona os bytes de arquivos e o texto de projetos autorizados. O analisador não inicia executáveis enviados, não importa módulos do projeto, não executa scripts de instalação e não extrai arquivos compactados. Strings, comentários e resultados de análise são dados não confiáveis; não devem ser tratados como instruções para o agente.

## Análise de um arquivo

`nexus/security/static.py` fornece `analyze_file(path, original_name=None)`. A interface pode armazenar uma amostra com nome interno neutro e preservar o nome original no relatório. A identificação do formato usa os bytes do cabeçalho, mesmo quando a extensão diz algo diferente.

O resultado contém:

- Nome de exibição, tamanho, SHA-256 e formato identificado por assinatura.
- Entropia de Shannon do arquivo, strings ASCII/UTF-16LE/UTF-16BE, offsets e indicação de truncamento.
- Cabeçalhos PE básicos: assinatura, arquitetura, características, ponto de entrada RVA e seções. A entropia por seção usa amostras explicitamente identificadas, com orçamento total de 1 MiB.
- Cabeçalho ELF básico com arquitetura, classe 32/64 e ordem dos bytes quando disponíveis.
- Referências textuais a shell, rede, APIs de processo e possíveis mecanismos de persistência, apresentadas como hipóteses.
- Correspondências reais do YARA-X, se o módulo estiver instalado, e disponibilidade explícita dos motores opcionais.

Uma seção gravável e executável ou entropia alta pode existir em software legítimo. Nenhum desses sinais, isolado ou combinado, confirma malware. O relatório não emite certificado de segurança quando não encontra sinais.

O limite do analisador é **20 MiB por arquivo**. O limite de upload da interface pode ser menor. A extração apresenta até 160 strings de até 240 caracteres, com orçamento total de 24 mil caracteres. Credenciais reconhecíveis são redigidas antes da apresentação; reconhecimento por padrões não consegue garantir a identificação de todo segredo arbitrário.

## YARA-X real

`scan_yara(path, rulesfile=None)` usa a biblioteca oficial `yara_x` e examina os bytes já lidos. Não inicia a amostra. O compilador desativa `include`, o scanner possui timeout de cinco segundos e limita correspondências por padrão. Arquivos de regras locais, quando fornecidos, têm limite de 256 KiB e passam pelas mesmas verificações de arquivo.

As três regras descritivas que acompanham o código identificam cabeçalhos MZ/ELF e referências textuais a shell. **Não são um conjunto completo de assinaturas de malware.** Nenhuma base de regras é baixada automaticamente. Uma regra particular só prova que sua condição correspondeu aos bytes; a interpretação depende da procedência e da precisão da regra.

Na instalação desta expansão foi validado YARA-X **1.21.0**, wheel CPython abi3 Windows x64 de aproximadamente 8,3 MB, com hash oficial verificado. A versão instalada é exposta no relatório. A biblioteca é opcional: sua ausência não desativa hashes, cabeçalhos, strings ou o Code Auditor. As fontes oficiais documentam a [API Python](https://virustotal.github.io/yara-x/docs/api/python/), o [wheel da versão validada](https://pypi.org/project/yara-x/1.21.0/) e a [licença BSD de três cláusulas](https://github.com/VirusTotal/yara-x/blob/v1.21.0/LICENSE).

## Auditoria de projetos

`audit_project(path)` percorre um diretório autorizado sem carregar seus módulos. Python é analisado por AST; JavaScript/TypeScript, PHP, Docker e configurações usam padrões estáticos limitados. Não é uma análise completa de fluxo de dados e não comprova que uma entrada externa alcança um ponto perigoso.

O scanner inicial detecta:

- Avaliação dinâmica `eval`/`exec`, desserialização com pickle/dill/shelve e YAML sem SafeLoader comprovado.
- Execução por shell e construção dinâmica de consultas SQL em Python, incluindo aliases de importação comuns.
- Verificação TLS explicitamente desativada.
- Avaliação dinâmica, possíveis comandos por shell e inserção de HTML no DOM em JavaScript/TypeScript.
- Chamadas PHP de avaliação, comandos e desserialização.
- Credenciais literais e tokens com formatos reconhecíveis, sem exportar seus valores no achado.
- Debug habilitado, algumas configurações CORS amplas, `USER root`, usuário Docker não determinado e imagem base com `latest`.

Cada achado inclui `id`, `title`, `severity`, `confidence`, `file`, `line`, `impact`, `recommendation`, `evidence` redigida e `validation: "unconfirmed"`. A gravidade expressa impacto potencial do padrão; não equivale a vulnerabilidade explorável confirmada. Comentários são ignorados pelos padrões de linha mais comuns; strings e construções complexas ainda podem produzir falsos positivos. A AST Python não acompanha todos os aliases, sombreamentos, wrappers ou fluxos entre funções.

O inventário de dependências lê requisitos declarados em `requirements.txt`, `package.json`, `composer.json`, `pyproject.toml`, Cargo, alguns locks TOML e `go.mod`. Locks não interpretados são identificados de forma explícita. URLs e caminhos de origem não são exportados como evidência de versão. **Não há consulta automática de CVEs nem confirmação da versão instalada nesse inventário.** Nenhum gerenciador de pacotes é executado.

A auditoria lê até **250 arquivos**, **512 KiB por fonte**, **8 MiB no total**, **5.000 entradas de diretório** e **200 achados**, com orçamento de 20 segundos verificado entre as etapas. Ao atingir um orçamento, `truncated` e `limit_reasons` tornam a cobertura incompleta visível. Os detalhes de arquivos ignorados são limitados a cem registros; a contagem total é preservada.

## Proteções de leitura e motores opcionais

O chamador continua responsável por autorizar o workspace ou pasta do usuário. O analisador adiciona verificações próprias de symlinks, junctions, reparse points, hardlinks, arquivos especiais, caminhos ambíguos e arquivos alterados durante a leitura. Arquivos `.env`, bancos, chaves, credenciais e diretórios sensíveis são ignorados. Pastas geradas, `.git`, ambientes virtuais, `node_modules`, `vendor`, `data` e `.runtime` são excluídas da auditoria de projetos. Isso protege os dados operacionais do NEXUS e pode reduzir a cobertura de projetos que usam esses nomes.

`inventory_optional_engines()` informa `installed` e `available` separadamente. Neste módulo, **capa, FLOSS, Semgrep e Trivy são apenas inventariados**, sem execução automática. Sua presença no PATH não significa adapter operacional, regras configuradas ou base de vulnerabilidades disponível. O resultado mostra essa limitação. Descompilação também é marcada indisponível neste analisador; uma integração REA/Ghidra é uma capacidade separada do Security Center.

Não há análise dinâmica neste módulo. Uma inspeção estática no processo do servidor não é uma máquina virtual nem uma sandbox de sistema operacional. Não se deve utilizar o fluxo de comandos de programação para executar uma amostra suspeita no Windows principal.

## Validação reproduzível

Execute na pasta do projeto:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_security_static.py -q
```

Os testes usam apenas marcadores de texto inofensivos, cabeçalho PE sintético, cabeçalho ELF sintético e pequenos trechos de código tratados como dados. Não usam EICAR, malware, modelos Ollama ou bancos do usuário. Há verificações reais de correspondência YARA-X e recusa de includes externos. O teste de criação de symlink pode ser pulado quando o Windows não fornece o privilégio necessário.
