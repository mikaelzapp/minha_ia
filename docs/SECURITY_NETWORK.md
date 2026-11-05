# Rede e OSINT no SECURITY CENTER

Este módulo acrescenta adaptadores reais e limitados à instalação existente. As funções ficam em `nexus/security/network.py`; elas não instalam programas nem concedem autorização a si próprias. O registro humano de escopos, as aprovações de execução, os logs e o histórico pertencem ao núcleo do SECURITY CENTER.

## Escopos e autorização

Um escopo informa nome, ambiente, finalidade, alvos e testes permitidos. Os identificadores dos testes são:

| Identificador | Operação |
| --- | --- |
| `http_headers` | Uma requisição HTTP HEAD para observar cabeçalhos |
| `tls_certificate` | Handshake TLS validado e metadados do certificado |
| `tcp_connect` | Conexão TCP em até oito portas de um host |
| `nmap_basic` | Nmap TCP connect em até dezesseis portas de um host |
| `osint` | Construtor de consulta pública e pesquisa de URLs do domínio |

O cadastro requer `authorization_confirmed: true` como booleano. O núcleo gera o ID e a revisão do escopo. Essa declaração não demonstra propriedade jurídica: o usuário continua responsável por registrar apenas seus sistemas ou aqueles para os quais tem autorização.

Exemplo de escopo de laboratório local, que não autoriza nenhum site externo:

```json
{
  "name": "Laboratório HTTP local",
  "targets": ["127.0.0.1"],
  "allowed_tests": ["http_headers", "tcp_connect"],
  "environment": "laboratório local",
  "purpose": "Validar a configuração do meu servidor de testes",
  "authorization_confirmed": true,
  "include_subdomains": false
}
```

Domínios usam correspondência exata. Subdomínios exigem `include_subdomains: true`. IPs individuais e redes CIDR são aceitos no cadastro; cada execução recebe um único host, sem expansão de CIDR ou varredura de toda a rede. Redes devem estar na forma canônica, por exemplo `10.20.30.0/24`.

O módulo recusa escopos abertos `/0`, destinos não especificados, multicast, link-local, IPv6 mapeado e formas numéricas ambíguas de IPv4. Loopback e redes privadas exigem IP ou CIDR concedido explicitamente. Autorizar um domínio que depois resolve para endereço interno não concede acesso implícito à rede interna.

Há duas decisões independentes: o escopo permite um tipo de teste naquele alvo; a aprovação humana permite a operação concreta. Antes da execução, o núcleo deve recarregar o escopo e conferir sua revisão. Desativar ou revogar um escopo precisa impedir uma aprovação pendente de ser reutilizada.

## HTTP, TLS e TCP

HTTP faz somente `HEAD`, sem enviar cookies, credenciais ou corpo. O limite de cabeçalhos é 16 KiB. Não segue redirecionamentos: registra se o destino proposto ainda pertence ao escopo. Não exporta valores de `Set-Cookie`. Não usa proxies do ambiente. Ausência de CSP, HSTS ou outro cabeçalho é uma observação com `confirmed: false`, sem afirmar que uma vulnerabilidade foi demonstrada.

TLS usa o repositório de confiança padrão do Python e valida nome, cadeia e validade do certificado. O resultado inclui SHA-256 do certificado, emissor, sujeito, datas, versão TLS e cifra. Certificado inválido produz `TLS_CERTIFICATE_INVALID`; o módulo não tenta novamente desabilitando a validação. Assim, certificados de laboratório sem confiança configurada podem impedir a coleta desses metadados.

As conexões usam o IP literal resolvido e autorizado. O socket não resolve novamente o nome na conexão; SNI e o cabeçalho Host preservam o domínio solicitado. A resolução DNS tem limite de espera de três segundos e o transporte HTTP/TLS tem orçamento de seis segundos. Cada nova execução resolve e valida novamente o destino. Respostas DNS mistas, com algum IP interno sem concessão explícita, são recusadas por inteiro.

`tcp_connect` usa uma conexão por vez, até oito portas e orçamento total de quinze segundos. Não envia banner ou outro payload. Porta aberta indica apenas que a conexão TCP foi estabelecida; não confirma identidade do serviço nem vulnerabilidade. O estado `unknown` diferencia falha ou timeout de uma porta que recusou explicitamente a conexão.

URLs de inspeção aceitam HTTP/HTTPS sem usuário/senha, fragmentos ou parâmetros de consulta. Caminhos com segmentos de escape, controles, percentuais inválidos ou codificação dupla de percentuais são recusados. Use caminhos percentualmente codificados quando houver espaços ou caracteres não ASCII.

Mesmo uma requisição HEAD ou uma conexão TCP pode aparecer nos logs e consumir recursos do destino. Essas operações são verificações ativas de baixo volume; não são apresentadas como análise puramente passiva.

## Nmap opcional

O adaptador procura somente instalações canônicas: `Program Files\Nmap\nmap.exe` no Windows, ou `/usr/bin/nmap` e `/usr/local/bin/nmap` em outros sistemas. Não executa um nome arbitrário encontrado no diretório atual ou no PATH. A evidência inclui o caminho e o SHA-256 do executável; isso é inventário de procedência, não uma atestação criptográfica do fornecedor. A assinatura do executável é explicitamente informada como não verificada.

O comando é construído pelo adaptador, com TCP connect (`-sT`), um IP literal, DNS desativado (`-n`), sem descoberta inicial (`-Pn`), sem ARP de descoberta próprio do Nmap, sem privilégios raw, sem retransmissão e com paralelismo um. Há no máximo dezesseis portas. Não aceita argumentos livres, scripts NSE, `-A`, detecção de sistema operacional, `-sV` ou UDP.

Há limite de processo de trinta segundos, timeout de host de vinte segundos e captura limitada durante a execução: 1 MB de stdout e 64 KB de stderr. A análise XML aceita apenas UTF-8; remove a declaração canônica vazia do Nmap antes do parser e recusa entidades ou DTDs adicionais. As pistas de nome de serviço da tabela de portas não são uma confirmação do serviço efetivamente presente.

Quando o executável não está disponível, o resultado é `TOOL_UNAVAILABLE`. O módulo não baixa o Nmap, não instala drivers, não solicita elevação e não simula uma varredura. ZAP e Nuclei não têm execução implementada neste adaptador; sua presença em inventário não significa integração de scan concluída.

## Construtor de dorks e OSINT

O construtor produz uma prévia sem DNS e sem acesso à rede. A consulta sempre inclui `site:DOMINIO`. Os operadores permitidos são `intitle`, `inurl` e `intext`, cada um com um valor. Também há tipo de documento, palavras-chave, exclusões e limite de um a dez resultados. Os termos livres são colocados entre aspas; operadores extras não podem ser injetados por esses campos.

Exemplo com domínio que já tenha sido cadastrado em um escopo OSINT:

```json
{
  "domain": "meu-dominio.example",
  "operators": {"intitle": "documentação"},
  "document_type": "pdf",
  "keywords": ["API pública"],
  "exclusions": ["obsoleto"],
  "max_results": 5
}
```

O resultado exibe a consulta antes da execução. Executar envia somente essa consulta ao mecanismo de pesquisa existente do NEXUS, incluindo o SearXNG já configurado quando disponível. A proteção de divulgação de credenciais/código/caminhos privados existente em `Tools._search_query` permanece aplicada; termos técnicos como vulnerabilidade, exploit ou malware não são uma blacklist de assuntos.

O adaptador reconstroi a consulta pelos campos estruturados, ignora uma eventual `query` livre enviada pelo cliente e filtra os URLs retornados pelo domínio selecionado e pelas permissões de subdomínios. Não abre os documentos encontrados. O mecanismo de pesquisa existente pode consultar páginas públicas durante seus próprios fallbacks; continuam valendo suas proteções contra endereços privados. As páginas e snippets são dados externos não confiáveis, não instruções para o agente.

O módulo não contorna CAPTCHA ou limites do provedor, não autentica em sites e não coleta credenciais. Resultados vazios ou falha do provedor são reportados como tal. A exportação conserva URLs, título, snippet e evidência da consulta; nenhuma pista é promovida automaticamente a vulnerabilidade confirmada.

## Consulta de CVE

`lookup_cve` aceita somente um identificador `CVE-AAAA-NNNN` e consulta o endpoint público fixo `https://cveawg.mitre.org/api/cve/ID`. Não aceita URL arbitrário, não envia arquivo ou código e não precisa de API key. A requisição tem TLS validado, IP fixado e limite de resposta de 1 MB, sem seguir redirecionamento.

O resultado inclui estado do registro, descrição, produtos afetados, métricas e referências fornecidas pelo registro oficial. Um registro publicado não demonstra que seu sistema esteja vulnerável; a versão e a configuração precisam ser confrontadas com as evidências locais. Erros HTTP do provedor não são recusas do modelo.

## Resultados e validação

Os adaptadores devolvem objetos JSON com `ok`, `tool`, `evidence` e `findings`; falhas acrescentam `code` e `error`. Entre os códigos estão `SCOPE_OR_INPUT`, `PROTOCOL_ERROR`, `TIMEOUT`, `NETWORK_ERROR`, `TLS_CERTIFICATE_INVALID`, `TOOL_UNAVAILABLE`, `TOOL_FAILED`, `SEARCH_FAILED` e `PROVIDER_HTTP`. Esses códigos descrevem permissões, entradas ou execução; não classificam o assunto da pergunta.

Execute os testes com:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_security_network.py -q
```

A suíte cobre autorização, revogação lógica, domínios/subdomínios, CIDR, DNS privado/rebinding, URLs com credenciais/escapes, limites de recursos, certificados inválidos, argv fixo, XML malicioso, dorks e filtragem OSINT. As únicas conexões reais da suíte são HEAD e TCP em um servidor efêmero em `127.0.0.1`; DNS público, TLS, Nmap, busca e CVE são simulados. Não atribua sucesso de integração real de uma ferramenta opcional apenas a esses testes.

## Referências oficiais consultadas

- [Nmap: técnicas de port scanning e TCP connect](https://nmap.org/book/man-port-scanning-techniques.html).
- [Nmap: limites de paralelismo, retransmissão e tempo](https://nmap.org/book/man-performance.html).
- [Nmap: referência de descoberta de hosts](https://nmap.org/book/man-host-discovery.html).
- [CVE Services: documentação oficial da API](https://cveawg.mitre.org/api-docs/).
- [CVE Program: uso de CVE Services](https://www.cve.org/Resources/Roles/Cnas/UsingVulnogramCVEServices.pdf).
