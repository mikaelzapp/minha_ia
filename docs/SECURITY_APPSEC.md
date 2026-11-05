# Auditoria SQLi e autenticação com dados fictícios

Os adaptadores de `nexus/security/appsec.py` executam requisições HTTP reais e limitadas, usando o mesmo controle de escopo, DNS e conexão IP fixada do módulo de rede existente. O executor humano do Security Center precisa preparar e aprovar a operação. Chamar um adaptador Python diretamente não cria uma aprovação humana.

São aceitos exclusivamente ambientes explicitamente classificados como `lab`, `laboratório`, `laboratorio`, `staging`, `homologação` ou `homologacao`. Uma descrição como `prod-lab` não habilita testes ativos. O escopo também deve autorizar especificamente `appsec_sqli` ou `appsec_auth`. Os identificadores, marcadores, usuários e senhas devem começar por `NEXUS_LAB_`, com caracteres alfanuméricos, `_` e `-`, para tornar explícito que se trata de dados preparados para auditoria.

Quando existir `environment_class`, essa classificação estruturada é a referência: somente `lab` e `staging` são aceitos, mesmo que a descrição livre contenha a palavra laboratório. Pela interface, abra **Security Center → Security Center 2.0 → AUTH & DATABASE SECURITY**, escolha SQLi ou autenticação A/B, o escopo, o perfil ativo apropriado e confirme o uso de dados fictícios. **Preparar auditoria** mostra o alvo e os limites; a execução começa somente após **Aprovar esta operação**.

## SQL Injection

`preview_sqli(scope, target, parameter='name', baseline='NEXUS_LAB_A', marker='NEXUS_LAB_SQLI_MARKER_A', lab_confirmation=False)` valida a configuração sem DNS ou conexão. `run_sqli` recebe os mesmos argumentos e os parâmetros opcionais `cancel` e `scope_loader`.

O teste envia seis GETs a um endpoint informado: registro fictício conhecido, valor com aspas, expressão `AND` verdadeira e falsa, repetidas. A confirmação exige que o marcador fictício esteja presente na referência e nos dois controles verdadeiros, ausente nos dois falsos, com respostas HTTP bem sucedidas nos controles. Não usa `OR`, `UNION`, consultas temporizadas, enumeração de banco, múltiplas instruções ou escrita. O ensaio não amplia a seleção para todos os registros.

O relatório distingue:

- `confirmed_controlled`: comportamento confirmado com o marcador sintético e controles repetidos.
- `dynamic_indication`: erro com aspas e referência válida, sem confirmação; um HTTP 500 isolado não comprova SQLi.
- `no_finding_in_coverage`: controles executados sem confirmar SQLi.
- `inconclusive`: o registro de referência não foi comprovado.

O **Code Auditor** anterior continua disponível no mesmo projeto e identifica construções SQL dinâmicas em Python por AST e padrões limitados em outras linguagens. Seus achados `PY-SQL-CONSTRUCTION` permanecem `unconfirmed`, com arquivo e linha. A análise existente acompanha atribuições dinâmicas simples, sem provar um fluxo completo da entrada HTTP até o banco. A cobertura dinâmica é um parâmetro GET textual por execução; JSON, formulários de SQLi, outros dialetos e todas as rotas não foram cobertos por esse teste. O módulo AUTH utiliza POST de formulário somente para as duas contas fictícias conhecidas.

## Autenticação e sessão

`preview_auth(scope, target, fixture=None, synthetic_accounts_confirmed=False, lab_confirmation=False)` exige a origem HTTP/HTTPS com caminho `/`. `run_auth` acrescenta `cancel` e `scope_loader`.

A fixture padrão contém:

```json
{
  "login_path": "/login",
  "logout_path": "/logout",
  "username_field": "username",
  "password_field": "password",
  "account_a": {
    "username": "NEXUS_LAB_A",
    "password": "NEXUS_LAB_PASSWORD_A",
    "resource": "/api/objects/NEXUS_LAB_A",
    "marker": "NEXUS_LAB_RESOURCE_A"
  },
  "account_b": {
    "username": "NEXUS_LAB_B",
    "password": "NEXUS_LAB_PASSWORD_B",
    "resource": "/api/objects/NEXUS_LAB_B",
    "marker": "NEXUS_LAB_RESOURCE_B"
  }
}
```

Esses valores são públicos e completamente fictícios, destinados ao laboratório incluído. Não devem ser usados como credenciais de aplicações reais.

O módulo envia até doze requisições: acesso anônimo aos recursos A/B; login A e acesso próprio/cruzado; login B e acesso próprio/cruzado; GET autenticado com origem CORS não confiável; logout A; tentativa de reutilizar a sessão A; logout B. BOLA só é confirmado depois de comprovar login e acesso ao recurso próprio, e quando a resposta cruzada contém o marcador do outro usuário. Uma sessão continua válida após logout apenas quando o marcador próprio é devolvido novamente com a sessão anterior.

Os resultados conservam status HTTP, endpoints fictícios, presença de marcadores e atributos de cookies HttpOnly/Secure/SameSite. Credenciais, valores de cookies, tokens, cabeçalhos brutos e corpos HTTP não entram nos relatórios. A prévia também omite senhas. Os valores de sessão existem temporariamente em memória durante a operação. O transporte HTTP manual não reproduz todas as regras de cookies de um navegador: domínio, caminho, expiração no navegador e políticas de terceiros não são validados. `Secure` é exigido pela checagem somente em HTTPS; o laboratório HTTP não confirma a configuração de produção.

Não foram implementados testes completos de CSRF, recuperação de senha, enumeração de usuários, expiração temporal de tokens, armazenamento/hash de senhas ou hierarquia administrador/usuário. Essas lacunas aparecem em `not_tested`; a ausência de achados não significa que esses controles foram aprovados. Não há força bruta ou tentativa de descobrir contas. Os logouts previstos são tentados no fluxo normal; interrupção, revogação ou falha não garantem limpeza de sessões no aplicativo-alvo.

## Limites e permissões

São no máximo 16 requisições, 30 segundos, uma conexão por vez, 128 KiB de corpo e 16 KiB de cabeçalhos por resposta. Três erros consecutivos ou sinais HTTP 429/5xx atingem o orçamento de degradação. Não há redirecionamentos, proxy herdado, execução de JavaScript, cookies pessoais ou novas tentativas automáticas. TLS usa a verificação de certificados do sistema. O IP resolvido é validado e usado diretamente no socket; DNS é reavaliado por requisição.

`scope_loader` deve retornar o escopo atualizado antes de cada requisição e durante a recepção limitada. Revogação ou alteração de revisão interrompe a execução. `cancel` aceita uma função que retorna booleano ou `threading.Event`. Operações já enviadas não são desfeitas pelo cancelamento.

## Laboratório reproduzível

Inicie o laboratório local na pasta do NEXUS:

```powershell
.\.venv\Scripts\python.exe scripts\security_lab.py --port 8899
```

A aplicação aceita somente `127.0.0.1`, contém duas contas e registros fictícios em SQLite na memória e não grava senhas/cookies nas observações. Endpoints: `/health`, `/sqli`, `/login`, `/logout`, `/api/objects/NEXUS_LAB_A` e `/api/objects/NEXUS_LAB_B`. Feche com **Ctrl+C**. Use `--fixed` para a versão parametrizada, com autorização por proprietário, invalidação de sessão, atributos de cookie e CORS restrito. O modo vulnerável existe somente para reproduzir esses achados e não deve ser publicado.

Para o fluxo de correção supervisionada, `--root CAMINHO_DO_PROJETO_DE_LAB` permite um `settings.json` contendo `{"fixed": false}`. A alteração aprovada para `{"fixed": true}` passa a valer na requisição seguinte, sem carregar código do projeto. Configuração inválida ou ausente nessa modalidade usa o modo corrigido. Essa chave didática demonstra revalidação e não é uma correção genérica de código de terceiros.

Execute a regressão isolada:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_security_appsec.py -q
```

A suíte testa os dois modos com HTTP e SQLite reais em loopback, sem acessar sites públicos. Os testes de cancelamento, limites e revogação usam controles instrumentados, identificados como testes do adaptador. Não atribua a esses resultados cobertura de OWASP ZAP ou Nuclei: esses são mecanismos independentes.
