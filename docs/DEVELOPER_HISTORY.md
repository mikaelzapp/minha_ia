# Histórico e reversão de arquivos no Developer

O histórico registra escritas feitas pelo editor de ferramentas do NEXUS, tanto no workspace quanto nas pastas do PC autorizadas. Cada escrita preserva um snapshot antes e depois, o SHA-256, a localização relativa, a pasta autorizada e o resultado. A resposta da ferramenta inclui `change_id`.

Para reverter, abra o histórico do Developer, escolha uma alteração aplicada, examine o diff reverso e confirme. Se a escrita criou um arquivo, desfazer remove apenas esse arquivo; os diretórios criados permanecem. Se o arquivo já existia, o conteúdo anterior é restaurado, inclusive BOM UTF-8 e quebras de linha CRLF. Uma reversão também cria seu próprio registro, permitindo examinar e reverter essa operação posteriormente.

A aprovação vale para uma única operação por cinco minutos. Recusar ou deixar expirar preserva o arquivo. Arquivos alterados por outra edição depois da escrita não são sobrescritos pela reversão. Nesse caso, compare as versões e faça uma alteração manual aprovada.

## O que o histórico cobre

- Escritas de texto feitas pelas ferramentas integradas `write_file` e `pc_write_file`, após aprovação original do diff.
- Resultado `prepared`, `applied` ou `failed`, com hashes e tamanhos antes/depois.
- Reversões de alterações aplicadas e ainda não revertidas.
- Uma nova consulta às autorizações atuais na prévia e na execução da reversão.

Comandos, testes, Git, instaladores e programas podem modificar outros arquivos; essas alterações **não são capturadas automaticamente por este histórico**. A reversão também não desfaz mudanças em banco de dados, serviços, pacotes ou efeitos externos de comandos. Use Git e os backups do projeto para esse acompanhamento.

`prepared` indica que o snapshot foi gravado antes da chamada de escrita. Se o processo for interrompido nesse intervalo, o estado fica incerto e não é apresentado como uma alteração confirmada. O aplicativo não tenta uma reversão automática de registros incertos. `failed` indica que a ferramenta ou a verificação final não confirmou a escrita esperada.

## Integridade e armazenamento

Os snapshots ficam como BLOBs no banco local `data/developer/history.sqlite3`. Eles contêm o código original necessário para restauração exata e não são enviados para serviços externos nem incluídos integralmente na listagem HTTP. Inclua esse banco nos backups consistentes do aplicativo.

O diff exibido remove padrões de credenciais reconhecidos. O campo `diff_redacted` informa quando houve remoção; a restauração usa os bytes originais privados do snapshot, preservando o arquivo exato. A identificação de segredos não cobre todos os formatos possíveis. A biblioteca não oferece exportação pública dos snapshots completos.

Caminhos protegidos, segredos por nome, links, junctions, hardlinks e arquivos binários são rejeitados pelas mesmas verificações do editor existente. O banco e seus arquivos auxiliares SQLite também rejeitam links. A raiz autorizada é vinculada por hash; trocar a raiz ou revogar a autorização invalida a reversão.

A escrita e a reversão conferem o SHA-256 novamente antes de aplicar. No Windows, a remoção de arquivo criado usa um handle que impede escrita e substituição concorrentes durante a conferência e a exclusão. Escritas de texto usam o mecanismo existente de arquivo temporário, nova validação e substituição atômica; isso não constitui uma sandbox de sistema operacional nem um bloqueio geral sobre editores externos. Em outros sistemas, a exclusão repete as validações de caminho/hash, sem alegar o bloqueio específico do Windows.

O histórico aceita arquivos de até 256.000 bytes, até 1.000 registros e 64 MiB totais de snapshots. A listagem mostra os 100 registros mais recentes. Se não puder preservar o snapshot, a escrita integrada é cancelada antes de alterar o arquivo. Diffs reversos acima de 100.000 caracteres não recebem aprovação parcial; precisam de recuperação manual pelo backup. Não há limpeza automática de versões antigas.

## API humana

As rotas usam a autenticação local e a verificação de origem do aplicativo; não são ferramentas que o modelo possa chamar para aprovar sua própria reversão.

| Método e rota | Resultado |
| --- | --- |
| `GET /api/developer/changes` | `{changes:[...]}` com metadados e sem os snapshots. |
| `POST /api/developer/changes/{change_id}/preview` | `{ok:true,requires_approval:true,approval_id,preview}`. Nenhuma alteração de arquivo. |
| `POST /api/developer/changes/{approval_id}/decision` | Corpo `{"approved":true}` ou `{"approved":false}`; consome uma única aprovação. |

A prévia contém `action`, `change_id`, `path`, `root_id`, `diff`, `current_sha256`, `restored_sha256`, `current_exists`, `restores_missing`, `removes_created_file`, `diff_redacted` e `reason`. Os argumentos aprovados ficam congelados no servidor com digest de integridade; a decisão não aceita outro caminho, conteúdo ou hash.

A decisão afirmativa confere novamente a autorização e o arquivo. Sucesso retorna `change_id` do registro inverso, `restored_change_id`, `path`, `root_id`, `exists`, `sha256` e `removed_created_file`. Erros de integridade e de versão retornam HTTP 409, como `history_file_changed`, `history_root_changed` e `history_snapshot_invalid`. Decisões ausentes, vencidas ou já consumidas retornam 404. Os erros incluem `source: developer_history`, diferenciando problemas operacionais de respostas do modelo.

## Validação automatizada

`tests/test_developer_history.py` usa arquivos reais temporários para validar escrita e reversão, preservação de arquivos vazios, exclusão segura no Windows, reversão do registro inverso, hashes e alterações concorrentes, revogação de autorização, snapshots adulterados, hardlinks, quotas, redaction de credenciais, reinicialização e preservação de dados anteriores. Os testes HTTP cobrem confirmação, recusa, expiração, uso único, argumentos congelados e decisões estritamente booleanas.
