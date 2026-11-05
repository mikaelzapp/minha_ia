# Instalar e atualizar no Windows

Baixe o projeto de [mikaelzapp/minha_ia](https://github.com/mikaelzapp/minha_ia), extraia o ZIP inteiro para uma pasta e dê dois cliques em **instalar.bat**. Mantenha o arquivo junto das pastas `scripts`, `nexus` e dos demais arquivos do projeto. Ao terminar, abra **Iniciar NEXUS.cmd**. Nas próximas vezes, execute **atualizar.bat** para atualizar a instalação.

Os arquivos `.bat` usam o Windows PowerShell e encaminham os parâmetros para `scripts/manutencao.ps1`. A janela fica aberta no fim para você ler o resultado, incluindo erros. A política `ExecutionPolicy Bypass` vale somente para esse processo PowerShell; não muda a política global do Windows.

## O que é instalado

O perfil completo é o padrão e prepara:

- Python x64 3.11 ou superior; se não encontrar uma instalação compatível, instala Python 3.12 pelo WinGet.
- Git, Ollama e Visual Studio Code, instalados pelo WinGet quando ausentes.
- Ambiente Python `.venv` e pacotes de `requirements-lock.txt`, com fallback para `requirements.txt` quando não houver lock.
- Chromium do Playwright dentro de `.browsers`.
- Modelo principal, embeddings e especialista de programação no Ollama, respeitando os nomes já configurados. Numa instalação nova, os padrões são `qwen3.5:4b-q4_K_M`, `embeddinggemma` e `qwen2.5-coder:7b`.
- Continue em perfil do VS Code próprio do NEXUS, dentro de `data`, e configuração local da aplicação.
- Verificações das dependências e testes locais previstos pelo instalador.

É necessária internet para baixar programas, pacotes, navegador e modelos. Reserve vários GB de espaço e franquia de dados: os modelos padrão somam aproximadamente 9 GB, além dos programas e dependências. O tamanho e o tempo dos downloads podem variar.

O WinGet precisa estar disponível para instalar os programas ausentes. Ele vem com o **Instalador de Aplicativo** do Windows. Se o script informar que não o encontrou, instale ou atualize esse componente pela Microsoft Store e tente novamente. Você pode iniciar sem privilégios de administrador; algum instalador pode solicitar confirmação do Windows (UAC).

Os comandos usados estão descritos na documentação oficial de [instalação de programas pelo WinGet](https://learn.microsoft.com/windows/package-manager/winget/install) e [atualização pelo WinGet](https://learn.microsoft.com/windows/package-manager/winget/upgrade).

O script verifica a disponibilidade do servidor Ollama configurado antes de baixar os modelos. Se você usa uma URL personalizada em `ollama_url`, inicie esse servidor antes de executar a instalação ou atualização. Com a URL local padrão, o script pode iniciar o Ollama quando necessário.

## Instalação menor e outros parâmetros

Abra um terminal na pasta do projeto e execute os comandos abaixo. Os exemplos usam PowerShell; os mesmos parâmetros podem ser usados pelo Prompt de Comando.

| Comando | Resultado |
| --- | --- |
| `.\instalar.bat` | Instala o perfil completo. |
| `.\instalar.bat -Basico` | Prepara Python, Git, Ollama, pacotes, Chromium e modelos principal/embeddings; dispensa VS Code, Continue e o modelo coder. |
| `.\instalar.bat -SemModelos` | Prepara o ambiente sem executar downloads de modelos do Ollama. |
| `.\instalar.bat -Basico -SemModelos` | Combina as duas opções. |
| `.\instalar.bat -InstalarSeguranca` | Inclui os runtimes opcionais de segurança descritos abaixo. |
| `.\instalar.bat -Verificar` | Mostra o plano das etapas, sem verificar componentes nem alterar a instalação. |

`-SemModelos` não impede downloads de Python, pacotes, Chromium ou programas. Para conversar e indexar com os modelos locais, eles precisam estar disponíveis no Ollama. Você pode rodar o instalador novamente sem essa opção para baixá-los.

## Atualizar

Execute **atualizar.bat** para atualizar o código quando a pasta for um clone Git, atualizar dependências Python, validar o ambiente, registrar as versões instaladas, sincronizar os modelos configurados e instalar a versão do Chromium exigida pelo Playwright. A configuração local existente é preservada. A aplicação deve ser iniciada novamente com **Iniciar NEXUS.cmd** depois da manutenção.

Antes da atualização de código, o script exige uma árvore Git limpa, a branch `main` e o remoto `origin` apontando para `mikaelzapp/minha_ia`. Ele cria um backup e usa `git pull --ff-only origin main`. Se houver alterações locais ou commits incompatíveis com esse avanço, ele interrompe a atualização de código e mostra o motivo. Revise suas alterações antes de tentar novamente ou use `-SomenteDependencias` para atualizar o ambiente sem buscar alterações de código.

Após os testes, as versões instaladas são registradas em `.runtime/requirements-installed.txt`, que fica fora do controle de versão. O arquivo `requirements-lock.txt` do repositório continua servindo como referência da instalação reproduzível; a atualização de pacotes não o reescreve nem cria essa alteração pendente no Git. Uma atualização de código pode trazer uma nova versão desse lock publicada no repositório.

| Comando | Resultado |
| --- | --- |
| `.\atualizar.bat` | Atualiza o código pelo Git quando disponível e os componentes do perfil completo. |
| `.\atualizar.bat -Basico` | Usa o perfil básico também durante a atualização. |
| `.\atualizar.bat -SomenteDependencias` | Pula a atualização de código por Git e realiza a manutenção das dependências. |
| `.\atualizar.bat -SemModelos` | Pula a sincronização dos modelos. |
| `.\atualizar.bat -AtualizarProgramas` | Também solicita ao WinGet atualizações dos programas usados por este perfil. Não atualiza todos os aplicativos do computador. |
| `.\atualizar.bat -InstalarSeguranca` | Inclui a instalação dos runtimes opcionais de segurança. |
| `.\atualizar.bat -Verificar` | Mostra o plano das etapas, sem verificar componentes nem alterar a instalação. |

Os backups ficam em `reports`. Quando uma etapa falha, o script informa o erro e preserva o backup criado. Ele não promete desfazer automaticamente todas as mudanças, como uma atualização de programa feita pelo WinGet. Corrija o erro informado e execute novamente. Consulte o caminho de backup exibido no terminal antes de restaurar arquivos.

### ZIP ou clone Git

Um ZIP baixado pelo GitHub não contém a pasta `.git`. Nesse caso, `atualizar.bat` avisa que não pode atualizar o código e continua com a manutenção das dependências. Para receber também novas versões do código pelo script, use um clone:

```powershell
git clone https://github.com/mikaelzapp/minha_ia.git
cd minha_ia
.\instalar.bat
```

Se você já usa a versão extraída do ZIP, crie o clone em outra pasta. Não apague a instalação anterior: ela pode conter suas conversas, configurações, modelos locais e projetos. Planeje a transferência dos seus dados antes de trocar de instalação.

## Automação sem pausa

Defina `NEXUS_SEM_PAUSA=1` para que os `.bat` terminem sem esperar uma tecla. O código de saída é `0` em caso de sucesso e diferente de `0` em caso de erro.

No PowerShell:

```powershell
$env:NEXUS_SEM_PAUSA = '1'
.\instalar.bat -Verificar
$LASTEXITCODE
```

No Prompt de Comando:

```bat
set NEXUS_SEM_PAUSA=1
call atualizar.bat -SomenteDependencias -SemModelos
echo %ERRORLEVEL%
```

## Recursos opcionais e projetos próprios

`-InstalarSeguranca` chama explicitamente `scripts/configurar_seguranca.py --instalar` para baixar os runtimes portáteis de Java, Ghidra, ZAP e Nuclei nas versões fixadas pelo projeto e preparar seus caminhos e hashes locais. É um download adicional e pode exigir bastante disco e memória. Caminhos e hashes novos ficam pendentes de aprovação: revise e aprove a configuração pelo painel do Security Center antes de usar as ferramentas. Instalar esses programas não comprova que todos os módulos ou análises tenham sido executados com sucesso. Consulte [Security Center](SECURITY_CENTER.md) e [compatibilidade](SECURITY_COMPATIBILITY.md) para configurar e verificar cada integração.

Tor e um servidor REA MCP não são instalados nem configurados automaticamente por esses `.bat`. Ative essas integrações separadamente quando precisar delas, seguindo o [guia de uso](GUIA_DE_USO.md) e a documentação do Security Center. Docker, WSL e SearXNG também não fazem parte dessa instalação automática.

Os scripts preparam o **NEXUS AI**. Projetos que você colocar em `workspaces` podem ter dependências próprias: por exemplo, `package.json`, outro `requirements.txt`, bancos ou SDKs. Essas dependências não são detectadas nem instaladas automaticamente pelo instalador do NEXUS. Siga as instruções de cada projeto e use ambientes separados quando necessário.
