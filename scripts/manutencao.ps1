[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Instalar', 'Atualizar')][string]$Acao,
    [switch]$Basico,
    [switch]$SemModelos,
    [switch]$SomenteDependencias,
    [switch]$AtualizarProgramas,
    [switch]$InstalarSeguranca,
    [switch]$Verificar
)
$ErrorActionPreference = 'Stop'
$rootPath = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $rootPath
. (Join-Path $PSScriptRoot 'ambiente.ps1')

function Invoke-WingetPackage {
    param([string]$Id, [switch]$Upgrade)
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { throw 'WinGet ausente. Instale/atualize o Instalador de Aplicativo pela Microsoft Store e execute novamente: https://aka.ms/getwinget' }
    $operation = if ($Upgrade) { 'upgrade' } else { 'install' }
    Write-Host "WinGet $operation : $Id"
    & $winget.Source $operation --id $Id --exact --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
    $code = $LASTEXITCODE
    # APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE: ja esta atualizado.
    if ($code -ne 0 -and $code -ne -1978335189) { throw "WinGet falhou para $Id (codigo $code). Corrija o erro acima e execute novamente." }
    Update-NexusPath
}

try {
    if ($Verificar) {
        Write-Host "PREVIA: $Acao NEXUS em $rootPath. Nenhum arquivo ou programa sera alterado."
        Write-Host 'Necessarios: Python x64 3.11+ (instalacao nova: 3.12), Git, Ollama, pacotes Python e Chromium local.'
        if (-not $Basico) { Write-Host 'Perfil completo: tambem VS Code, Continue e Qwen2.5-Coder 7B.' }
        if (-not $SemModelos) { Write-Host 'Modelos: principal e embeddings configurados; instalacao nova usa Qwen3.5 4B e EmbeddingGemma.' }
        if ($Acao -eq 'Atualizar') { Write-Host 'Atualizacao: backup local, git pull --ff-only quando houver .git, pip upgrade, testes e registro local das versoes.' }
        if ($InstalarSeguranca) { Write-Host 'Extra solicitado: Java/Ghidra/ZAP/Nuclei portateis com hashes fixados; revisar configuracao no painel.' }
        if ($AtualizarProgramas) { Write-Host 'Atualizacao adicional via WinGet somente dos programas do perfil.' }
        return
    }
    $env:PYTHONUTF8 = '1'
    $env:PIP_REQUIRE_VIRTUALENV = 'true'
    Update-NexusPath
    Write-Host "NEXUS AI - $Acao"
    Write-Host 'A preparacao pode baixar varios GB. Etapas concluidas sao reaproveitadas ao executar novamente.'

    # Recusar mudancas locais antes de instalar/atualizar qualquer componente.
    $versioned = Test-Path -LiteralPath (Join-Path $rootPath '.git')
    if ($Acao -eq 'Atualizar' -and $versioned -and -not $SomenteDependencias) {
        $gitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
        if (-not $gitCommand) { throw 'Git ausente; execute instalar.bat primeiro.' }
        $changes = & $gitCommand.Source -c "safe.directory=$rootPath" status --porcelain
        if ($LASTEXITCODE -ne 0) { throw 'Nao foi possivel verificar o repositorio Git.' }
        if ($changes) { throw 'Existem alteracoes locais. Salve/commit suas alteracoes antes de atualizar, ou use atualizar.bat -SomenteDependencias.' }
    }
    $basePython = Find-NexusPython -Root $rootPath
    if (-not $basePython) {
        Invoke-WingetPackage -Id 'Python.Python.3.12'
        $basePython = Find-NexusPython -Root $rootPath
        if (-not $basePython) { throw 'Python x64 3.11+ nao localizado apos instalar. Reabra instalar.bat.' }
    }
    foreach ($package in @(@{Command='git.exe'; Id='Git.Git'}, @{Command='ollama.exe'; Id='Ollama.Ollama'})) {
        if (-not (Get-Command $package.Command -ErrorAction SilentlyContinue)) { Invoke-WingetPackage -Id $package.Id }
        if (-not (Get-Command $package.Command -ErrorAction SilentlyContinue)) { throw "$($package.Command) nao localizado apos instalar. Reabra instalar.bat." }
    }
    if (-not $Basico -and -not (Get-Command code -ErrorAction SilentlyContinue)) { Invoke-WingetPackage -Id 'Microsoft.VisualStudioCode' }

    if ($Acao -eq 'Atualizar' -and (Test-Path -LiteralPath (Join-Path $rootPath '.venv\Scripts\python.exe'))) {
        & (Join-Path $rootPath 'atualizar.ps1') -AtualizarDependencias -AtualizarCodigo:(-not $SomenteDependencias)
    } elseif ($Acao -eq 'Atualizar') {
        throw 'Ambiente virtual ausente. Execute instalar.bat antes de atualizar.'
    } else {
        & (Join-Path $rootPath 'instalar.ps1')
    }

    if ($AtualizarProgramas) {
        # Python permanece na serie 3.12; nao ha winget upgrade --all.
        $ids = @('Git.Git', 'Ollama.Ollama')
        if ($basePython -like '*Python312*') { $ids += 'Python.Python.3.12' }
        if (-not $Basico) { $ids += 'Microsoft.VisualStudioCode' }
        foreach ($id in $ids) { Invoke-WingetPackage -Id $id -Upgrade }
    }
    $pythonPath = Join-Path $rootPath '.venv\Scripts\python.exe'
    $env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $rootPath '.browsers'
    & $pythonPath -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao preparar Chromium. Verifique conexao/espaco e execute novamente.' }

    if (-not $SemModelos) {
        # Ler a configuracao depois da atualizacao; nunca substituir modelo escolhido pelo usuario.
        $settingsText = & $pythonPath -c 'import json; from nexus.config import Settings; print(json.dumps(Settings().public()))'
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao ler configuracao dos modelos.' }
        $settings = $settingsText | ConvertFrom-Json
        Start-NexusOllama -Root $rootPath -Url $settings.ollama_url
        $models = @($settings.model)
        $embedding = if ($settings.embedding_model) { $settings.embedding_model } else { 'embeddinggemma' }
        $models += $embedding
        if (-not $Basico) {
            $coder = if ($settings.coding_model) { $settings.coding_model } else { 'qwen2.5-coder:7b' }
            $models += $coder
        }
        $previousOllamaHost = $env:OLLAMA_HOST
        try {
            $env:OLLAMA_HOST = $settings.ollama_url
            foreach ($model in ($models | Select-Object -Unique)) {
                Write-Host "Preparando modelo: $model"
                & ollama.exe pull $model
                if ($LASTEXITCODE -ne 0) { throw "Falha ao baixar/atualizar $model. Execute novamente para retomar." }
            }
        } finally { $env:OLLAMA_HOST = $previousOllamaHost }
        if (-not $settings.embedding_model) {
            & $pythonPath -m nexus.setup --embeddings
            if ($LASTEXITCODE -ne 0) { throw 'Falha ao configurar embeddings.' }
        }
        if (-not $Basico -and -not $settings.coding_model) {
            & $pythonPath -m nexus.setup --coding-model $coder
            if ($LASTEXITCODE -ne 0) { throw 'Falha ao configurar modelo de programacao.' }
        }
    }
    if (-not $Basico) {
        & (Join-Path $PSScriptRoot 'configurar-vscode.ps1')
    }
    if ($InstalarSeguranca) {
        & $pythonPath (Join-Path $PSScriptRoot 'configurar_seguranca.py') --instalar
        if ($LASTEXITCODE -ne 0) { throw 'Falha nas ferramentas opcionais de seguranca. Etapas anteriores foram preservadas.' }
    }
    & $pythonPath -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'Dependencias Python inconsistentes.' }
    Write-Host 'Concluido. Abra Iniciar NEXUS.cmd para usar o assistente.' -ForegroundColor Green
    exit 0
} catch {
    Write-Host "ERRO: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Consulte a mensagem acima. Corrija a causa e execute o mesmo arquivo novamente.'
    exit 1
}
