[CmdletBinding()]
param([switch]$AtualizarDependencias, [switch]$AtualizarCodigo)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Execute instalar.bat antes de atualizar.' }
$hasGit = Test-Path -LiteralPath (Join-Path $PSScriptRoot '.git')
if ($AtualizarCodigo -and $hasGit) {
    $gitRoot = & git.exe -c "safe.directory=$PSScriptRoot" rev-parse --show-toplevel
    if ($LASTEXITCODE -ne 0 -or [IO.Path]::GetFullPath($gitRoot) -ne [IO.Path]::GetFullPath($PSScriptRoot)) { throw 'A pasta atual nao e a raiz do repositorio Git.' }
    $origin = & git.exe -c "safe.directory=$PSScriptRoot" remote get-url origin
    if ($LASTEXITCODE -ne 0 -or $origin -notmatch '^(https://github\.com/|git@github\.com:)mikaelzapp/minha_ia(?:\.git)?/?$') { throw 'O remote origin deve apontar para https://github.com/mikaelzapp/minha_ia.git.' }
    $branch = & git.exe -c "safe.directory=$PSScriptRoot" branch --show-current
    if ($LASTEXITCODE -ne 0 -or $branch -ne 'main') { throw 'Atualizacao automatica de codigo exige a branch main. Salve seu trabalho antes de trocar de branch.' }
    $changes = & git.exe -c "safe.directory=$PSScriptRoot" status --porcelain
    if ($LASTEXITCODE -ne 0 -or $changes) { throw 'Salve/commit as alteracoes locais antes de atualizar o codigo. Para atualizar apenas pacotes, use atualizar.bat -SomenteDependencias.' }
}
& (Join-Path $PSScriptRoot 'parar.ps1')
$backupPath = Join-Path $PSScriptRoot ('reports\backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $backupPath | Out-Null
# A API SQLite inclui WAL; o backup continua local e nao inclui auth.secret.
& $pythonPath -m nexus.setup --backup $backupPath
if ($LASTEXITCODE -ne 0) { throw 'Backup falhou; atualizacao cancelada.' }
$installed = & $pythonPath -m pip freeze
if ($LASTEXITCODE -ne 0) { throw 'Falha ao registrar dependencias anteriores; atualizacao cancelada.' }
$installed | Set-Content -LiteralPath (Join-Path $backupPath 'requirements-installed.txt') -Encoding UTF8
Write-Host "Backup preservado em $backupPath"
if ($AtualizarCodigo) {
    if ($hasGit) {
        $previousCommit = & git.exe -c "safe.directory=$PSScriptRoot" rev-parse HEAD
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao registrar versao anterior.' }
        $previousCommit | Set-Content -LiteralPath (Join-Path $backupPath 'git-head.txt') -Encoding ASCII
        & git.exe -c "safe.directory=$PSScriptRoot" pull --ff-only origin main
        if ($LASTEXITCODE -ne 0) { throw "Git pull falhou. Nenhuma mesclagem forcada foi feita. Backup: $backupPath" }
    } else {
        Write-Warning 'Pasta obtida por ZIP/sem .git: codigo nao foi atualizado. Para isso, use git clone; consulte docs/INSTALACAO_WINDOWS.md.'
    }
}
if ($AtualizarDependencias) {
    & $pythonPath -m pip install --upgrade -r requirements.txt --disable-pip-version-check
} else {
    & $pythonPath -m pip install -r requirements-lock.txt --disable-pip-version-check
}
if ($LASTEXITCODE -ne 0) { throw "Falha nos pacotes; backup preservado em $backupPath. Restaure com python -m pip install -r requirements-installed.txt do backup." }
& $pythonPath -m pip check
if ($LASTEXITCODE -ne 0) { throw "Dependencias inconsistentes. Backup: $backupPath" }
& $pythonPath -m nexus.setup
if ($LASTEXITCODE -ne 0) { throw "Falha na configuracao. Backup: $backupPath" }
& $pythonPath -m pytest tests -q
if ($LASTEXITCODE -ne 0) { throw "Testes falharam. O backup foi preservado em $backupPath; consulte-o antes de reiniciar." }
# O lock do ambiente local fica ignorado pelo Git para permitir proximas atualizacoes.
New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot '.runtime') | Out-Null
$validated = & $pythonPath -m pip freeze
if ($LASTEXITCODE -ne 0) { throw 'Falha ao registrar as versoes validadas.' }
$validated | Set-Content -LiteralPath (Join-Path $PSScriptRoot '.runtime\requirements-installed.txt') -Encoding UTF8
Write-Host "Atualizacao validada. Backup: $backupPath. Inicie novamente com Iniciar NEXUS.cmd."
