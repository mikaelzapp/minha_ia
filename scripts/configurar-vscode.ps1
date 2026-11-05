[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$rootPath = Split-Path -Parent $PSScriptRoot
$code = Get-Command code -ErrorAction SilentlyContinue
if (-not $code) { throw 'VS Code CLI não encontrado no PATH.' }
$userPath = Join-Path $rootPath 'data\vscode-user'
$extensionsPath = Join-Path $rootPath 'data\vscode-extensions'
$continuePath = Join-Path $rootPath 'data\continue'
New-Item -ItemType Directory -Force -Path $userPath,$extensionsPath,$continuePath,(Join-Path $userPath 'User') | Out-Null
$env:CONTINUE_GLOBAL_DIR = $continuePath
$configPath = Join-Path $continuePath 'config.yaml'
if (-not (Test-Path -LiteralPath $configPath)) {
    Copy-Item -LiteralPath (Join-Path $rootPath 'integrations\continue.yaml') -Destination $configPath
}
$settingsPath = Join-Path $userPath 'User\settings.json'
if (-not (Test-Path -LiteralPath $settingsPath)) {
    @{
        'telemetry.telemetryLevel'='off'
        'continue.telemetryEnabled'=$false
        'continue.enableTabAutocomplete'=$false
        'continue.enableNextEdit'=$false
        'continue.enableIndexing'=$false
        'workbench.colorTheme'='Default Dark Modern'
        'security.workspace.trust.enabled'=$true
    } | ConvertTo-Json | Set-Content -LiteralPath $settingsPath -Encoding UTF8
}
& $code.Source --user-data-dir $userPath --extensions-dir $extensionsPath --install-extension Continue.continue
if ($LASTEXITCODE -ne 0) { throw 'Falha ao instalar Continue no perfil isolado. Seu VS Code original não foi alterado.' }
& $code.Source --user-data-dir $userPath --extensions-dir $extensionsPath --list-extensions --show-versions
Write-Host 'Continue configurado somente no perfil local NEXUS. Abra com .\vscode.ps1.'
