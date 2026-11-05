[CmdletBinding()]
param([switch]$PararOllamaProprio)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$runtimePath = Join-Path $PSScriptRoot '.runtime'
$names = @('server.json')
if ($PararOllamaProprio) { $names += 'ollama.json' }
foreach ($name in $names) {
    $path = Join-Path $runtimePath $name
    if (-not (Test-Path -LiteralPath $path)) { continue }
    & (Join-Path $PSScriptRoot '.venv\Scripts\python.exe') -m nexus.lifecycle $path
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao encerrar árvore identificada do NEXUS.' }
}
Write-Host 'Ollama, modelos e serviços preexistentes foram preservados.'
