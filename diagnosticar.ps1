[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Execute .\instalar.ps1 primeiro.' }
& $pythonPath -m nexus.diagnostics
if ($LASTEXITCODE -ne 0) { throw 'Falha ao coletar diagnóstico.' }
Write-Host 'Relatório: reports\diagnostico.json'
