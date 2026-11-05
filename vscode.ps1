[CmdletBinding()]
param([string]$Projeto = 'workspaces')
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
$projectPath = [IO.Path]::GetFullPath((Join-Path $rootPath $Projeto))
if (-not $projectPath.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Selecione um projeto dentro de NEXUS.' }
if (-not (Test-Path -LiteralPath $projectPath -PathType Container)) { throw 'Pasta não encontrada.' }
$env:CONTINUE_GLOBAL_DIR = Join-Path $rootPath 'data\continue'
$userPath = Join-Path $rootPath 'data\vscode-user'
$extensionPath = Join-Path $rootPath 'data\vscode-extensions'
if (-not (Test-Path -LiteralPath $extensionPath)) { throw 'Execute .\scripts\configurar-vscode.ps1 primeiro.' }
& code --user-data-dir $userPath --extensions-dir $extensionPath --new-window $projectPath
