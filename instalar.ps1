[CmdletBinding()]
param([switch]$BaixarModelo, [switch]$BaixarEmbeddings, [switch]$BaixarCoder, [switch]$InstalarContinue, [switch]$TestarModelo)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\ambiente.ps1')
Update-NexusPath
$basePython = Find-NexusPython -Root $PSScriptRoot
if (-not $basePython) { throw 'Python x64 3.11+ necessário. Execute instalar.bat para preparar os programas.' }
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) { throw 'Ollama nativo necessário: https://ollama.com/download/windows . Instale e execute novamente.' }
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { & $basePython -m venv .venv; if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar ambiente virtual.' } }
& $pythonPath -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) and sys.maxsize > 2**32 else 1)'
if ($LASTEXITCODE -ne 0) { throw 'O .venv existente e incompativel. Preserve-o e recrie o ambiente com Python x64 3.11+.' }
$requirements = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'requirements-lock.txt')) { 'requirements-lock.txt' } else { 'requirements.txt' }
& $pythonPath -m pip install -r $requirements --disable-pip-version-check
if ($LASTEXITCODE -ne 0) { throw 'Falha nas dependências. Verifique acesso ao PyPI.' }
& $pythonPath -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependencias Python inconsistentes.' }
New-Item -ItemType Directory -Force -Path 'data','workspaces','reports','.runtime' | Out-Null
& $pythonPath -m nexus.diagnostics
if ($LASTEXITCODE -ne 0) { throw 'Falha no diagnóstico.' }
if ($BaixarModelo -or $BaixarEmbeddings -or $BaixarCoder -or $TestarModelo) { Start-NexusOllama -Root $PSScriptRoot }
if ($BaixarModelo) {
    Write-Host 'Download explícito: Qwen3.5 4B Q4_K_M, aproximadamente 3,4 GB; reserve 5 GB.'
    & ollama pull 'qwen3.5:4b-q4_K_M'
    if ($LASTEXITCODE -ne 0) { throw 'Falha no download do modelo.' }
}
if ($BaixarEmbeddings) {
    Write-Host 'Download explícito: EmbeddingGemma, aproximadamente 622 MB; reserve 1 GB.'
    & ollama pull embeddinggemma
    if ($LASTEXITCODE -ne 0) { throw 'Falha no download dos embeddings.' }
    & $pythonPath -m nexus.setup --embeddings
} else { & $pythonPath -m nexus.setup }
if ($LASTEXITCODE -ne 0) { throw 'Falha na configuração local.' }
if ($BaixarCoder) {
    Write-Host 'Download explícito: Qwen2.5-Coder 7B Q4_K_M, aproximadamente 4,7 GB; reserve 6 GB.'
    & ollama pull 'qwen2.5-coder:7b'
    if ($LASTEXITCODE -ne 0) { throw 'Falha no download do especialista de programação.' }
    & $pythonPath -m nexus.setup --coding-model 'qwen2.5-coder:7b'
    if ($LASTEXITCODE -ne 0) { throw 'Falha na configuração do especialista.' }
}
if ($InstalarContinue) { & (Join-Path $PSScriptRoot 'scripts\configurar-vscode.ps1') }
& $pythonPath -m pytest tests -q
if ($LASTEXITCODE -ne 0) { throw 'Testes locais falharam.' }
if ($TestarModelo) { & $pythonPath -m nexus.benchmark --quick; if ($LASTEXITCODE -ne 0) { throw 'Falha no benchmark.' } }
Write-Host 'Instalação pronta. Inicie com .\iniciar.ps1 -Abrir'
