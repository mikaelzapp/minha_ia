[CmdletBinding()]
param([int]$Porta = 8765, [switch]$Abrir)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($PSScriptRoot)
Set-Location -LiteralPath $rootPath
$pythonPath = Join-Path $rootPath '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Execute .\instalar.ps1 primeiro.' }
$runtimePath = Join-Path $rootPath '.runtime'
New-Item -ItemType Directory -Force -Path $runtimePath | Out-Null
$pidPath = Join-Path $runtimePath 'server.json'
if (Test-Path -LiteralPath $pidPath) {
    $existing = Get-Content -LiteralPath $pidPath -Raw | ConvertFrom-Json
    $process = Get-Process -Id $existing.pid -ErrorAction SilentlyContinue
    if ($process -and $process.Path -eq $pythonPath -and $process.StartTime.ToUniversalTime().ToString('o') -eq $existing.started) {
        Write-Host "NEXUS já está em execução: http://127.0.0.1:$($existing.port)"
        if ($Abrir) { Start-Process "http://127.0.0.1:$($existing.port)" }
        return
    }
}
$probe = New-Object Net.Sockets.TcpClient
try { $probe.Connect('127.0.0.1', $Porta); throw "A porta $Porta está ocupada. Use -Porta com uma porta livre." }
catch [Net.Sockets.SocketException] { } finally { $probe.Dispose() }
try { Invoke-RestMethod 'http://127.0.0.1:11434/api/version' -TimeoutSec 5 | Out-Null }
catch {
    $ollama = Get-Command ollama -ErrorAction SilentlyContinue
    if (-not $ollama) { throw 'Ollama não encontrado. Consulte o README.' }
    # Configuração apenas deste processo novo; nunca reinicia um Ollama existente.
    $env:OLLAMA_HOST = '127.0.0.1:11434'
    $env:OLLAMA_NUM_PARALLEL = '1'
    $env:OLLAMA_MAX_LOADED_MODELS = '1'
    $ollamaProcess = Start-Process -FilePath $ollama.Source -ArgumentList 'serve' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimePath 'ollama.out.log') -RedirectStandardError (Join-Path $runtimePath 'ollama.err.log')
    @{pid=$ollamaProcess.Id; started=$ollamaProcess.StartTime.ToUniversalTime().ToString('o'); path=$ollama.Source} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtimePath 'ollama.json') -Encoding UTF8
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        try { Invoke-RestMethod 'http://127.0.0.1:11434/api/version' -TimeoutSec 2 | Out-Null; $ready = $true; break } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw 'Ollama não iniciou; consulte .runtime\ollama.err.log.' }
}
$env:PYTHONUTF8 = '1'
$process = Start-Process -FilePath $pythonPath -ArgumentList @('-m','uvicorn','nexus.app:app','--host','127.0.0.1','--port',"$Porta",'--no-access-log') -WorkingDirectory $rootPath -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimePath 'server.out.log') -RedirectStandardError (Join-Path $runtimePath 'server.err.log')
@{pid=$process.Id; started=$process.StartTime.ToUniversalTime().ToString('o'); port=$Porta; path=$pythonPath} | ConvertTo-Json | Set-Content -LiteralPath $pidPath -Encoding UTF8
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    try { $response = Invoke-WebRequest "http://127.0.0.1:$Porta/" -UseBasicParsing -TimeoutSec 2; if ($response.StatusCode -eq 200) { $ready = $true; break } } catch { Start-Sleep -Milliseconds 500 }
    if ($process.HasExited) { break }
}
if (-not $ready) { Get-Content -LiteralPath (Join-Path $runtimePath 'server.err.log') -Tail 30; throw 'NEXUS não ficou pronto.' }
Write-Host "NEXUS AI: http://127.0.0.1:$Porta"
Write-Host 'Somente localhost. Para parar: .\parar.ps1'
if ($Abrir) { Start-Process "http://127.0.0.1:$Porta" }
