# Funcoes compartilhadas; carregar este arquivo nao instala nem inicia programas.
function Update-NexusPath {
    $extraPaths = @(
        [Environment]::GetEnvironmentVariable('Path', 'Machine'),
        [Environment]::GetEnvironmentVariable('Path', 'User'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Ollama'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code\bin'),
        (Join-Path $env:ProgramFiles 'Git\cmd'),
        (Join-Path $env:ProgramFiles 'Microsoft VS Code\bin')
    )
    $env:Path = ((@($env:Path) + $extraPaths) -join ';').Split(';') |
        Where-Object { $_ } | Select-Object -Unique | Join-NexusPath
}

function Join-NexusPath {
    begin { $items = @() }
    process { $items += $_ }
    end { $items -join ';' }
}

function Find-NexusPython {
    param([string]$Root)
    $candidates = @((Join-Path $Root '.venv\Scripts\python.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'))
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command -and $command.Source -notlike '*\Microsoft\WindowsApps\*') { $candidates += $command.Source }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        foreach ($version in @('-3.12', '-3.11')) {
            try {
                $candidate = & $launcher.Source $version -c 'import sys; print(sys.executable)' 2>$null
                if ($LASTEXITCODE -eq 0) { $candidates += $candidate }
            } catch { }
        }
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            & $candidate -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) and sys.maxsize > 2**32 else 1)' 2>$null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        } catch { }
    }
    return $null
}

function Start-NexusOllama {
    param([string]$Root, [string]$Url = 'http://127.0.0.1:11434')
    try { Invoke-RestMethod "$Url/api/version" -TimeoutSec 3 | Out-Null; return }
    catch { }
    if ($Url -ne 'http://127.0.0.1:11434') { throw "Inicie seu servidor Ollama configurado em $Url e execute novamente." }
    $ollamaCommand = Get-Command ollama.exe -ErrorAction SilentlyContinue
    if (-not $ollamaCommand) { throw 'Ollama ausente. Execute instalar.bat.' }
    $runtime = Join-Path $Root '.runtime'
    New-Item -ItemType Directory -Force -Path $runtime | Out-Null
    $savedEnvironment = @{}
    foreach ($name in @('OLLAMA_HOST', 'OLLAMA_NUM_PARALLEL', 'OLLAMA_MAX_LOADED_MODELS')) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    try {
        $env:OLLAMA_HOST = '127.0.0.1:11434'
        $env:OLLAMA_NUM_PARALLEL = '1'
        $env:OLLAMA_MAX_LOADED_MODELS = '1'
        $service = Start-Process -FilePath $ollamaCommand.Source -ArgumentList 'serve' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtime 'ollama.out.log') -RedirectStandardError (Join-Path $runtime 'ollama.err.log')
        @{pid=$service.Id; started=$service.StartTime.ToUniversalTime().ToString('o'); path=$ollamaCommand.Source} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtime 'ollama.json') -Encoding UTF8
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            try { Invoke-RestMethod 'http://127.0.0.1:11434/api/version' -TimeoutSec 2 | Out-Null; return }
            catch { Start-Sleep -Milliseconds 500 }
        }
        throw 'Ollama nao respondeu. Consulte .runtime\ollama.err.log e execute novamente.'
    } finally {
        foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
    }
}
