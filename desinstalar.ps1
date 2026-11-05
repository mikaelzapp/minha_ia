[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param([switch]$RemoverAmbiente, [switch]$RemoverDados)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
& (Join-Path $rootPath 'parar.ps1')
$targets = @()
if ($RemoverAmbiente) { $targets += '.venv','.browsers' }
if ($RemoverDados) { $targets += 'data' }
foreach ($relative in $targets) {
    $candidate = [IO.Path]::GetFullPath((Join-Path $rootPath $relative))
    if (-not $candidate.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Destino fora do projeto.' }
    if (Test-Path -LiteralPath $candidate) {
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Link/junction recusado na remoção.' }
        $links = Get-ChildItem -LiteralPath $candidate -Force -Recurse | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
        if ($links) { throw 'Subdiretório com link/junction; remova manualmente após revisão.' }
        if ($PSCmdlet.ShouldProcess($candidate, 'Remover somente componente NEXUS selecionado')) { Remove-Item -LiteralPath $candidate -Recurse -Force }
    }
}
Write-Host 'Código, projetos em workspaces, modelos Ollama e containers foram preservados.'
