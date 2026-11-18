$ErrorActionPreference = "Stop"

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Shim = Join-Path $env:LOCALAPPDATA "GitMortem\app\bin\gitmortem.cmd"
if (-not (Test-Path $Shim -PathType Leaf)) {
    Write-Host "[!] GitMortem is not installed for this user: run $(Join-Path $Here 'install.ps1') first"
    exit 1
}
& $Shim local @args
exit $LASTEXITCODE
