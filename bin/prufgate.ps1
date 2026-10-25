<#
.SYNOPSIS
    PrufGate for Windows PowerShell.
.DESCRIPTION
    Runs prufgate/cli.py with Python 3 and passes every argument through, e.g.
    .\bin\prufgate.ps1 check . --changed --base origin/main --format sarif
    With -Docker it runs the locally built container instead (build it with -Build).
#>

$ErrorActionPreference = "Stop"
$PrufGateDir = if ($env:PRUFGATE_DIR -and (Test-Path "$env:PRUFGATE_DIR\prufgate\cli.py")) { $env:PRUFGATE_DIR } else { (Split-Path -Parent $PSScriptRoot) }
$CliPy = Join-Path $PrufGateDir "prufgate\cli.py"
$Image = if ($env:PRUFGATE_IMAGE) { $env:PRUFGATE_IMAGE } else { "prufgate:latest" }

$Rest = @($args)
if ($Rest.Count -gt 0 -and $Rest[0] -eq "-Build") {
    docker build -t "prufgate:latest" -f (Join-Path $PrufGateDir "Dockerfile") $PrufGateDir
    exit $LASTEXITCODE
}
$UseDocker = $Rest -contains "-Docker"
$Rest = @($Rest | Where-Object { $_ -ne "-Docker" })

$Python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command python -ErrorAction SilentlyContinue }

if (-not $UseDocker -and $Python -and (Test-Path $CliPy)) {
    & $Python.Source $CliPy @Rest
    exit $LASTEXITCODE
}

$WorkspaceMount = "$((Get-Location).Path):/workspace"
docker run --rm -i -v $WorkspaceMount $Image @Rest
exit $LASTEXITCODE
