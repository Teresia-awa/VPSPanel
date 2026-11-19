$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    & git config --local core.hooksPath .githooks
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    & dotnet build VPSPanel.slnx -c Release --nologo
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    & dotnet test VPSPanel.slnx -c Release --no-build --nologo
    exit $LASTEXITCODE
} finally { Pop-Location }
