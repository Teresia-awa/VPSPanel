$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    & dotnet publish src/VPSPanel.Desktop -c Release --self-contained false -o publish/desktop --nologo
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'desktop-demo.cmd') -Destination 'publish/desktop/本地演示.cmd' -Force
} finally { Pop-Location }
