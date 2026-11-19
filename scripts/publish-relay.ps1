param([ValidateSet('linux-x64','linux-arm64')][string]$Runtime = 'linux-x64')
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    & dotnet publish src/VPSPanel.Relay -c Release -r $Runtime --self-contained true -p:PublishSingleFile=true -o "publish/relay/$Runtime" --nologo
    exit $LASTEXITCODE
} finally { Pop-Location }
