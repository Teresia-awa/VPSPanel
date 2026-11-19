param([Parameter(Mandatory=$true)][string]$XrayLinux,[string]$Distribution='Ubuntu',[string]$OpenSshRoot='/')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
& dotnet publish (Join-Path $root 'src/VPSPanel.Relay') -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o (Join-Path $root 'publish/relay/linux-x64') --nologo
if($LASTEXITCODE){throw 'Relay publish failed.'}
$linuxRoot=(& wsl.exe -d $Distribution -- wslpath -a ($root.Replace('\','/'))).Trim()
if($LASTEXITCODE){throw 'Invalid WSL workspace path.'}
& wsl.exe -d $Distribution -u root -- unshare --mount --propagation private --net -- python3 "$linuxRoot/tests/lab/relay-e2e.py" $XrayLinux "$linuxRoot/publish/relay/linux-x64/VPSPanel.Relay"
if($LASTEXITCODE){throw 'Stage 3 loopback acceptance failed.'}
$oldVisual=$env:VPSPANEL_VISUAL_DIR
try {
    $env:VPSPANEL_VISUAL_DIR=Join-Path $root 'artifacts/stage3'
    & (Join-Path $PSScriptRoot 'test-phase2.ps1') -XrayLinux $XrayLinux -Distribution $Distribution -OpenSshRoot $OpenSshRoot -RelayLinux "$linuxRoot/publish/relay/linux-x64/VPSPanel.Relay"
} finally { $env:VPSPANEL_VISUAL_DIR=$oldVisual }
