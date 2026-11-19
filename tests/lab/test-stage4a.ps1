param([Parameter(Mandatory=$true)][string]$Xray,[Parameter(Mandatory=$true)][string]$GeoDirectory,
    [string]$OpenSshRoot='/',[string]$Distribution='Ubuntu')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$assets=Join-Path $env:LOCALAPPDATA 'VPSPanel/recovery-assets'
& (Join-Path $root scripts/prepare-recovery-assets.ps1) -Xray $Xray -GeoDirectory $GeoDirectory -Distribution $Distribution -Destination $assets
function LinuxPath([string]$file) {
    $v=& wsl -d $Distribution -- wslpath -a ((Resolve-Path -LiteralPath $file).Path.Replace('\','/'))
    if($LASTEXITCODE){throw 'WSL path conversion failed.'};$v.Trim()
}
& (Join-Path $PSScriptRoot test-phase2.ps1) -XrayLinux (LinuxPath $Xray) -OpenSshRoot $OpenSshRoot -Distribution $Distribution -RelayLinux (LinuxPath (Join-Path $root 'publish/relay/linux-x64/VPSPanel.Relay')) -RecoveryAssets $assets
