param([Parameter(Mandatory=$true)][string]$Xray,[Parameter(Mandatory=$true)][string]$GeoDirectory,
    [string]$Destination=(Join-Path $env:LOCALAPPDATA 'VPSPanel/recovery-assets'),[string]$Distribution='Ubuntu',
    [ValidateSet('linux-x64','linux-arm64')][string]$Runtime='linux-x64')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
& dotnet publish (Join-Path $root src/VPSPanel.Relay) -c Release -r $Runtime --self-contained true -p:PublishSingleFile=true -o (Join-Path $root "publish/relay/$Runtime") --nologo
if($LASTEXITCODE){throw 'Relay publish failed.'}
function LinuxPath([string]$p) {
    $v=& wsl -d $Distribution -- wslpath -a ((Resolve-Path -LiteralPath $p).Path.Replace('\','/'))
    if($LASTEXITCODE){throw 'WSL path conversion failed.'}
    $v.Trim()
}
$relay=Join-Path $root "publish/relay/$Runtime/VPSPanel.Relay"
$version=& wsl -d $Distribution -- (LinuxPath $Xray) version
if($LASTEXITCODE -or $version[0] -notmatch '^Xray 26\.10\.31 '){throw 'Expected Xray 26.10.31.'}
$v=& wsl -d $Distribution -- (LinuxPath $relay) version
if($LASTEXITCODE -or $v -ne 'VPSPanel.Relay 1.5.0'){throw 'Relay version mismatch.'}
$features=& wsl -d $Distribution -- (LinuxPath $relay) capabilities
if($LASTEXITCODE -or $features -notcontains 'configurable-default'){throw 'Relay lacks configurable default routing.'}
if($features -notcontains 'exit-failover'){throw 'Relay lacks exit failover support.'}
if($features -notcontains 'split-doh'){throw 'Relay lacks managed DoH configuration.'}
[void][IO.Directory]::CreateDirectory($Destination)
$items=@{'xray'=$Xray;'relay'=$relay;'geoip.dat'=(Join-Path $GeoDirectory geoip.dat);'geosite.dat'=(Join-Path $GeoDirectory geosite.dat)}
$hashes=@{}
foreach($name in $items.Keys){
    $p=Join-Path $Destination $name
    if([IO.Path]::GetFullPath($items[$name]) -ne [IO.Path]::GetFullPath($p)){
        Copy-Item -LiteralPath $items[$name] -Destination $p -Force
    }
    $hashes[$name]=(Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash
}
$hashes['relay-configurable-default']=$hashes['relay']
$hashes['relay-exit-failover']=$hashes['relay']
$hashes['relay-managed-doh']=$hashes['relay']
$hashes['relay-split-doh']=$hashes['relay']
[IO.File]::WriteAllText((Join-Path $Destination assets.json),($hashes|ConvertTo-Json))
Write-Output 'Offline recovery assets verified.'
