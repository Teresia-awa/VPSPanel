param(
    [Parameter(Mandatory=$true)][string]$XrayLinux,
    [string]$Distribution = 'Ubuntu',
    [string]$OpenSshRoot = '/',
    [string]$RelayLinux = '-',
    [string]$RecoveryAssets
)
$ErrorActionPreference = 'Stop'
if ($Distribution -notmatch '^[\w.-]+$') { throw 'Invalid WSL distribution name.' }
$work = [IO.Directory]::CreateDirectory((Join-Path ([IO.Path]::GetTempPath()) ('VPSPanel-loopback-' + [guid]::NewGuid().ToString('N')))).FullName
$oldMigration=$env:VPSPANEL_MIGRATION_ASSETS
$oldRelay = $env:VPSPANEL_LAB_RELAY
$oldConfig = $env:VPSPANEL_LOOPBACK_CONFIG
$daemon = $null
function LinuxPath([string]$path) {
    $result = & wsl.exe -d $Distribution -- wslpath -a ($path.Replace('\','/'))
    if ($LASTEXITCODE) { throw 'WSL path conversion failed.' }
    $result.Trim()
}
try {
    $fixture = LinuxPath $PSScriptRoot
    $bridge = LinuxPath $work
    $key = Join-Path $work client
    $keyProcess = Start-Process "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe" -ArgumentList "-q -t rsa -b 2048 -m PEM -N `"`" -f `"$key`"" -WindowStyle Hidden -Wait -PassThru
    if ($keyProcess.ExitCode) { throw 'Could not create the disposable test key.' }
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls $key /inheritance:r /grant:r ("*" + $sid + ':(F)') | Out-Null
    if ($LASTEXITCODE) { throw 'Could not protect the disposable key.' }
    $migration=if($RecoveryAssets){"migration"}else{"-"}
    $argsText = "-d $Distribution -u root -- unshare --mount --net --propagation private bash `"$fixture/start-isolated.sh`" `"$bridge`" `"$XrayLinux`" `"$OpenSshRoot`" `"$fixture`" `"$RelayLinux`" $migration"
    $daemon = Start-Process wsl.exe -ArgumentList $argsText -WindowStyle Hidden -PassThru
    for ($i=0; $i -lt 350 -and !(Test-Path "$work/ns.pid") -and !$daemon.HasExited; $i++) { Start-Sleep -Milliseconds 200 }
    if (!(Test-Path "$work/ns.pid")) {
        $line=if(Test-Path "$work/fixture-failure-line"){Get-Content "$work/fixture-failure-line"}else{'readiness timeout'}
        throw "Isolated fixture failed to start at $line. Check WSL, Xray and OpenSSH server prerequisites."
    }
    $nsId = (Get-Content "$work/ns.pid" -Raw).Trim()
    if ($nsId -notmatch '^[0-9]+$') { throw 'Invalid namespace id.' }
    $root = $work.Replace('\','/')
    $pipeName = 'vpspanel-' + [guid]::NewGuid().ToString('N')
    @"
Host phase2-lab
  IdentityFile "$root/client"
  IdentityAgent none
Host phase2-agent
  IdentityFile "$root/agent-public"
  IdentityAgent //./pipe/$pipeName
Host phase2-lab phase2-agent
  HostName 127.0.0.1
  User root
  IdentitiesOnly yes
  HostKeyAlias phase2-lab
  UserKnownHostsFile "$root/known_hosts"
  GlobalKnownHostsFile NUL
  ProxyCommand C:/Windows/System32/wsl.exe -d $Distribution -u root -- nsenter -t $nsId -m -n nc 127.0.0.1 26442
"@ | Set-Content "$work/config" -Encoding utf8
    if($RecoveryAssets){
        $env:VPSPANEL_MIGRATION_ASSETS=(Resolve-Path -LiteralPath $RecoveryAssets).Path
        @"
Host phase4-target
  HostName 127.0.0.1
  User root
  IdentityFile "$root/client"
  IdentitiesOnly yes
  IdentityAgent none
  HostKeyAlias phase4-target
  UserKnownHostsFile "$root/known_hosts"
  GlobalKnownHostsFile NUL
  ProxyCommand C:/Windows/System32/wsl.exe -d $Distribution -u root -- nsenter -t $nsId -m -n nc 127.0.0.1 26444
"@ | Add-Content "$work/config"
    }
    $config = Join-Path $work config
    [IO.File]::WriteAllText($config,[IO.File]::ReadAllText($config),[Text.UTF8Encoding]::new($false))
    $env:VPSPANEL_LOOPBACK_CONFIG = $config
    if($RelayLinux -ne '-'){$env:VPSPANEL_LAB_RELAY='1'} else {$env:VPSPANEL_LAB_RELAY=$null}
    & dotnet test (Join-Path $PSScriptRoot '../../VPSPanel.slnx') -c Release --nologo
    if ($LASTEXITCODE) { throw 'Phase 2 tests failed.' }
} finally {
    $env:VPSPANEL_MIGRATION_ASSETS=$oldMigration
    $env:VPSPANEL_LAB_RELAY=$oldRelay
    $env:VPSPANEL_LOOPBACK_CONFIG = $oldConfig
    [IO.File]::WriteAllText((Join-Path $work stop),'')
    if ($daemon) { [void]$daemon.WaitForExit(15000) }
    $resolved = (Resolve-Path -LiteralPath $work).Path
    if ([IO.Path]::GetDirectoryName($resolved) -eq ([IO.Path]::GetTempPath().TrimEnd('\')) -and
        [IO.Path]::GetFileName($resolved) -match '^VPSPanel-loopback-[a-f0-9]{32}$' -and (!$daemon -or $daemon.HasExited)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
