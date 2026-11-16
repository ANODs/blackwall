# The installed service replaces itself with a newer one that the release
# key signed, without the administrator, and refuses one that it did not.
# For a CI machine; a throwaway key is made here.
#
#   pwsh tools/windows/upgrade.ps1 -Wintun path\to\wintun.dll
param([string]$Wintun)
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:RUNNER_TEMP 'bwup'
$cfg = Join-Path $env:RUNNER_TEMP 'bwupcfg'
New-Item -ItemType Directory -Force $work, $cfg | Out-Null
$failed = $false
function Check([string]$what, [bool]$ok) {
    if ($ok) { Write-Host "ok   $what" } else { Write-Host "FAIL $what"; $script:failed = $true }
}

zig build sign
$keys = & zig-out\bin\blackwall-sign.exe keygen
$seed = $keys[1].Trim(); $pub = $keys[3].Trim()

foreach ($v in '0.0.1', '0.0.2') {
    zig build service "-Dversion=$v" -Dupdate-repo=example/none "-Dupdate-pubkey=$pub" "-Dwintun=$Wintun"
    New-Item -ItemType Directory -Force (Join-Path $work $v) | Out-Null
    Copy-Item zig-out\bin\blackwall-service.exe (Join-Path $work "$v\blackwall-service.exe")
}
$env:BLACKWALL_UPDATE_KEY = $seed
& zig-out\bin\blackwall-sign.exe sign-helper 0.0.2 (Join-Path $work '0.0.2\blackwall-service.exe') (Join-Path $work '0.0.2\blackwall-service.sig')
Remove-Item Env:\BLACKWALL_UPDATE_KEY
# the same file signed by somebody else
$other = & zig-out\bin\blackwall-sign.exe keygen
New-Item -ItemType Directory -Force (Join-Path $work 'forged') | Out-Null
Copy-Item (Join-Path $work '0.0.2\blackwall-service.exe') (Join-Path $work 'forged\blackwall-service.exe')
$env:BLACKWALL_UPDATE_KEY = $other[1].Trim()
& zig-out\bin\blackwall-sign.exe sign-helper 0.0.2 (Join-Path $work 'forged\blackwall-service.exe') (Join-Path $work 'forged\blackwall-service.sig')
Remove-Item Env:\BLACKWALL_UPDATE_KEY

Set-Content -Path (Join-Path $cfg 'config.json') -Encoding ascii -Value '{"version":1,"next_id":1,"settings":{"default_route":{"direct":{}},"kill_switch":"off","ipv6":"block"},"subs":[],"servers":[],"rules":[]}'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& (Join-Path $work '0.0.1\blackwall-service.exe') install --config $cfg --user $sid
$build = "$env:ProgramFiles\BLACKWALL\build"
Check "0.0.1 installed ($(Get-Content $build))" ((Get-Content $build) -eq '0.0.1')

function Upgrade([string]$dir) {
    & sc.exe start BLACKWALL --upgrade (Join-Path $work $dir) | Out-Null
    for ($i = 0; $i -lt 50 -and (Get-Service BLACKWALL).Status -ne 'Stopped'; $i++) { Start-Sleep -Milliseconds 200 }
}
Upgrade 'forged'
Check "a forged one is refused ($(Get-Content $build))" ((Get-Content $build) -eq '0.0.1')
Upgrade '0.0.2'
Check "the signed 0.0.2 replaced it ($(Get-Content $build))" ((Get-Content $build) -eq '0.0.2')
$same = (Get-FileHash "$env:ProgramFiles\BLACKWALL\blackwall-service.exe").Hash -eq (Get-FileHash (Join-Path $work '0.0.2\blackwall-service.exe')).Hash
Check 'the file in Program Files is the new one' $same
& sc.exe start BLACKWALL --tun wintun | Out-Null
Start-Sleep -Seconds 6
Check "the new one runs ($((Get-Service BLACKWALL).Status))" ((Get-Service BLACKWALL).Status -eq 'Running')
Check 'it put wintun.dll next to itself' (Test-Path "$env:ProgramFiles\BLACKWALL\wintun.dll")
& sc.exe stop BLACKWALL | Out-Null
Start-Sleep -Seconds 5
& "$env:ProgramFiles\BLACKWALL\blackwall-service.exe" uninstall
if (Test-Path (Join-Path $cfg 'service.events')) { Get-Content (Join-Path $cfg 'service.events') -Tail 20 | Write-Host }
if ($failed) { exit 1 }
