# End-to-end check of the Windows capture, for a CI machine (an
# administrator, nothing of value on it): the service creates the Wintun
# adapter and its routes, a direct default route lets curl through the
# tunnel, a blocking one stops it, and the adapter goes with the service.
#
#   pwsh tools/windows/e2e.ps1 -Bin zig-out\bin
param([string]$Bin = "zig-out\bin")
$ErrorActionPreference = 'Stop'
$cfg = Join-Path $env:RUNNER_TEMP 'bwcfg'
New-Item -ItemType Directory -Force $cfg | Out-Null
$failed = $false

function Config([string]$route) {
    $json = '{"version":1,"next_id":1,"settings":{"default_route":{"' + $route + '":{}},"kill_switch":"off","ipv6":"block"},"subs":[],"servers":[],"rules":[]}'
    Set-Content -Path (Join-Path $cfg 'config.json') -Value $json -Encoding ascii
}

function Fetch {
    $code = & curl.exe -s -m 10 -o NUL -w "%{http_code}" http://example.com 2>$null
    if (-not $code) { $code = 'fail' }
    return $code
}

function Start-Service([string]$name) {
    $p = Start-Process -FilePath (Join-Path $Bin 'blackwall-service.exe') `
        -ArgumentList '--config', $cfg, '--tun', 'wintun' `
        -RedirectStandardError (Join-Path $cfg "$name.err") -RedirectStandardOutput (Join-Path $cfg "$name.out") `
        -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 6
    return $p
}

function Check([string]$what, [bool]$ok) {
    if ($ok) { Write-Host "ok   $what" } else { Write-Host "FAIL $what"; $script:failed = $true }
}

Write-Host "== before: $(Fetch)"

Write-Host "== direct through the tunnel"
Config 'direct'
$p = Start-Service 'direct'
Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Wintun*' -or $_.Name -eq 'BLACKWALL' } | Format-Table -AutoSize | Out-String | Write-Host
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq 'BLACKWALL' } | Format-Table -AutoSize | Out-String | Write-Host
Check 'the service runs' (-not $p.HasExited)
Check 'the adapter is there' ($null -ne (Get-NetAdapter -Name 'BLACKWALL' -ErrorAction SilentlyContinue))
$code = Fetch
Check "curl through the tunnel ($code)" ($code -eq '200')
Get-Content (Join-Path $cfg 'direct.err') -Tail 30 | Write-Host
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 3
Check 'the adapter went with the service' ($null -eq (Get-NetAdapter -Name 'BLACKWALL' -ErrorAction SilentlyContinue))
$code = Fetch
Check "the network is back ($code)" ($code -eq '200')

Write-Host "== blocked"
Config 'block'
$p = Start-Service 'block'
$code = Fetch
Check "curl is stopped ($code)" ($code -ne '200')
Get-Content (Join-Path $cfg 'block.err') -Tail 15 | Write-Host
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 3
$code = Fetch
Check "the network is back ($code)" ($code -eq '200')

if (Test-Path (Join-Path $cfg 'service.events')) {
    Write-Host "== service.events"
    Get-Content (Join-Path $cfg 'service.events') -Tail 40 | Write-Host
}
if ($failed) { exit 1 }
