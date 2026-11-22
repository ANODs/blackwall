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

function Config([string]$route, [string]$rules = '', [string]$kill = 'off', [string]$lan = 'false') {
    $json = '{"version":1,"next_id":1,"settings":{"default_route":{"' + $route + '":{}},"kill_switch":"' + $kill + '","ipv6":"block","allow_lan":' + $lan + '},"subs":[],"servers":[],"rules":[' + $rules + ']}'
    Set-Content -Path (Join-Path $cfg 'config.json') -Value $json -Encoding ascii
}

function Rule([string]$path, [string]$route) {
    $id = $path.ToLower().Replace('\', '\\')
    return '{"app_id":"' + $id + '","name":"x","route":{"' + $route + '":{}}}'
}

function FetchPwsh {
    try { return [string](Invoke-WebRequest -Uri http://example.com -TimeoutSec 10 -UseBasicParsing).StatusCode } catch { return 'fail' }
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
# the same long download without the tunnel, to compare its speed with
$r = & curl.exe -s -m 90 -o NUL -w "%{http_code} %{size_download} %{speed_download}" "https://speed.cloudflare.com/__down?bytes=32000000" 2>$null
Write-Host "   32 MB without the tunnel: $r"
$direct_speed = [double]("$r".Split(' ')[2])

Write-Host "== direct through the tunnel"
Config 'direct'
$p = Start-Service 'direct'
Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Wintun*' -or $_.Name -eq 'BLACKWALL' } | Format-Table -AutoSize | Out-String | Write-Host
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq 'BLACKWALL' } | Format-Table -AutoSize | Out-String | Write-Host
Check 'the service runs' (-not $p.HasExited)
Check 'the adapter is there' ($null -ne (Get-NetAdapter -Name 'BLACKWALL' -ErrorAction SilentlyContinue))
$code = Fetch
Check "curl through the tunnel ($code)" ($code -eq '200')
# what a video is: one long download, and several at once (a page, a player)
$big = 32000000
$r = & curl.exe -s -m 90 -o NUL -w "%{http_code} %{size_download} %{speed_download}" "https://speed.cloudflare.com/__down?bytes=$big" 2>$null
$f = "$r".Split(' ')
Check "a long download through the tunnel ($r)" (($f[0] -eq '200') -and ([int64]$f[1] -eq $big))
# the tunnel ran at 1-2 MB/s here once, beside 100 without it (issue #5)
Check "at a quarter of the direct speed or more ($([int]([double]$f[2] / 1MB)) of $([int]($direct_speed / 1MB)) MB/s)" ([double]$f[2] -ge $direct_speed / 4)
$urls = 1..6 | ForEach-Object { "https://speed.cloudflare.com/__down?bytes=8000000&n=$_" }
$out = 1..6 | ForEach-Object { '-o'; 'NUL' }
$t0 = Get-Date
$r = & curl.exe -s -m 90 --parallel --parallel-max 6 -w "%{size_download}\n" $out $urls 2>$null
Write-Host "   six at once took $([int]((Get-Date) - $t0).TotalMilliseconds) ms"
$sizes = @($r | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int64]$_ })
Check "six at once through the tunnel ($($sizes -join ', '))" (($sizes.Count -eq 6) -and (($sizes | Where-Object { $_ -ne 8000000 }).Count -eq 0))
Get-Content (Join-Path $cfg 'direct.err') -Tail 30 | Write-Host
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 3
Check 'the adapter went with the service' ($null -eq (Get-NetAdapter -Name 'BLACKWALL' -ErrorAction SilentlyContinue))
$code = Fetch
Check "the network is back ($code)" ($code -eq '200')

Write-Host "== the same downloads through SOCKS (no Wintun, no TCP stack)"
# halves the path: if these are fast, the TUN side is what is slow
Config 'direct'
$p = Start-Process -FilePath (Join-Path $Bin 'blackwall-service.exe') `
    -ArgumentList '--config', $cfg, '--socks', '1089' `
    -RedirectStandardError (Join-Path $cfg "socks.err") -RedirectStandardOutput (Join-Path $cfg "socks.out") `
    -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 4
$r = & curl.exe -s -m 90 --socks5-hostname 127.0.0.1:1089 -o NUL -w "%{http_code} %{size_download} %{speed_download}" "https://speed.cloudflare.com/__down?bytes=32000000" 2>$null
Write-Host "   32 MB through SOCKS: $r"
$t0 = Get-Date
$r = & curl.exe -s -m 90 --socks5-hostname 127.0.0.1:1089 --parallel --parallel-max 6 -w "%{size_download}\n" $out $urls 2>$null
Write-Host "   six at once through SOCKS took $([int]((Get-Date) - $t0).TotalMilliseconds) ms"
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 2

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

Write-Host "== a rule for one application"
$curl = (Get-Command curl.exe).Source
$pwsh = (Get-Process -Id $PID).Path
Write-Host "curl: $curl; pwsh: $pwsh"
Config 'direct' (Rule $curl 'block')
$p = Start-Service 'rule'
$code = Fetch
Check "curl has its own rule and is stopped ($code)" ($code -ne '200')
$code = FetchPwsh
Check "PowerShell follows the default route ($code)" ($code -eq '200')
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 3

Write-Host "== a rule for the application that started it"
Config 'direct' (Rule $pwsh 'block')
$p = Start-Service 'parent'
$code = FetchPwsh
Check "PowerShell is stopped ($code)" ($code -ne '200')
$code = Fetch
Check "curl started by it is stopped too ($code)" ($code -ne '200')
Get-Content (Join-Path $cfg 'parent.err') -Tail 15 | Write-Host
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 3
$code = Fetch
Check "the network is back ($code)" ($code -eq '200')

Write-Host "== as a Windows service"
Config 'direct'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& (Join-Path $Bin 'blackwall-service.exe') install --config $cfg --user $sid
Check "installed (exit $LASTEXITCODE)" ($LASTEXITCODE -eq 0)
Check 'it is in Program Files' (Test-Path "$env:ProgramFiles\BLACKWALL\blackwall-service.exe")
& sc.exe sdshow BLACKWALL | Write-Host
& sc.exe start BLACKWALL --tun wintun | Out-Null
Start-Sleep -Seconds 6
Check "it runs ($((Get-Service BLACKWALL).Status))" ((Get-Service BLACKWALL).Status -eq 'Running')
$code = Fetch
Check "curl through the service ($code)" ($code -eq '200')
& sc.exe stop BLACKWALL | Out-Null
Start-Sleep -Seconds 5
Check "it stopped ($((Get-Service BLACKWALL).Status))" ((Get-Service BLACKWALL).Status -eq 'Stopped')
Check 'the adapter went with it' ($null -eq (Get-NetAdapter -Name 'BLACKWALL' -ErrorAction SilentlyContinue))
$code = Fetch
Check "the network is back ($code)" ($code -eq '200')
Write-Host "== the kill switch holds the traffic when the service dies"
$svc = Join-Path $Bin 'blackwall-service.exe'
# whatever happens below, the machine gets its network back
Start-Process -WindowStyle Hidden -FilePath pwsh -ArgumentList '-NoProfile', '-Command', "Start-Sleep 90; & '$svc' --release"
Config 'direct' '' 'selective'
& sc.exe start BLACKWALL --tun wintun | Out-Null
Start-Sleep -Seconds 6
$code = Fetch
Check "selective: through the tunnel ($code)" ($code -eq '200')
Get-Process blackwall-service -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3
Check 'the adapter went with it' ($null -eq (Get-NetAdapter -Name 'BLACKWALL' -ErrorAction SilentlyContinue))
$code = Fetch
Check "nothing goes out directly ($code)" ($code -ne '200')
& sc.exe start BLACKWALL --release | Out-Null
Start-Sleep -Seconds 4
$code = Fetch
Check "released: the network is back ($code)" ($code -eq '200')

# A home network's resolver is the router, at a local address. With the
# local network allowed, lookups there past the VPN are blocked; the same
# lookup into the adapter is the VPN's and must be answered.
Config 'direct' '' 'selective' 'true'
& sc.exe start BLACKWALL --tun wintun | Out-Null
Start-Sleep -Seconds 6
$answer = Resolve-DnsName example.com -Type A -DnsOnly -Server 10.255.255.53 -ErrorAction SilentlyContinue
Check "selective, local network allowed: a lookup at a local address is answered in the tunnel ($(@($answer).Count))" ($null -ne $answer)
& sc.exe stop BLACKWALL | Out-Null
Start-Sleep -Seconds 5

Config 'direct' '' 'strict'
& sc.exe start BLACKWALL --tun wintun | Out-Null
Start-Sleep -Seconds 6
$code = Fetch
Check "strict: a direct route does not work ($code)" ($code -ne '200')
& sc.exe stop BLACKWALL | Out-Null
Start-Sleep -Seconds 5
$code = Fetch
Check "a clean stop lets the traffic go ($code)" ($code -eq '200')

Write-Host "== zapret or GoodbyeDPI beside it is stopped at the window's word"
Config 'direct'
# stand-ins: zapret's winws.exe as a plain process (a copy of cmd.exe that
# waits), and zapret-discord-youtube's service "zapret" (a copy of our own
# service, which answers the SCM, under that name)
$dpi = Join-Path $env:RUNNER_TEMP 'dpi'
$zcfg = Join-Path $dpi 'cfg'
New-Item -ItemType Directory -Force (Join-Path $dpi 'svc'), $zcfg | Out-Null
Copy-Item (Join-Path $env:SystemRoot 'System32\cmd.exe') (Join-Path $dpi 'winws.exe')
Copy-Item (Join-Path $Bin 'blackwall-service.exe') (Join-Path $dpi 'svc\winws.exe')
function Start-Winws {
    $t = Start-Process -FilePath (Join-Path $dpi 'winws.exe') -ArgumentList '/d', '/c', 'ping -n 120 127.0.0.1 >nul' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 1
    return $t
}
# what the window sends: the secret from the file, then one request line
function Ask([string]$line) {
    $ep = (Get-Content (Join-Path $cfg 'service.sock') -Raw).Trim().Split(' ')
    $c = [System.Net.Sockets.TcpClient]::new('127.0.0.1', [int]$ep[0])
    try {
        $s = $c.GetStream()
        $s.ReadTimeout = 30000
        $b = [System.Text.Encoding]::ASCII.GetBytes($ep[1] + "`n" + $line + "`n")
        $s.Write($b, 0, $b.Length)
        return [System.IO.StreamReader]::new($s).ReadLine()
    } catch { return "fail: $_" } finally { $c.Close() }
}

# no BLACKWALL service runs: the installed one is started for just this
$t = Start-Winws
(Get-Service BLACKWALL).Start([string[]]@('--stop-dpi', ('{"pid":' + $t.Id + '}')))
Check 'started for it, the service ends the stand-in' ($t.WaitForExit(15000))
Start-Sleep -Seconds 2
Check "and is stopped again ($((Get-Service BLACKWALL).Status))" ((Get-Service BLACKWALL).Status -eq 'Stopped')

New-Service -Name zapret -StartupType Manual -BinaryPathName ('"' + (Join-Path $dpi 'svc\winws.exe') + '" --scm --config "' + $zcfg + '"') | Out-Null
(Get-Service zapret).Start([string[]]@('--socks', '18099'))
Start-Sleep -Seconds 4
Check "the service zapret runs ($((Get-Service zapret).Status))" ((Get-Service zapret).Status -eq 'Running')

# over the running service's channel
& sc.exe start BLACKWALL --socks 18098 | Out-Null
Start-Sleep -Seconds 4
$r = Ask '{"cmd":"stop_dpi","service":"zapret"}'
Check "the service zapret through the SCM ($r)" ($r -like '*"ok":true*')
Check "it is stopped ($((Get-Service zapret).Status))" ((Get-Service zapret).Status -eq 'Stopped')
$t = Start-Winws
$r = Ask ('{"cmd":"stop_dpi","pid":' + $t.Id + '}')
Check "a plain process ($r)" (($r -like '*"ok":true*') -and $t.WaitForExit(5000))
# nothing but the tools: not this PowerShell, not BLACKWALL, not the system's
$r = Ask ('{"cmd":"stop_dpi","pid":' + $PID + '}')
Check "another process is left alone ($r)" ($r -like '*"ok":false*')
$r = Ask '{"cmd":"stop_dpi","service":"BLACKWALL"}'
Check "its own service too ($r)" (($r -like '*"ok":false*') -and (Get-Service BLACKWALL).Status -eq 'Running')
$spooler = (Get-Service Spooler -ErrorAction SilentlyContinue).Status
$r = Ask '{"cmd":"stop_dpi","service":"Spooler"}'
Check "and a service of the system ($r)" (($r -like '*"ok":false*') -and (Get-Service Spooler -ErrorAction SilentlyContinue).Status -eq $spooler)
& sc.exe stop BLACKWALL | Out-Null
Start-Sleep -Seconds 4
& sc.exe delete zapret | Out-Null
if (Test-Path (Join-Path $zcfg 'service.events')) { Get-Content (Join-Path $zcfg 'service.events') -Tail 10 | Write-Host }

& (Join-Path $Bin 'blackwall-service.exe') uninstall
Check 'uninstalled' ($null -eq (Get-Service BLACKWALL -ErrorAction SilentlyContinue))

Write-Host "== a crash of the window is in its log"
# BLACKWALL_CRASH makes it crash at once, as it would (an illegal
# instruction, a panic), and without the message box that asks the user
$wcfg = Join-Path $env:RUNNER_TEMP 'bwwin'
New-Item -ItemType Directory -Force $wcfg | Out-Null
$appdata = $env:APPDATA
$wlog = Join-Path $wcfg 'BLACKWALL\window.log'
foreach ($how in 'trap', 'panic') {
    $env:APPDATA = $wcfg
    $env:BLACKWALL_CRASH = $how
    $p = Start-Process -FilePath (Join-Path $Bin 'blackwall.exe') -PassThru -WindowStyle Hidden
    $env:APPDATA = $appdata
    Remove-Item Env:BLACKWALL_CRASH
    $ended = $p.WaitForExit(30000)
    if (-not $ended) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    $text = if (Test-Path $wlog) { Get-Content $wlog -Raw } else { '' }
    Write-Host $text
    if ($how -eq 'trap') {
        Check "an illegal instruction, and where ($($p.ExitCode))" ($ended -and $text -match 'crash: illegal instruction \(0xc000001d\) at BLACKWALL\+0x[0-9a-f]+')
    } else {
        Check "a panic ($($p.ExitCode))" ($ended -and $text -match 'panic: BLACKWALL_CRASH')
        Check 'the run before is kept' ((Get-Content (Join-Path $wcfg 'BLACKWALL\window.previous.log') -Raw) -match 'crash: illegal instruction')
    }
}

if (Test-Path (Join-Path $cfg 'service.events')) {
    Write-Host "== service.events"
    Get-Content (Join-Path $cfg 'service.events') -Tail 40 | Write-Host
}
if ($failed) { exit 1 }
