# Windows

How the Windows build carries traffic, and why it is put together this way.

## The pieces

`BLACKWALL-<version>-<lang>-windows-x86_64.exe` is one file. It carries
`blackwall-service.exe` (and, in a release, its signature), and the service carries
`wintun.dll` 0.14.1 from [wintun.net](https://www.wintun.net), the WireGuard project's
signed driver library, pinned by its hash in the release workflow.

- **The window** ([src/link.zig](../src/link.zig)) starts, stops and asks the service the
  same way as on macOS and Linux, over an AF_UNIX socket in `%APPDATA%\BLACKWALL`.
- **The service** runs as a Windows service (`BLACKWALL`, LocalSystem): Wintun adapters,
  routes and the firewall need an administrator. It is installed once, at the first
  Connect, after the UAC prompt ([src/core/win_scm.zig](../src/core/win_scm.zig)):
  - the executable goes to `%ProgramFiles%\BLACKWALL`, where only administrators write,
    since the system runs it;
  - its command line fixes the user's configuration folder;
  - the user who installed it may start, stop and query it, nothing more. The window
    passes only `--tun wintun`, the SOCKS port and the MTU.
- **Upgrades**: a release signs the service with the update key. When the window finds
  an installed service of another release, it unpacks its own and starts the installed
  one with `--upgrade`; that one checks the signature and that the release is not older,
  then replaces its own file. No UAC prompt after the first. Builds without the key (local
  ones) ask again.

## The data plane

[src/service/windows.zig](../src/service/windows.zig) follows the Linux plan:

- the adapter `BLACKWALL` gets 198.18.0.1/15 (and fd62:6c61:636b::1/64);
- `0.0.0.0/1` and `128.0.0.0/1` go into it, more specific than the real default route,
  which stays for the service's own sockets;
- the network's resolvers get host routes into it, so lookups reach the tunnel's DNS;
- the service's own sockets stay on the physical interface with `IP_UNICAST_IF`.

The adapter goes away with the process that opened it, routes and all.

Sockets: Zig's std on Windows talks to the AFD driver directly and has no connect
timeout or readiness wait yet; [src/core/afd.zig](../src/core/afd.zig) adds them on the
same kind of handle, so std still reads, writes and closes them.

Who owns a connection ([src/service/win_owner.zig](../src/service/win_owner.zig)): the
TCP and UDP tables of the IP Helper API give the process of a local port; its executable
and those of its parents, in lower case, are the identity the rules match. The list of
applications comes from the Start menu shortcuts ([src/platform/apps.zig](../src/platform/apps.zig)).

## The kill switch

[src/service/wfp.zig](../src/service/wfp.zig): persistent filters of the Windows
Filtering Platform at the ALE connect layers, in a sublayer of our own. They stay when the
service dies.

- **selective**: out through the adapter, loopback, DHCP, the local network when allowed,
  and the service itself. While the service runs nothing changes; when it dies, nothing
  leaves directly.
- **strict**: the same, but the service too reaches only the VPN servers and the
  resolvers it asks, so Direct routes do not work.

A clean stop removes the filters; "suspend" (a restart by the window) keeps them.
Disconnect after a crash starts the service with `--release`, which only removes them.

## DPI circumvention beside it

zapret (`winws.exe`, also in the zapret-discord-youtube bundle) and GoodbyeDPI
(`goodbyedpi.exe`) rewrite packets through the WinDivert driver, the VPN's own among
them. [src/core/win_dpi.zig](../src/core/win_dpi.zig):

- **Found** by the window at every Connect, without any rights: the process list, the
  services they run as (any name; `zapret` and `GoodbyeDPI` also when the executable is
  called otherwise), and a loaded WinDivert driver, which confirms it. Shown like a VPN
  in the way on macOS: the notice, then the list with Stop and reconnect.
- **Stopped** by the service, since the tools run as administrators or as LocalSystem:
  `stop_dpi` over its channel, or, when none runs, the installed one started with
  `--stop-dpi` for just that. A service through the SCM, its process only when it does
  not stop (or on Force quit); a plain process only when its number and start time are
  still the ones shown. Only those two executables, outside the Windows folder and not
  critical, and services of those names; never `BLACKWALL` itself.

## Testing

`.github/workflows/windows-e2e.yml` runs on a Windows machine of CI:

- the socket layer;
- the whole suite;
- [tools/windows/e2e.ps1](../tools/windows/e2e.ps1): capture, routes per application,
  install as a service, the kill switch, stopping stand-ins of zapret (a process and a
  service) and refusing anything else;
- [tools/windows/upgrade.ps1](../tools/windows/upgrade.ps1): a signed upgrade, and a
  forged one refused.

Wine (CrossOver included) does not implement the AFD calls std uses, so it is no
substitute.
