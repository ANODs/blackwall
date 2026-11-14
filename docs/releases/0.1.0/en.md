The first public build of BLACKWALL — a lightweight VPN client written in Zig.

### What works
- Subscriptions by link, or keys pasted directly (`vless://`, `trojan://`, …); latency of every server.
- A local SOCKS5 proxy at `127.0.0.1:1080`: apps set up to use it go direct or over VLESS (TCP, REALITY, Vision).
- Per-app routes, traffic statistics, kill switch and IPv6 settings in the interface.

### Not yet
- Capturing all traffic (TUN), WS / XHTTP / TLS transports and per-app rules in the data plane.
- Android.

### Download
| System | File |
|---|---|
| macOS (Apple Silicon) | `BLACKWALL-0.1.0-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.1.0-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.1.0-en-linux-x86_64.tar.gz` |

The build is not signed by Apple or Microsoft yet. macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway.

Other languages: [Русский](../../releases/tag/v0.1.0-ru) · [中文](../../releases/tag/v0.1.0-zh)
