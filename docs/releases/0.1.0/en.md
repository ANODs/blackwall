The first public build of BLACKWALL — a lightweight VPN client written in Zig.

### What works
- Subscriptions by link, or keys pasted directly (`vless://`, `trojan://`, `ss://`, `vmess://`); latency of every server.
- Protocols: VLESS (REALITY, Vision, TLS), Trojan, Shadowsocks (2022 included), VMess. Transports: TCP, WebSocket, HTTPUpgrade, gRPC, XHTTP (stream-one).
- macOS: all traffic captured (TUN) with per-app routes — through the VPN, through a chosen server, direct, or no network. Programs an app starts follow its rule. A background service carries the traffic, so the window can be closed; state and speed show in the menu bar.
- Kill switch, protection after Disconnect (apps with their own VPN rule stay without network) and reserve servers: when a server stops answering, the client reconnects once, then moves to the starred ones.
- macOS: detects another VPN standing in the way.
- Windows and Linux: a local SOCKS5 proxy on `127.0.0.1:1080`.
- Signed automatic updates.

### Not yet
- Capturing all traffic on Windows and Linux.
- UDP over Trojan, Shadowsocks and VMess; Hysteria2, TUIC, WireGuard; local DPI bypass.
- Android.

macOS is the platform tested in real use. The Windows and Linux builds have only been through the automatic tests so far.

### Download
| System | File |
|---|---|
| macOS (Apple Silicon) | `BLACKWALL-0.1.0-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.1.0-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.1.0-en-linux-x86_64.tar.gz` |

The build is not signed by Apple or Microsoft yet. macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway.

Other languages: [Русский](../../releases/tag/v0.1.0-ru) · [中文](../../releases/tag/v0.1.0-zh)
