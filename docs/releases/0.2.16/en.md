BLACKWALL 0.2.16: the reserve holds on networks that cut servers, and a careful pass over everything.

### What is new
- A server the provider cuts no longer takes the connection down again and again. The service reloads its settings often, and each reload used to forget the failures of the server in use and to drop a working reserve server for a new "fastest" one that nothing had checked. Now a reserve server that carries traffic stays in use, a new main server is taken only after a real request got through it, and a server that carries nothing right after Connect is given up in seconds.
- Settings that cannot be read are kept in `config.json.unreadable` instead of being replaced by empty ones.
- A connection whose application cannot be identified is refused whenever the default route is direct and some application or site is held to the VPN.
- Plain TLS: every certificate that signs another must be a certificate authority. A malformed signature can no longer stop the service.
- IPv6 "Block" and "DNS through the route" now do what they say. "Notifications" and "Sound", which did nothing, are gone.
- A strict kill switch that cannot be set stops the connection from starting, on Linux and Windows as on macOS. On Windows it no longer fails with many servers.
- After a server switch, UDP (calls, games) through the old server ends properly and starts through the new one.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.16-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.16-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.16-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.16-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.16-ru) · [中文](../../releases/tag/v0.2.16-zh)
