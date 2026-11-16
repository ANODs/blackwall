BLACKWALL 0.2.0 — sites, DPI bypass, UDP everywhere, QR codes.

### What is new
- Routes for sites: youtube.com and everything under it gets its own route, as an application does. An application's own rule always comes first, so one held to the VPN never leaves it.
- DPI bypass works: a direct route whose TLS ClientHello leaves in a shape that name filters miss, picked per site from three ways. On a Russian ISP YouTube, which loads nothing directly, opened through it at full speed.
- UDP through every protocol: VMess, Trojan and Shadowsocks now carry it too (games, calls, DNS), not only VLESS.
- QR codes: add a subscription from the camera or a picture on Android, from the clipboard or the screen on a computer.

### Download
| System | File |
|---|---|
| macOS (Apple Silicon) | `BLACKWALL-0.2.0-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.0-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.0-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.0-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.0-ru) · [中文](../../releases/tag/v0.2.0-zh)
