BLACKWALL 0.2.19: on Windows, browsers work again with the VPN on.

### What is new
- Windows: with the kill switch on and "Local network" allowed, no site opened in a browser while the VPN said it worked, and applications with addresses of their own (Telegram) went on working. The kill switch blocks name lookups on the local network so that none leaves past the VPN, and it blocked them inside the VPN's adapter too. On a home network the resolver is the router, at a local address, so no name resolved at all.
- Windows: with another VPN connected, the service keeps its own connections on the network's interface, not on that VPN's adapter (0.2.18).
- Updates are looked for every hour (0.2.18).

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.19-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.19-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.19-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.19-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.19-ru) · [中文](../../releases/tag/v0.2.19-zh)
