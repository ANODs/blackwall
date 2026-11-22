BLACKWALL 0.2.22: on Windows, sites open with the VPN on, on a home network too.

### What is new
- Windows: with the VPN connected, no name resolved, so no site opened, while applications that need no names (Telegram) worked. The tunnel's adapter had no resolver of its own, so Windows asked the router from the network's own interface, and the kill switch blocks name lookups there. The adapter now names the tunnel's resolver, which Windows asks first.
- Windows: BLACKWALL does not connect while another VPN is on and says which one (0.2.21).

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.22-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.22-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.22-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.22-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.22-ru) · [中文](../../releases/tag/v0.2.22-zh)
