BLACKWALL 0.2.21: Windows refuses to connect while another VPN is on and says which.

### What is new
- Windows: with another VPN connected (hidemy.name, OpenVPN, WireGuard and the like), Connect used to capture the traffic anyway, and its kill switch cut that VPN's own connection: both stopped working, and the other VPN could not reconnect. Now BLACKWALL checks the routes first, does not touch the network, and says which VPN to turn off.
- Quit leaves nothing behind, one window at a time, a newer release replaces the older one (0.2.20).

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.21-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.21-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.21-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.21-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.21-ru) · [中文](../../releases/tag/v0.2.21-zh)
