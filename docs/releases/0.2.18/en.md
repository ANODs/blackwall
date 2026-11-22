BLACKWALL 0.2.18: Windows connects while another VPN is on.

### What is new
- Windows: with another VPN connected (OpenVPN and the like), Connect left the computer without a network, and it stayed so after that VPN was turned off. The service kept its own connections on that VPN's adapter, and its kill switch cut that VPN at the same moment. It now keeps them on the network's own interface, whatever else is connected.
- Updates are looked for every hour, not every six: a window that is never closed no longer misses a day's releases.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.18-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.18-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.18-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.18-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.18-ru) · [中文](../../releases/tag/v0.2.18-zh)
