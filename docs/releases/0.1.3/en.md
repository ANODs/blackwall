BLACKWALL 0.1.3 — Linux, all the way.

### What is new
- Linux: all traffic goes through the VPN (TUN mode) from the window, with a route for every application, protection after Disconnect and reserve servers, as on macOS.
- Linux: the strict kill switch, on nftables. It stays in the kernel if the service dies, so nothing leaves past the VPN.
- Linux: no part of BLACKWALL runs as root. A small `blackwall-tun` holds one network permission, asked for once through the system's password dialog; updates keep it.
- Linux: `install.sh` puts BLACKWALL into the applications menu for your user.

### Download
| System | File |
|---|---|
| macOS (Apple Silicon) | `BLACKWALL-0.1.3-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.1.3-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.1.3-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.1.3-android.apk` |

Linux: unpack, run `./install.sh`, start BLACKWALL from the menu. Kernel 5.7 or newer.
macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.1.3-ru) · [中文](../../releases/tag/v0.1.3-zh)
