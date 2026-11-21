BLACKWALL 0.2.12: the tunnel on Windows is tens of times faster, and videos load.

### What is new
- Windows: the tunnel ran at 1-2 MB/s, videos on YouTube and Telegram did not load, and connections to the server broke while being made. The cause: Windows sends its local network queries (LLMNR) on every network adapter, BLACKWALL's too, thousands a second, and the real traffic waited behind them. Such packets (LLMNR, mDNS, SSDP, NetBIOS) no longer go into the tunnel, and a download through it runs almost as fast as without it: 79 MB/s instead of 1-2 on the test machine.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.12-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.12-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.12-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.12-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.12-ru) · [中文](../../releases/tag/v0.2.12-zh)
