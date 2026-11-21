BLACKWALL 0.2.11: reserve servers work on Windows again.

### What is new
- Windows: the check of whether a server carries traffic, and the speed measurement, did not work, so BLACKWALL took every server for dead, working ones included, and the reserve could never take over. Fixed.
- Windows: when a connection to a server breaks, the log and the report for GitHub now show the system's exact error code, which tells whether the server, the network or BLACKWALL itself ended it.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.11-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.11-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.11-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.11-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.11-ru) · [中文](../../releases/tag/v0.2.11-zh)
