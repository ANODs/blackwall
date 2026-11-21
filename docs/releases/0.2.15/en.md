BLACKWALL 0.2.15: servers with plain TLS work on Windows.

### What is new
- Windows: VLESS and Trojan servers over TLS (not REALITY) could fail entirely there while they worked on other systems. Windows keeps only the root certificates it already fetched, and Let's Encrypt's, for one, may be missing when the browser (Chrome) uses a set of its own. BLACKWALL on Windows now knows a full set of root certificates itself, and fetches nothing for it.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.15-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.15-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.15-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.15-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.15-ru) · [中文](../../releases/tag/v0.2.15-zh)
