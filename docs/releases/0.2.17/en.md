BLACKWALL 0.2.17: a server the provider cuts is given up three times faster.

### What is new
- On a network that cuts the main server, the reserve used to take over about half a minute after Connect, and nothing opened meanwhile. The service asked the dead server twice, waited long for each answer, and then asked the reserve servers one after another. Now the first check is enough, it waits 5 seconds instead of 8, and three reserve servers are asked at once: the best one that carries traffic takes over.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.17-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.17-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.17-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.17-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.17-ru) · [中文](../../releases/tag/v0.2.17-zh)
