BLACKWALL 0.2.14: a server's real country.

### What is new
- Providers often name a server after one country while it exits to the internet in another. Once a server is in use, one request through it to cloudflare.com shows where it really exits. That country has a dot next to it in the server list, on the main screen, in the tray and in the Android notification; where it differs from the declared one, both show. For an "Auto" group it is the country of the server in use. It can be turned off in the settings: "Real server country".
- The logs of the service and of the window no longer grow without limit when the service runs for weeks on a failing network.
- A service that could not start frees everything it had taken.
- Linux: an interrupted update no longer leaves old files beside the app.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.14-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.14-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.14-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.14-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.14-ru) · [中文](../../releases/tag/v0.2.14-zh)
