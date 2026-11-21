BLACKWALL 0.2.8: the reserve servers are ranked by speed ahead of time.

### What is new
- The reserve servers (starred) are now measured in the background: response time and download speed. When the server fails, the app moves to the best measured one, not to the one that was quickest to accept a connection. Those that did not answer the measurement are tried last.
- A pass runs 30 seconds after connecting and then every half hour, only while data goes through the VPN. Servers are measured one at a time, the one in use is left alone. Each downloads 1 MB, so three reserve servers take about 6 MB an hour.
- Every server is still proven with a real request before the switch; the app never goes direct.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.8-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.8-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.8-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.8-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.8-ru) · [中文](../../releases/tag/v0.2.8-zh)
