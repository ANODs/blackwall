BLACKWALL 0.1.4 — Windows, all the way.

### What is new
- Windows: all traffic goes through the VPN (TUN mode, on Wintun) from the window, with a route for every application, protection after Disconnect and reserve servers, as on macOS and Linux.
- Windows: the kill switch, on the Windows Filtering Platform. Its filters stay if the service dies, so nothing leaves past the VPN; strict lets traffic out only to the VPN servers.
- Windows: the first Connect asks once (UAC) to install the BLACKWALL system service. Later releases replace it by themselves, after checking the release signature.
- Windows: the list of applications comes from the Start menu.

### Download
| System | File |
|---|---|
| macOS (Apple Silicon) | `BLACKWALL-0.1.4-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.1.4-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.1.4-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.1.4-android.apk` |

Windows: SmartScreen → More info → Run anyway; at the first Connect, allow the service in the UAC prompt.
macOS: right-click the app → Open. Linux: unpack, run `./install.sh`, start BLACKWALL from the menu. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.1.4-ru) · [中文](../../releases/tag/v0.1.4-zh)
