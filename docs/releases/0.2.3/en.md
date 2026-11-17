BLACKWALL 0.2.3: Android keeps the local network and stays quiet when idle.

### What is fixed
- Android: while connected, the router, printers, casting and anything else on the local network were out of reach. The local network (10/8, 172.16/12, 192.168/16, link-local, multicast) now stays outside the VPN, as on a computer.
- Android: the core told the window its status every second even with nothing moving and the window closed. Now it speaks only when something changes or the window is on screen, so an idle VPN costs the phone next to nothing.
- Measured on Android against NekoBox and Hiddify (Shadowsocks 2022): the least memory of the three (23 MB idle against 96 and 182), the fastest single download, the smallest app (3 MB).

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.3-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.3-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.3-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.3-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.3-ru) · [中文](../../releases/tag/v0.2.3-zh)
