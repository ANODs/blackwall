BLACKWALL 0.2.9: Windows starts on every build of the system, and zapret beside it no longer goes unseen.

### What is new
- Windows: on some builds of the system (26300, for one) the service did not start, failing with AddressFamilyUnsupported, because they have no Unix sockets. The window and the service now talk over 127.0.0.1 with a secret only your profile can read.
- Windows: zapret (winws.exe, zapret-discord-youtube among them) and GoodbyeDPI are now shown as programs in the way of the connection, and BLACKWALL can unload them. The BLACKWALL service stops their service; system processes and BLACKWALL itself are never touched.
- When the service cannot start, the report for GitHub shows at which step.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.9-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.9-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.9-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.9-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.9-ru) · [中文](../../releases/tag/v0.2.9-zh)
