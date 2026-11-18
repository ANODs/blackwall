BLACKWALL 0.2.5: subscriptions download in full again on the computer.

### What is fixed
- Windows, macOS and Linux: 0.2.4 kept only the first piece of a subscription's answer, so a refresh said the subscription had no supported servers (the servers already in the list stayed). The whole answer is read again, plain, compressed or in chunks. Android was not affected.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.5-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.5-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.5-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.5-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.5-ru) · [中文](../../releases/tag/v0.2.5-zh)
