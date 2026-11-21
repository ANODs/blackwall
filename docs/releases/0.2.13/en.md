BLACKWALL 0.2.13: automatic updates work on Windows.

### What is new
- Windows: a new version was downloaded and verified but never installed. Windows does not let a running program be renamed the way BLACKWALL did it, and the log said `not installed: FileBusy`. The app now moves itself aside the way Windows allows, so the next versions install themselves.
- On Windows this version has to be downloaded and started by hand once: the old one cannot update itself. The hidden folder `.BLACKWALL-….staging` beside the old version can be deleted.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.13-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.13-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.13-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.13-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.13-ru) · [中文](../../releases/tag/v0.2.13-zh)
