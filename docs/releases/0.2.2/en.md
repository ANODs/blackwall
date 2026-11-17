BLACKWALL 0.2.2: the Mac app starts on macOS 13 and later again.

### What is fixed
- macOS: the app was built for the newest macOS of the build machine, so a Mac with an older system (even a minor version behind) refused to open it. It now asks for macOS 13 or later.
- Updates check that a new version starts on this Mac before installing it, and put the old one back at once if it does not start.
- Everything from 0.2.1: the report for GitHub issues in Settings, and updates in every build.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.2-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.2-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.2-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.2-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.2-ru) · [中文](../../releases/tag/v0.2.2-zh)
