BLACKWALL 0.2.10: the window opens on Windows again, and if something breaks, you are told where to report it.

### What is new
- Windows: in 0.2.9 the window closed right after it opened. The tray icon's picture sat in memory at an unaligned address, and SDL stopped the program while converting it. Fixed.
- The window now writes its log to `window.log` in the settings folder (`%APPDATA%\BLACKWALL` on Windows), without links, keys or addresses, as in a report. The previous run's log is kept beside it and goes into the report for GitHub.
- Windows: should the window crash anyway, a message says where the log is, with a button that opens a new GitHub issue and shows the file to attach.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.10-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.10-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.10-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.10-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.10-ru) · [中文](../../releases/tag/v0.2.10-zh)
