BLACKWALL 0.2.23: a subscription is added with one press of an "add to app" button.

### What is new
- Links of the form `blackwall://add/<subscription address>` open the app, started or not, and add the subscription the way a pasted address is added. A provider can put such a button next to the ones for other clients. Works on macOS, Windows, Linux and Android.
- An address that is already in the app is downloaded again instead of being added twice. That holds for a pasted address too.
- A link connects nothing by itself and changes nothing that is already there. Only `http` and `https` addresses are taken.
- Linux: a menu entry left by an earlier version is brought up to date by the app when it starts.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.23-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.23-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.23-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.23-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.23-ru) · [中文](../../releases/tag/v0.2.23-zh)
