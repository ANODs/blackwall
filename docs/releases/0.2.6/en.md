BLACKWALL 0.2.6: Android spends half the processor time per gigabyte.

### What is new
- Android: encryption runs on the processor's own AES instructions when it has them (nearly every phone): AES-GCM for Shadowsocks and for TLS (VLESS, REALITY, Trojan) takes half the CPU per gigabyte it took, which is battery. A phone without these instructions keeps the previous way.
- Android: the tunnel's packets are 9000 bytes instead of 1500, six times fewer of them: faster with many downloads at once.
- Measured against NekoBox on the same emulator: 5.6 s of processor per GB against 12.2, one download 461 Mbit/s against 412, eight at once 882 against 1162 (NekoBox still leads there).

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.6-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.6-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.6-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.6-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.6-ru) · [中文](../../releases/tag/v0.2.6-zh)
