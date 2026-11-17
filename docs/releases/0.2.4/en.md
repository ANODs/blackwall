BLACKWALL 0.2.4: a provider's "Auto" works as it should.

### What is new
- Subscriptions in Xray JSON with balancers (the "Auto" of Remnawave, Marzban, 3x-ui and the like) used to become one server each: only the first of the group was taken. Now an "Auto" is one entry with all its servers: each is measured, the fastest carries the traffic, the others take over when it stops, never a direct connection meanwhile.
- A refresh no longer drops anything: servers are followed by name, a group's new servers are taken in while connected, and a server that left the list stays in use until Disconnect.
- The provider's headers are read: the subscription's title, how often to refresh it (the app does it by itself), its announcement and support link (in Settings).
- Subscriptions are requested as BLACKWALL/<version>, so providers can send it their full format.

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.4-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.4-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.4-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.4-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.4-ru) · [中文](../../releases/tag/v0.2.4-zh)
