BLACKWALL 0.2.20: Quit leaves nothing behind, one window, the newest release wins.

### What is new
- Quit ends everything: the VPN is disconnected, the service stops and lets the traffic go, and the window waits for that before it closes. Until now the service went on after Quit, with the kill switch holding the network and nothing on screen to say so. One exception: with "Protect when the VPN is off" on and applications held to the VPN, those stay held, as after Disconnect.
- One window at a time: a second start shows the window that is already open and leaves.
- Starting a newer release closes the older one that runs and takes over; on Windows it also removes the older file. The connection is carried all the while.
- Windows: browsers work with the VPN on and "Local network" allowed (0.2.19).

### Download
| System | File |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.20-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.20-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.20-en-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.20-android.apk` |

macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway. Linux: unpack, run `./install.sh`. Android: open the APK and allow installing from that source.

Other languages: [Русский](../../releases/tag/v0.2.20-ru) · [中文](../../releases/tag/v0.2.20-zh)
