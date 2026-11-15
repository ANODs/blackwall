BLACKWALL 0.1.1 — protection from boot, and updates without the password.

### What is new
- macOS: traffic is held from boot until the service is up, so apps that start at login no longer reach the network past the VPN. It turns on by itself with "Launch at login" in TUN mode when auto-connect is on or some apps have a VPN rule of their own. If no service comes within two minutes of a login, the traffic is let go.
- macOS: the network helper updates itself, checking the release signature. The administrator password is asked once, at installation. Moving on from 0.1.0 asks for it one last time.

### Download
| System | File |
|---|---|
| macOS (Apple Silicon) | `BLACKWALL-0.1.1-en-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.1.1-en-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.1.1-en-linux-x86_64.tar.gz` |

The build is not signed by Apple or Microsoft yet. macOS: right-click the app → Open. Windows: SmartScreen → More info → Run anyway.

Other languages: [Русский](../../releases/tag/v0.1.1-ru) · [中文](../../releases/tag/v0.1.1-zh)
