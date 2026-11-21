BLACKWALL 0.2.15: на Windows работают серверы с обычным TLS.

### Что нового
- Windows: серверы VLESS и Trojan с TLS (не REALITY) могли не работать вовсе, хотя на других системах работали. Windows хранит у себя только те корневые сертификаты, которые уже скачала, и, например, корня Let's Encrypt там может не оказаться, если браузер (Chrome) пользуется своим набором. Теперь BLACKWALL на Windows знает полный набор корневых сертификатов сам и ничего для этого не скачивает.

### Скачать
| Система | Файл |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.15-ru-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.15-ru-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.15-ru-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.15-android.apk` |

macOS: правый клик по приложению → «Открыть». Windows: SmartScreen → «Подробнее» → «Выполнить в любом случае». Linux: распакуйте, запустите `./install.sh`. Android: откройте APK и разрешите установку из этого источника.

Другие языки: [English](../../releases/tag/v0.2.15-en) · [中文](../../releases/tag/v0.2.15-zh)
