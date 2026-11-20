BLACKWALL 0.2.9: Windows запускается на любой сборке системы, и zapret рядом больше не прячется.

### Что нового
- Windows: на некоторых сборках системы (например, 26300) сервис не запускался с ошибкой AddressFamilyUnsupported, потому что в них нет Unix-сокетов. Теперь окно и сервис общаются через локальный адрес 127.0.0.1 с секретом, который знает только ваш профиль.
- Windows: zapret (winws.exe, в том числе zapret-discord-youtube) и GoodbyeDPI теперь видны как программы, мешающие подключению, и их можно выгрузить из BLACKWALL. Службу останавливает сервис BLACKWALL, системные процессы и сам BLACKWALL не трогаются.
- Если сервис не смог запуститься, в отчёте для GitHub видно, на каком шаге.

### Скачать
| Система | Файл |
|---|---|
| macOS 13+ (Apple Silicon) | `BLACKWALL-0.2.9-ru-macos-arm64.zip` |
| Windows (x64) | `BLACKWALL-0.2.9-ru-windows-x86_64.exe` |
| Linux (x64) | `BLACKWALL-0.2.9-ru-linux-x86_64.tar.gz` |
| Android 10+ (arm64, x86_64) | `BLACKWALL-0.2.9-android.apk` |

macOS: правый клик по приложению → «Открыть». Windows: SmartScreen → «Подробнее» → «Выполнить в любом случае». Linux: распакуйте, запустите `./install.sh`. Android: откройте APK и разрешите установку из этого источника.

Другие языки: [English](../../releases/tag/v0.2.9-en) · [中文](../../releases/tag/v0.2.9-zh)
