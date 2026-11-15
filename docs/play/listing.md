# Google Play listing

Texts for the store page. Limits: title 30, short description 80, full description 4000.

Category: Tools. Price: free, no ads, no purchases. Package: `dev.blackwall`.
Privacy policy: <https://github.com/ANODs/blackwall/blob/main/docs/privacy.md>

## English (en-US)

**Title** — BLACKWALL: VPN client

**Short description** — Open-source VPN client with a route for every app. No ads, no accounts.

**Full description**

BLACKWALL is a small, open-source VPN client. It connects to the servers you add yourself — by a subscription link or by keys — and gives every application its own route.

It does not come with servers and it is not a VPN service: you need a subscription or a server of your own.

ROUTES PER APPLICATION
• Through VPN only — the app never touches the network without the VPN
• Direct — the app stays outside the VPN
• No network — the app is cut off

PROTECTION THAT DOES NOT LET GO
• After Disconnect, apps set to "Through VPN only" stay without network instead of going out directly
• Reserve servers: when the server stops responding the app reconnects once, then moves to the servers you starred — never to a direct connection
• Comes back by itself after a restart of the phone; works with Android's "Always-on VPN" and "Block connections without VPN"

PROTOCOLS
• VLESS (REALITY with Vision, TLS), Trojan, VMess, Shadowsocks (including 2022)
• Transports: TCP, WebSocket, HTTPUpgrade, gRPC, XHTTP
• Links: vless://, trojan://, ss://, vmess://, subscriptions (plain, base64, Xray JSON)

SMALL AND QUIET
• About 3 MB. No ads, no analytics, no account
• The notification shows the server, the time connected and the speed, with a switch
• Interface in English, Russian and Chinese

OPEN SOURCE
MIT licence. The code, the build and the tests: https://github.com/ANODs/blackwall

BLACKWALL uses Android's VpnService to carry your applications' traffic to the server you chose. Nothing is sent to the developer.

## Русский (ru-RU)

**Название** — BLACKWALL: VPN-клиент

**Краткое описание** — Открытый VPN-клиент с маршрутом для каждого приложения. Без рекламы и аккаунтов.

**Полное описание**

BLACKWALL — небольшой VPN-клиент с открытым кодом. Он подключается к серверам, которые вы добавляете сами — ссылкой на подписку или ключами, — и задаёт каждому приложению свой маршрут.

В приложении нет своих серверов, и это не VPN-сервис: нужна ваша подписка или собственный сервер.

МАРШРУТ ДЛЯ КАЖДОГО ПРИЛОЖЕНИЯ
• Только через VPN — приложение не выходит в сеть без VPN
• Напрямую — приложение остаётся вне VPN
• Без сети — приложение отрезано от сети

ЗАЩИТА, КОТОРАЯ НЕ ОТПУСКАЕТ
• После отключения приложения с правилом «Только через VPN» остаются без сети, а не идут напрямую
• Резервные серверы: если сервер перестал отвечать — одно переподключение, затем переход на серверы со звёздочкой, и никогда не напрямую
• Возвращается сам после перезагрузки телефона; работает с системными «Постоянной VPN» и «Блокировать соединения без VPN»

ПРОТОКОЛЫ
• VLESS (REALITY с Vision, TLS), Trojan, VMess, Shadowsocks (включая 2022)
• Транспорты: TCP, WebSocket, HTTPUpgrade, gRPC, XHTTP
• Ссылки: vless://, trojan://, ss://, vmess://, подписки (список, base64, Xray JSON)

МАЛЕНЬКИЙ И ТИХИЙ
• Около 3 МБ. Без рекламы, аналитики и аккаунтов
• В уведомлении — сервер, время подключения и скорость, с выключателем
• Интерфейс на русском, английском и китайском

ОТКРЫТЫЙ КОД
Лицензия MIT. Код, сборка и тесты: https://github.com/ANODs/blackwall

BLACKWALL использует системный VpnService, чтобы передавать трафик ваших приложений на выбранный вами сервер. Разработчику ничего не отправляется.

## What the console will ask

- **VPN declaration** (App content → VpnService): the app's core function is a VPN
  client; traffic goes to the server the user configured and is encrypted by that
  server's protocol.
- **Data safety**: no data collected, no data shared. Traffic passes to the user's own
  server, which the form does not count as collection by the app.
- **Ads**: none. **Target audience**: 18+ is the simplest honest answer for a VPN tool.
- **Content rating**: utility, no user-generated content.
- A phone screenshot set (at least two), a 512×512 icon and a 1024×500 feature graphic.
