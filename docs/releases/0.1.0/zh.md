BLACKWALL 首个公开版本 —— 一款用 Zig 编写的轻量级 VPN 客户端。

### 已可用
- 通过链接添加订阅，或直接粘贴密钥（`vless://`、`trojan://`、`ss://`、`vmess://`）；显示每台服务器的延迟。
- 协议：VLESS（REALITY、Vision、TLS）、Trojan、Shadowsocks（含 2022）、VMess。传输：TCP、WebSocket、HTTPUpgrade、gRPC、XHTTP（stream-one）。
- macOS：接管全部流量（TUN），并按应用分流——经 VPN、经指定服务器、直连或断网。应用启动的程序沿用该应用的规则。流量由后台服务承载，可以关闭窗口；菜单栏显示状态和速度。
- 断线保护、断开后的保护（拥有独立 VPN 规则的应用保持无网络）以及备用服务器：服务器停止响应时先重连一次，再切换到带星标的服务器。
- macOS：检测妨碍连接的其他 VPN。
- Windows 和 Linux：本地 SOCKS5 代理 `127.0.0.1:1080`。
- 带签名校验的自动更新。

### 暂未支持
- 在 Windows 和 Linux 上接管全部流量。
- 通过 Trojan、Shadowsocks、VMess 传输 UDP；Hysteria2、TUIC、WireGuard；本地 DPI 绕过。
- Android。

macOS 是实际使用中验证过的平台。Windows 和 Linux 版本目前只通过了自动测试。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.1.0-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.1.0-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.1.0-zh-linux-x86_64.tar.gz` |

本版本尚未经过 Apple 和 Microsoft 签名。macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。

其他语言：[English](../../releases/tag/v0.1.0-en) · [Русский](../../releases/tag/v0.1.0-ru)
