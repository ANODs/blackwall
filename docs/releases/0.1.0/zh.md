BLACKWALL 首个公开版本 —— 一款用 Zig 编写的轻量级 VPN 客户端。

### 已支持
- 通过链接添加订阅，或直接粘贴密钥（`vless://`、`trojan://` 等）；显示每台服务器的延迟。
- 本地 SOCKS5 代理 `127.0.0.1:1080`：设置为使用它的应用可直连或通过 VLESS（TCP、REALITY、Vision）传输。
- 按应用设置路由、流量统计、断线保护和 IPv6 设置。

### 尚未支持
- 全局流量接管（TUN）、WS / XHTTP / TLS 传输方式以及网络层的按应用规则。
- Android。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.1.0-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.1.0-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.1.0-zh-linux-x86_64.tar.gz` |

本版本尚未经过 Apple 和 Microsoft 签名。macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。

其他语言：[English](../../releases/tag/v0.1.0-en) · [Русский](../../releases/tag/v0.1.0-ru)
