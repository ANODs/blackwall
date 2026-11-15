BLACKWALL 0.1.1 —— 开机即保护，更新无需密码。

### 新增内容
- macOS：从系统启动起即接管流量，直到服务就绪。登录时自启动的应用不再能绕过 VPN 联网。在 TUN 模式下开启“登录时启动”，并且已开启自动连接或存在拥有独立 VPN 规则的应用时自动生效。登录后两分钟内服务仍未就绪，则放行流量。
- macOS：网络助手可校验发布签名后自行更新。管理员密码只在安装时询问一次。从 0.1.0 升级时会最后询问一次。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.1.1-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.1.1-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.1.1-zh-linux-x86_64.tar.gz` |

本版本尚未经过 Apple 和 Microsoft 签名。macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。

其他语言：[English](../../releases/tag/v0.1.1-en) · [Русский](../../releases/tag/v0.1.1-ru)
