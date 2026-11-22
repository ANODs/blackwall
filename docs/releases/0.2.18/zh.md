BLACKWALL 0.2.18：Windows 上在其他 VPN 开启时也能连接。

### 新增内容
- Windows：在已连接其他 VPN（OpenVPN 等）时点击连接会让电脑断网，关闭那个 VPN 后也无法恢复。服务把自己的连接放在了那个 VPN 的适配器上，而它自己的断线保护同时切断了那个 VPN。现在无论还连接着什么，服务都把自己的连接保持在网络本身的接口上。
- 每小时检查一次更新，而不是每六小时：一直不关闭的窗口不会再错过一整天的版本。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.18-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.18-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.18-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.18-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.18-en) · [Русский](../../releases/tag/v0.2.18-ru)
