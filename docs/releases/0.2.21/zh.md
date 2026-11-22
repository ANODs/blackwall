BLACKWALL 0.2.21：Windows 上在其他 VPN 开启时拒绝连接，并指出是哪一个。

### 新增内容
- Windows：在已连接其他 VPN（hidemy.name、OpenVPN、WireGuard 等）时，以前点击连接仍会接管流量，断线保护还会切断那个 VPN 自己的连接：两者都无法使用，另一个 VPN 也无法重新连接。现在 BLACKWALL 会先检查路由，不改动网络，并提示需要关闭哪个 VPN。
- 退出后不留任何进程，只有一个窗口，新版本取代旧版本（0.2.20）。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.21-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.21-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.21-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.21-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.21-en) · [Русский](../../releases/tag/v0.2.21-ru)
