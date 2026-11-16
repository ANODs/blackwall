BLACKWALL 0.1.4 —— 完整支持 Windows。

### 新增内容
- Windows：在窗口中即可让全部流量通过 VPN（TUN 模式，基于 Wintun），支持按应用设置路由、断开后继续拦截以及备用服务器，与 macOS 和 Linux 相同。
- Windows：基于 Windows 筛选平台（WFP）的断网保护。服务崩溃后过滤规则仍然保留，任何流量都不会绕过 VPN；严格模式只允许流量发往 VPN 服务器。
- Windows：首次连接时系统会询问一次（UAC），是否安装 BLACKWALL 系统服务。之后的版本会在校验发布签名后自行替换它。
- Windows：应用列表来自“开始”菜单。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.1.4-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.1.4-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.1.4-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.1.4-android.apk` |

Windows：SmartScreen → “更多信息” → “仍要运行”；首次连接时在 UAC 窗口中允许安装服务。
macOS：右键点击应用 → “打开”。Linux：解压后运行 `./install.sh`，然后从菜单启动 BLACKWALL。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.1.4-en) · [Русский](../../releases/tag/v0.1.4-ru)
