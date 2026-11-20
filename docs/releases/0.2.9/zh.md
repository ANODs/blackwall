BLACKWALL 0.2.9：在任何版本的 Windows 上都能启动，旁边运行的 zapret 也不会再被忽略。

### 新增内容
- Windows：在部分系统版本（例如 26300）上，服务因缺少 Unix 套接字而无法启动，报错 AddressFamilyUnsupported。现在窗口与服务通过 127.0.0.1 通信，并使用只有您的用户配置文件才能读取的密钥。
- Windows：zapret（winws.exe，包括 zapret-discord-youtube）和 GoodbyeDPI 现在会显示为妨碍连接的程序，并可由 BLACKWALL 卸载。其服务由 BLACKWALL 服务停止；系统进程和 BLACKWALL 本身不会被触碰。
- 服务无法启动时，GitHub 报告中会显示失败的步骤。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.9-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.9-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.9-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.9-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.9-en) · [Русский](../../releases/tag/v0.2.9-ru)
