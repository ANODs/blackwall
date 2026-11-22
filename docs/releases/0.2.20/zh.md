BLACKWALL 0.2.20：退出后不留任何进程，只有一个窗口，新版本取代旧版本。

### 新增内容
- 退出会结束一切：VPN 断开，服务停止并放行流量，窗口等这些完成后才关闭。此前退出后服务仍在运行，断线保护继续占住网络，而屏幕上没有任何提示。唯一的例外：开启“VPN 关闭时保护”且有应用被限定走 VPN 时，这些应用仍被拦住，与断开连接后相同。
- 只有一个窗口：再次启动会显示已打开的窗口，然后退出。
- 启动更新的版本会关闭正在运行的旧版本并接替它；在 Windows 上还会删除旧文件。连接在此期间不中断。
- Windows：开启 VPN 并允许“本地网络”时浏览器可正常使用（0.2.19）。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.20-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.20-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.20-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.20-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.20-en) · [Русский](../../releases/tag/v0.2.20-ru)
