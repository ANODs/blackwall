BLACKWALL 0.2.10：Windows 上的窗口又能打开了；如果出了问题，您会知道该去哪里报告。

### 新增内容
- Windows：在 0.2.9 中，窗口打开后立即关闭。托盘图标的图像在内存中位于未对齐的地址，SDL 在转换它时终止了程序。已修复。
- 窗口现在会把日志写入设置文件夹中的 `window.log`（Windows 上为 `%APPDATA%\BLACKWALL`），与报告一样不含链接、密钥和地址。上一次运行的日志保存在旁边，并会包含在 GitHub 报告中。
- Windows：如果窗口仍然崩溃，会弹出消息说明日志的位置，并提供一个按钮来打开新的 GitHub 问题并显示该文件以便附加。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.10-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.10-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.10-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.10-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.10-en) · [Русский](../../releases/tag/v0.2.10-ru)
