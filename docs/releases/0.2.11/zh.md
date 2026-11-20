BLACKWALL 0.2.11：Windows 上的备用服务器又能用了。

### 新增内容
- Windows：“服务器能否传输流量”的检查和测速无法工作，BLACKWALL 因此把所有服务器（包括正常的）都当作失效，备用服务器始终无法接替。已修复。
- Windows：与服务器的连接中断时，日志和 GitHub 报告中现在会显示系统的确切错误代码，从而判断是服务器、网络还是 BLACKWALL 本身中断了连接。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.11-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.11-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.11-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.11-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.11-en) · [Русский](../../releases/tag/v0.2.11-ru)
