BLACKWALL 0.2.6：Android 每 GB 的处理器时间减半。

### 新增内容
- Android：处理器支持时（几乎所有手机都支持），加密使用处理器自带的 AES 指令：Shadowsocks 和 TLS（VLESS、REALITY、Trojan）的 AES-GCM 每 GB 的处理器时间减半，也就是更省电。没有这些指令的手机仍按原方式工作。
- Android：隧道数据包从 1500 字节变为 9000 字节，数量减少到六分之一，多个下载同时进行时更快。
- 在同一模拟器上与 NekoBox 对比：每 GB 处理器时间 5.6 秒对 12.2 秒，单个下载 461 Mbit/s 对 412，八个同时 882 对 1162（这一项 NekoBox 仍领先）。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.6-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.6-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.6-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.6-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.6-en) · [Русский](../../releases/tag/v0.2.6-ru)
