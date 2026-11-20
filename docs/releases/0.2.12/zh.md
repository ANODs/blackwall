BLACKWALL 0.2.12：Windows 上的隧道快了几十倍，视频可以加载了。

### 新增内容
- Windows：隧道速度只有 1–2 MB/s，YouTube 和 Telegram 的视频无法加载，与服务器的连接在建立时就会中断。原因是 Windows 会向每个网络适配器（包括 BLACKWALL 的适配器）发送本地网络查询（LLMNR），每秒数千个，真正的流量只能在后面排队。现在这类数据包（LLMNR、mDNS、SSDP、NetBIOS）不再进入隧道，通过隧道下载的速度几乎与不使用隧道时相同：测试机上为 79 MB/s，而不是 1–2 MB/s。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.12-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.12-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.12-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.12-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.12-en) · [Русский](../../releases/tag/v0.2.12-ru)
