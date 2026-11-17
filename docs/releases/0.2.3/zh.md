BLACKWALL 0.2.3：Android 上可以访问局域网，空闲时几乎不耗电。

### 修复内容
- Android：连接 VPN 时，路由器、打印机、投屏以及局域网中的其他设备都无法访问。现在局域网（10/8、172.16/12、192.168/16、链路本地、组播）不经过 VPN，与电脑上一致。
- Android：核心每秒都会向界面发送状态，即使没有流量、界面已关闭。现在只在状态变化或界面显示时发送，空闲的 VPN 几乎不耗电。
- 在 Android 上与 NekoBox 和 Hiddify 对比（Shadowsocks 2022）：内存占用最少（空闲 23 MB，对比 96 和 182），单线程下载最快，应用最小（3 MB）。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.3-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.3-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.3-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.3-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.3-en) · [Русский](../../releases/tag/v0.2.3-ru)
