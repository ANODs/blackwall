BLACKWALL 0.2.0 —— 网站规则、绕过 DPI、全协议 UDP、二维码。

### 新增内容
- 网站路由：youtube.com 及其所有子域名可以像应用一样设置自己的路由。应用自身的规则始终优先，因此被固定走 VPN 的应用不会离开 VPN。
- 绕过 DPI 已可用：直连路由会把 TLS ClientHello 以按域名过滤的设备识别不出的形式发出，每个网站从三种方式中自动选择。在俄罗斯的运营商网络中，直连完全打不开的 YouTube 通过它以全速打开。
- 所有协议都支持 UDP：VMess、Trojan 和 Shadowsocks 现在也能承载 UDP（游戏、通话、DNS），不再只有 VLESS。
- 二维码：在 Android 上可通过相机或图片添加订阅，在电脑上可从剪贴板或屏幕读取。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.0-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.0-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.0-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.0-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.0-en) · [Русский](../../releases/tag/v0.2.0-ru)
