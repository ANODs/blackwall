BLACKWALL 0.2.24：连接看起来像当前的 Chrome，俄罗斯和独联体的网站直连，设置更易读。

### 新增内容
- 与服务器的连接现在看起来像 Chrome 155。在一些俄罗斯网络中，看起来像旧版 Chrome 的连接会被切断，几次之后该网络会在数小时内无法访问这台服务器。
- 俄罗斯和独联体的网站绕过 VPN 打开，设有 VPN 规则的应用也一样，因此看不到服务器地址。默认开启，开关位于“设置” → “路由” → “俄罗斯和独联体直连”。为网站设置的规则优先。列表每天更新。
- macOS、Windows、Linux：应用和网站的规则，连同其他应用的走向，可以复制到剪贴板、从剪贴板载入或重置（“设置” → “路由” → “规则”）。
- 设置分为“连接”“防护”“路由”“应用”几组，不常用的技术选项收在“高级”中。每个选项都有更清楚的名称和简短说明。已保存的设置保持不变。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.24-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.24-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.24-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.24-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.24-en) · [Русский](../../releases/tag/v0.2.24-ru)
