BLACKWALL 0.2.19：在 Windows 上，开启 VPN 后浏览器恢复正常。

### 新增内容
- Windows：开启断线保护并允许“本地网络”时，VPN 显示正常工作，浏览器却打不开任何网站，而自带地址的应用（Telegram）仍可使用。断线保护会阻止本地网络上的域名查询，以免查询绕过 VPN，但它把 VPN 适配器内部的查询也一并阻止了。家庭网络中负责解析的是位于本地地址的路由器，所以任何域名都无法解析。
- Windows：已连接其他 VPN 时，服务把自己的连接保持在网络本身的接口上，而不是那个 VPN 的适配器上（0.2.18）。
- 每小时检查一次更新（0.2.18）。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.19-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.19-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.19-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.19-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.19-en) · [Русский](../../releases/tag/v0.2.19-ru)
