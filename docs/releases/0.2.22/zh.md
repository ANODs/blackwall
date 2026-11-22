BLACKWALL 0.2.22：在 Windows 上开启 VPN 后网站可以打开，家庭网络中也一样。

### 新增内容
- Windows：连接 VPN 后任何域名都无法解析，因此网站打不开，而不需要域名的应用（Telegram）却能使用。隧道适配器没有自己的 DNS 服务器，Windows 便通过网络本身的接口询问路由器，而断线保护会拦截那里的域名查询。现在适配器指定了隧道的 DNS 服务器，Windows 会优先询问它。
- Windows：在其他 VPN 开启时 BLACKWALL 不会连接，并指出是哪一个（0.2.21）。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.22-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.22-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.22-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.22-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.22-en) · [Русский](../../releases/tag/v0.2.22-ru)
