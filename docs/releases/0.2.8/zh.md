BLACKWALL 0.2.8：备用服务器提前按速度排序。

### 新增内容
- 备用服务器（加星标的）现在会在后台测速：响应时间和下载速度。当前服务器失效时，应用会切换到测速结果最好的服务器，而不是连接最快的那个。测速时没有响应的服务器最后才尝试。
- 测速在连接后 30 秒进行，之后每半小时一次，且仅在有流量经过 VPN 时进行。服务器逐个测速，正在使用的服务器不受影响。每个服务器下载 1 MB，三个备用服务器每小时约消耗 6 MB。
- 切换前每个服务器仍会用真实请求验证；应用从不直连。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.8-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.8-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.8-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.8-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.8-en) · [Русский](../../releases/tag/v0.2.8-ru)
