BLACKWALL 0.2.14：服务器的真实国家。

### 新增内容
- 服务商经常用一个国家来命名服务器，而它实际从另一个国家接入互联网。服务器在使用中时，BLACKWALL 会通过它向 cloudflare.com 发送一次请求，以确定它真正的出口。该国家会在服务器列表、主界面、托盘和 Android 通知中以圆点标出；如果与声明的国家不同，两者都会显示。对于“Auto”组，显示的是当前使用的服务器的国家。可以在设置中关闭：“服务器真实国家”。
- 当服务在网络不稳定的情况下运行数周时，服务和窗口的日志不再无限增长。
- 服务启动失败时，会释放它已占用的所有资源。
- Linux：中断的更新不再在程序旁边留下旧文件。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.14-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.14-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.14-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.14-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.14-en) · [Русский](../../releases/tag/v0.2.14-ru)
