BLACKWALL 0.2.17：被运营商封锁的服务器被放弃的速度提高到三倍。

### 新增内容
- 在主服务器被封锁的网络中，以前备用服务器要在连接后约半分钟才接管，这段时间什么都打不开。服务会两次询问已失效的服务器，每次都等待很久，然后再逐个询问备用服务器。现在第一次检查就够了，等待 5 秒而不是 8 秒，并同时询问三个备用服务器：能传输流量的最佳服务器接管。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.17-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.17-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.17-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.17-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.17-en) · [Русский](../../releases/tag/v0.2.17-ru)
