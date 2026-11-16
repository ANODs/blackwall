BLACKWALL 0.1.3 —— 完整支持 Linux。

### 新增内容
- Linux：在窗口中即可让全部流量通过 VPN（TUN 模式），支持按应用设置路由、断开后继续拦截以及备用服务器，与 macOS 相同。
- Linux：基于 nftables 的严格断网保护。服务崩溃后规则仍保留在内核中，任何流量都不会绕过 VPN。
- Linux：BLACKWALL 的任何部分都不以 root 运行。小程序 `blackwall-tun` 只持有一项网络权限，通过系统密码对话框授权一次；更新后依然保留。
- Linux：`install.sh` 会为当前用户把 BLACKWALL 加入应用菜单。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.1.3-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.1.3-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.1.3-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.1.3-android.apk` |

Linux：解压后运行 `./install.sh`，然后从菜单启动 BLACKWALL。需要 5.7 或更新的内核。
macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.1.3-en) · [Русский](../../releases/tag/v0.1.3-ru)
