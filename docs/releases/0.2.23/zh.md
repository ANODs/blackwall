BLACKWALL 0.2.23：点一下“添加到应用”按钮即可添加订阅。

### 新增内容
- 形如 `blackwall://add/<订阅地址>` 的链接会打开应用（无论是否已在运行），并像手动粘贴地址一样添加订阅。服务商可以把这个按钮放在其他客户端的按钮旁边。适用于 macOS、Windows、Linux 和 Android。
- 应用中已有的地址会重新下载，而不会重复添加。手动粘贴地址时也是如此。
- 链接本身不会发起连接，也不会改动已有的内容。只接受 `http` 和 `https` 地址。
- Linux：旧版本留下的菜单项会在应用启动时自动更新。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.23-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.23-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.23-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.23-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.23-en) · [Русский](../../releases/tag/v0.2.23-ru)
