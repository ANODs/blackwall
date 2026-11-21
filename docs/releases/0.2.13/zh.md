BLACKWALL 0.2.13：Windows 上的自动更新可以用了。

### 新增内容
- Windows：新版本会被下载并验证，但从未被安装。Windows 不允许以 BLACKWALL 原来的方式重命名正在运行的程序，日志中显示 `not installed: FileBusy`。现在程序会以 Windows 允许的方式把自己移开，之后的版本会自动安装。
- 在 Windows 上，此版本需要手动下载并运行一次：旧版本无法自行更新。旧版本旁边的隐藏文件夹 `.BLACKWALL-….staging` 可以删除。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.13-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.13-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.13-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.13-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.13-en) · [Русский](../../releases/tag/v0.2.13-ru)
