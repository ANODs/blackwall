BLACKWALL 0.2.5：电脑版重新完整下载订阅。

### 修复内容
- Windows、macOS 和 Linux：0.2.4 只保存了订阅响应的第一部分，因此更新时提示订阅中没有受支持的服务器（列表中已有的服务器仍保留）。现在会完整读取响应，包括普通、压缩和分块传输的响应。Android 不受影响。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.5-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.5-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.5-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.5-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.5-en) · [Русский](../../releases/tag/v0.2.5-ru)
