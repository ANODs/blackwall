BLACKWALL 0.2.15：在 Windows 上，使用普通 TLS 的服务器可以工作了。

### 新增内容
- Windows：使用 TLS（非 REALITY）的 VLESS 和 Trojan 服务器可能完全无法工作，而在其他系统上却正常。Windows 只保存已经下载过的根证书，当浏览器（Chrome）使用自己的证书集时，例如 Let's Encrypt 的根证书可能并不存在。现在 Windows 上的 BLACKWALL 自带完整的根证书集，无需为此下载任何内容。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.15-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.15-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.15-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.15-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.15-en) · [Русский](../../releases/tag/v0.2.15-ru)
