BLACKWALL 0.2.4：订阅中的「自动」分组正常工作。

### 新增内容
- 带负载均衡的 Xray JSON 订阅（Remnawave、Marzban、3x-ui 等面板的「自动」）以前只取分组中的第一个服务器。现在「自动」是一个条目，包含其全部服务器：逐个测速，由最快的承载流量，它失效时其余服务器接替，期间不会直连。
- 更新订阅不再中断任何连接：按名称匹配服务器，连接期间也会接入分组的新服务器，从列表中消失的服务器在断开前继续使用。
- 读取提供商的响应头：订阅名称、更新频率（应用自动更新）、公告和支持链接（在设置中）。
- 订阅以 BLACKWALL/<版本> 的身份请求，便于提供商返回完整格式。

### 下载
| 系统 | 文件 |
|---|---|
| macOS（Apple 芯片） | `BLACKWALL-0.2.4-zh-macos-arm64.zip` |
| Windows（x64） | `BLACKWALL-0.2.4-zh-windows-x86_64.exe` |
| Linux（x64） | `BLACKWALL-0.2.4-zh-linux-x86_64.tar.gz` |
| Android 10+（arm64、x86_64） | `BLACKWALL-0.2.4-android.apk` |

macOS：右键点击应用 → “打开”。Windows：SmartScreen → “更多信息” → “仍要运行”。Linux：解压后运行 `./install.sh`。Android：打开 APK 并允许从该来源安装。

其他语言：[English](../../releases/tag/v0.2.4-en) · [Русский](../../releases/tag/v0.2.4-ru)
