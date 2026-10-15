# 本机取证工具安装与配置

2026-10-15 可用性复审后的修复：启动器取消命名 `Tool` 参数，避免原生 `-t` 被 PowerShell 当成参数缩写。`scripts/verify-forensic-tools.py` 在 Windows PowerShell 5.1 和当前 PowerShell 完成 16 项检查：默认清单、`-V`、带空格镜像路径的 `mmls -t dos`、原生失败退出码、未知工具拒绝、ALEAPP/iLEAPP `-t fs` 真实解析及环境恢复。两个手机样例的 TSV 均含预设值。本节结果更新下方安装阶段仅版本参数验证的结论；不代表完整手机提取或新增 Agent 适配器已验收。

配置日期：2026-10-15。安装根目录 `E:\Forensics`，项目 `D:\取证`。

## 已准备的软件

| 软件 | 版本 | 可执行入口 |
|---|---|---|
| Volatility 3 | 2.28.2，含 full 可选依赖 | `E:\Forensics\Volatility3\venv\Scripts\vol.exe` |
| The Sleuth Kit | 4.14.0 | `E:\Forensics\SleuthKit\4.14.0\sleuthkit-4.14.0-win32\bin` |
| TestDisk / PhotoRec | 7.2 | `E:\Forensics\TestDisk\7.2\testdisk-7.2` |
| ALEAPP | 2026.4.3 | `E:\Forensics\ALEAPP\2026.4.3\aleapp.exe` |
| iLEAPP | 2026.4.4 | `E:\Forensics\iLEAPP\2026.4.4\ileapp.exe` |
| Autopsy | 4.23.1，当前用户安装 | `E:\Forensics\Autopsy\4.23.1\bin\autopsy64.exe` |

现有 PECmd、MFTECmd、RECmd、SQLECmd 2026.5.0 保留，路径也已列入本机清单。

## 统一启动

在项目根目录的 PowerShell 中执行：

```powershell
.\scripts\forensic-tools.ps1 list
.\scripts\forensic-tools.ps1 mmls -V
.\scripts\forensic-tools.ps1 volatility3 -h
.\scripts\forensic-tools.ps1 aleapp --version
.\scripts\forensic-tools.ps1 ileapp --version
.\scripts\forensic-tools.ps1 autopsy
```

参数会传给所选工具，工具路径来自 `config/local-tools.json`。启动器核对可执行文件 SHA256；软件更新后应核实并更新清单。已验证 Windows PowerShell 5.1 与当前 PowerShell 的 `mmls -V` 参数传递。参数含空格时照常加引号。

Volatility 启动器默认附加 `--offline`，使用 `E:\Forensics\Volatility3\symbols` 和 `E:\Forensics\Volatility3\cache`。官方 Windows 包已核对 SHA256，原包保存在 `E:\Forensics\Volatility3\windows-symbols.zip`；3,014 份符号文件采用解压目录布局，减少逐项读取大 ZIP 的开销。它覆盖部分 Windows 内核版本，具体镜像可能仍需要补充匹配符号，Linux/macOS 则需要对应内核的符号。Python 环境与项目原环境分开，7 个包的 wheel 和带 SHA256 的 `requirements.lock` 保留在 Volatility3 目录。

PhotoRec/TestDisk 按 [CGSecurity 官方镜像运行方法](https://www.cgsecurity.org/wiki/Scripted_run#Windows_UAC)，仅在本次子进程使用 `RunAsInvoker`，保持普通用户权限；不会获得访问物理磁盘的管理员权限。Autopsy 的统一入口将用户数据和缓存放在 `E:\Forensics\AutopsyData`，Java 最大堆设为 4 GiB。

手动工具调用请使用检材副本，把导出结果放入独立目录。这个启动入口由操作者使用，未接入 Agent 的检材登记、资源限制和证据报告链路。

## 与 Agent 的关系

这次完成的是软件下载、安装、路径及独立启动配置。`config/local-tools.json` 是补充工具清单，原 `config/default.toml` 和分析白名单未改。现有 10 个 Agent 适配器继续工作；上述新工具及现有四个 EZTools 的自动分析适配器仍需单独开发和验证。清单中的 `AgentAdapter=False` 明确表示这一点。

TLS 解密依然需要与抓包匹配的密钥材料；这次没有创建虚构密钥或取消结果不完整标记。大镜像的快照、内存、超时、结果分页等限制应在后续适配器任务中处理。

## 验证与证据

记录目录：`E:\Forensics\Validation\20261015`。下载原包、来源和摘要：`E:\Forensics\Downloads\20261015`。

- 9 个命令行入口的版本／帮助检查通过：mmls、fls、icat、tsk_recover、PhotoRec、TestDisk、ALEAPP、iLEAPP、Volatility。
- 自建 FAT12/MBR 小镜像：分区与目录读取、正常文件提取、删除项恢复、tsk_recover 和 PhotoRec PNG 恢复通过；输入镜像 SHA256 保持一致。
- 自建 Android XML 与 iOS plist：ALEAPP/iLEAPP 在 TSV 输出中找到预设字段，输入哈希保持一致。
- Volatility full 依赖安装成功，`pip check` 通过。全部 7 个 wheel 与官方 PyPI SHA256 一致；Windows 符号包与官方发布 SHA256 一致。
- Volatility 以 `--offline` 完成符号检查，退出码 0：官方包 3,014 个文件全部进入 Windows 符号缓存，ISF 检查返回 3,014 条记录。首次解压布局索引用时约 13 分钟，缓存已建立。记录 `volatility-symbol-check.json`；本轮没有真实内存镜像，未声称内存案件分析通过。
- Autopsy MSI 安装退出码 0，Windows Installer 产品状态 5（已安装），版本与安装路径正确。冷启动出现标题为“Autopsy 4.23.1”的主窗口，进程 Responding=True，测试后已结束专用进程；官方包启动日志含 JavaFX 和重复 JAR 的警告，未完成完整案件导入与 GUI 交互验收。`--help` 的退出码为 2，未将它伪报为退出码 0。
- 原 Agent `doctor` 成功；本轮未修改分析核心或项目依赖，未重跑整个既有测试集。
- 安装脚本 Ruff 检查通过。启动器聚焦复查发现 Windows PowerShell 5.1 会将高级脚本的 `-V` 绑定为 `-Verbose`，已改成普通脚本参数转发；部分 PS5 子进程环境没有 `Get-FileHash`，已改为 .NET SHA256。两个 PowerShell 版本的原生版本参数、含空格路径、实际失败退出码、未知工具拒绝，以及环境恢复共 9 项验证全部通过，记录在 `Validation\20261015\launcher\results.json`。根代理聚焦复查没有未处理的可操作发现。

ALEAPP、iLEAPP、Autopsy 安装包按官方 release SHA256 校验。TSK 和 TestDisk/PhotoRec 通过官方 HTTPS 地址下载并保存本地摘要；TSK 的 GPG 签名文件已保存，未进行 GPG 身份验证。

最终汇总：`E:\Forensics\Validation\20261015\summary.json`。软件安装和本机独立启动配置验收完成，没有待处理的本轮安装问题；后续 Agent 适配器开发继续使用原有证据链与白名单边界。

## 可直接使用的复审提示词

```text
复审 D:\取证 本次取证软件安装与启动配置。范围：scripts/forensic-tools.ps1、config/local-tools.json、docs/TOOLS_SETUP.md、local-state/setup-20261015 下的安装与验证脚本，以及 E:\Forensics\Downloads\20261015 和 E:\Forensics\Validation\20261015 的事实记录。验收：软件路径与版本真实可用；来源与已声称的摘要校验一致；Windows PowerShell 5.1/当前 PowerShell 保留原生参数和退出码；PhotoRec 的局部普通权限环境不污染后续进程；Volatility 使用已配置的离线符号与缓存；既有 Agent 配置继续有效；不能把安装完成说成 Agent 适配器接入完成。优先检查已有真实样例及输入哈希记录，只在变化或证据缺口时补充检查。输出仅含可操作发现，每项给出 P1/P2/P3、文件与行号、复现条件、实际影响和修复验收条件；无发现明确说明，并列出尚未验证的范围。
```

## 可直接使用的修复提示词

```text
依据本次复审的可操作发现修复取证工具安装配置，保持 docs/TOOLS_SETUP.md 的验收标准。已知的 PowerShell 5.1 -V 参数绑定和 Get-FileHash 可用性问题已经修复，两个 PowerShell 环境共9项专项检查通过。当前没有未处理的可操作发现，没有新发现则保持代码不变。若发现新问题，先复现，再最小修复并重测相关入口；不得用删除工具、隐藏失败、取消哈希校验、取消 partial 标记或开放模型任意命令来获得通过。Autopsy 的完整案件流程、真实内存镜像、Agent 新适配器属于明确记录的后续验收范围，不得伪称本轮已完成。
```
