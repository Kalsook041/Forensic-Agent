# 人工操作指南：实施与验证

## 目标与范围

当分析失败、停止或工具结果不完整时，报告和本机工作台提供按保存状态选择的人工接续步骤，说明工具、操作、应导出的文件及复核条件。通用版本见 [MANUAL_GUIDE.md](MANUAL_GUIDE.md)。指南是确定性模板，不依赖模型响应，也不运行工具、挂载镜像或删除文件。

范围：`src/forensic_agent/manual.py`、`evidence/store.py`、`reports/writer.py`、`gui.py`、`web/{app.js,index.html,app.css}`；`tests/test_manual_guidance.py`、`tests/test_gui.py`、`tests/gui-client.test.mjs`；本文、通用指南和离线 wheel/摘要锁。

## 行为与验收

- 失败或 partial 的报告附人工指南；先保存 `report.md` 和包含结构化 `manual_guidance` 的 `report.json`，再尽力保存独立 `manual-guide.md`。辅助文件失败的 `file_error` 回写同样尽力而为，不能覆盖原错误或阻止主报告。
- 工作台提供通用入口。失败任务自动显示案件指南；报告缺失仍可从案件记录生成。案件指南读取失败可显示通用步骤，原任务错误保留。
- 副本登记前保留输入路径及计划文件数/字节数；容量或空间预检的失败仍不复制文件。既有案件缺少新字段可读取。
- 覆盖容量/空间、分卷与未知容器、普通文本搜索、Windows 计算机名、PCAP/TLS、SQLite、内存、手机、恢复、模型停止及完整性问题。未知格式不凭高熵断定加密工具；无密码或密钥不承诺解密；没有现场内存不虚构内存镜像。
- 工具入口检测只表示文件存在，不表示已能解析本题。人工导出链需操作者记录与复核；人工笔记、指南、截图不直接成为已通过引用校验的答案。
- 不改变状态、候选答案、首次失败日志、整次规划/引用纠正预算、证据校验、资源限制或工具白名单；不开放 Shell。
- 新 API 复用本机服务认证、来源校验和案件路径限制。恶意路径只按文本显示；并发请求不能让旧指南覆盖新指南。
- 发布源码、离线 wheel、锁和安装包逐文件一致；保留工作区其他未提交功能。

## 验证记录

初始定向验证：Python 26 passed / 1 skipped（Windows 符号链接权限）；页面脚本 8 passed。初始 JUnit：`local-state/manual-guidance-20261017/targeted-first.xml`。

初版内部复审覆盖正确性、测试、维护性、项目约束、安全、接口、可靠性、对抗输入、页面竞态、Agent 可访问性和既有经验，确认以下四项 P2 并完成修复。当时的复核结论不替代后续复审；后续新增的四项问题另记于下方修复记录。

| 问题 | 修复与验收 |
| --- | --- |
| 历史案件报告缺失只显示错误 | 报告请求失败仍读取案件指南；增加历史路径回归及真实页面检查 |
| 慢报告响应覆盖后来选择的通用指南 | 捕获指南请求代次并拒绝过时报告续接；增加延迟报告测试 |
| 裸 `.001` 未进入容器流程 | 数字卷号触发待确认流程，明确原始镜像分段不等于压缩包；验证 `.001`、`.002`、`.7z.001` |
| 根目录形式的错误 tshark 路径阻断全部指南 | 隔离 `with_name` 路径转换错误，继续显示入口待准备；验证通用和 PCAP 两路径 |

数字卷号发现经另一审查者独立确认；其余按确定代码路径与回归验证。原审查结果保留在本机 `Temp/compound-engineering/ce-code-review/manual-guidance-20261017/`。新增分类/坏路径测试先记录 **3 failed**（`review-before-fix.xml`），修复后指南模块 **15 passed**（`review-fixed.xml`）。页面脚本最终 **10 passed**。首次诊断/一次性规划纠正/引用纠正/PCAP 等受影响回归 **90 passed / 1 skipped**（`targeted-final.xml`）；这些检查有重叠，不能相加成独立测试数，也不代表整个本机工作树全套通过。

真实 Chrome 页面用 7 字节合成输入和 1 字节配额触发登记失败，验证自动指南、下载、实际缺失报告、重启视角下的历史入口、根因保留、通用指南、记录不变、390px 宽度、无页面异常及路径越界拒绝，11 项检查通过（`browser/result.json`、截图）。初次浏览器启动缺少 Playwright 附带浏览器，未进入页面/分析；改用本机已安装 Chrome 后验证，不下载浏览器。

现有工作台空闲时重启到新接口，仍使用 64 GiB 案件配置；已有空间不足案件可读取指南，`case.json` 内容摘要前后相同，未重跑分析或复制大检材（`live-gui-result.json`）。

初版离线发布与本机工作区分别打包，保留其他尚未提交的适配器（以下为历史包，本轮新包见后续记录）：

| 对象 | SHA-256 | 文件核对 |
| --- | --- | --- |
| 已发布基线加本轮改动的 wheel | `f556ba7891cf73ae8517730739eb4f7e97314abb89508ab7419429d9a5e7af6e` | 34 个 Python/界面资源与发布源码、隔离安装一致 |
| 包含既有未提交功能的本机 wheel | `b949a6d01c604af1fc3aa04539b5daabb2f5230430a6db22ee3fd34bf273521f` | 36 个资源与实际工作树、当前安装一致 |

两套各 27 个 wheel 摘要、对应锁与实际文件一致，`pip check` 均通过。发布时暂存独立发布包及锁，本机包和未提交功能保留。首次打包校验脚本误用隔离解释器的控制台编码解读中文安装路径，逐文件检查因此中断；改用 ASCII JSON 传输路径后完成校验，未据此更改产品代码。记录为 `packages.json`、`final-package-consistency.json` 与 `package-commands.log`。

初版基于 `9713e69` 的独立发布源码/安装环境，完整回归一次执行：**225 passed / 1 skipped / 0 failed，447.37 秒**（`release-full.xml`）。跳过项为 `tests/test_gui.py:192`，Windows 符号链接创建权限不足。Ruff 和本轮暂存差异空白检查通过。本机含其他未提交功能的整个工作树没有再跑全套；其受影响检查为上述 90 passed / 1 skipped，加最后修复后的指南 15 passed，与发布基线完整回归分开记录。

全套成功仅限本次发布回归；浏览器/CLI 使用合成小文件，不代表未知比赛容器已成功解析，也不覆盖历史模型原题验收的失败记录。

## 后续四项复审修复（基线 ebc8a03）

后续只读复审确认四项新的 P2，原审查与独立验证保存在本机 `Temp/compound-engineering/ce-code-review/manual-rereview-20261017T103648Z/`。修复记录位于 `local-state/manual-guidance-repair-20261017/`，不上传案件或本地证据。

| 问题 | 修复与验收 |
| --- | --- |
| 首次复制时源文件增长被误当作空间不足 | `manual.py` 对含源文件增长的混合诊断先给完整性步骤；真实 1 字节 PCAP 在复制时增长为 5 字节、尚未登记来源，报告仍保持原 `intake_failed` 和首个错误；真正空间不足继续走 storage |
| 等待旧指南后抛出的旧异常覆盖新报告 | `showReport` 在等待指南之后再次检查请求代次；覆盖切换历史 B 和启动新任务 B，两者的报告、按钮、指南、诊断保持对应 |
| 纯 TXT 搜索 partial 无对应工具与操作 | 增加仅人工使用的 PowerShell Select-String 流程，固定占位参数、字面路径/关键词、编码、大小写、行号、CSV 导出及范围记录；真实小 TXT 配 1 字节扫描上限产生 partial，保留步骤、限制、状态和答案 |
| 可选指南先占空间导致必要 JSON 失败 | 必要 Markdown/JSON 先保存；辅助指南及其错误信息更新尽力而为；覆盖空间仅够必要报告，以及辅助失败后附加 JSON 更新也失败的两种情况 |

先新增复现再修复：Python **4 failed / 1 passed**（真正空间不足的负对照通过，`python-before.xml`）；Node **10 passed / 2 failed**（`node-before.log`）。修复后受影响 Python **36 passed / 1 skipped**（`targeted-after.xml`，跳过仍为 Windows 符号链接权限），Node **12 passed**（`node-after.log`）。这些是定向结果，不能代替最终完整回归。

人工搜索命令只写入指南，不作为工具注册或自动执行。命令及单引号转义按 [Select-String 官方说明](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/select-string?view=powershell-5.1) 与 [Export-Csv 官方说明](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/export-csv?view=powershell-5.1) 核对。实际双 PowerShell 检查使用带空格、方括号、美元符号、单引号的文件名/关键词，验证 UTF-8、UTF-16LE、已有输出和缺少输入，源文件摘要不变。初次验证发现本机 Windows PowerShell 5.1 拒绝覆盖时退出码仍为 0，旧输出保持；记录 `search-command-first-failure.json`，随后增加显式存在性检查，不删除原断言。最终命令检查记录 `search-command-final/results.json`。

随后规划/引用纠正与 PCAP 的相关回归 **64 passed，65.03 秒**（`strict-regression.xml`）。双 PowerShell 最终 **8/8** 通过。Chrome 实际工具模式使用小 TXT 得到 partial，验证对应指南、完整命令下载、状态/步骤/答案保留及两种慢指南交错，**7 项通过**（`browser/result.json`、`partial-guide.png`）。首个浏览器检查因测试选择器匹配两个 summary 在启动分析前中断，改用直接子选择器后通过，见 `browser-first-failure.json`。

本轮代码改动集中且未变更 API 签名、依赖版本及生产边界，按 `ce-work` Tier 1 做调用处与修改内容的聚焦直接复核，确认四项已处理，无剩余已确认范围内发现（`focused-review.json`）。实际满盘未执行，文件空间边界使用可用字节配额模拟；没有运行比赛原题或模型验收，没有改变扫描上限、工具白名单、规划/引用纠正预算或原始失败记录。

最终发布源码以 `ebc8a03` 为基线，仅覆盖本轮文件；对应离线安装环境完整回归一次执行 **230 passed / 1 skipped / 0 failed，171.52 秒**（`release-full.xml`）。跳过仍为 `tests/test_gui.py:192` 的 Windows 符号链接权限。这是独立发布全套；本机带其他未提交功能的工作树只做上述受影响及相关回归，不冒充其全套结果。Ruff、差异空白检查通过。

| 最终包 | SHA-256 | 一致性 |
| --- | --- | --- |
| 本轮独立发布 wheel | `743f7892f7420c5ac52ce4b36b9a2d330421989b6c341291a92a331043f5d1f7` | 34 个源码/界面资源与发布源、隔离安装逐字节一致 |
| 保留其他未提交功能的本机 wheel | `d0ad87a60e4edb8cf2511d484f3244eb8762413db222125be28443156f3c37be` | 36 个资源与实际工作树、当前安装逐字节一致 |

两套各 27 个 wheel、摘要及锁逐项匹配，`pip check` 均通过（`packages.json`、`final-package-consistency.json`）。最后补充首次登记尚无摘要时的人工说明后重建以上最终包，早一轮包记录仍留在 `packages-initial.json`，不与最终验收混淆。

当前工作台在空闲时重启，继续使用原 64 GiB 配置，通用指南共 12 个方向并包含人工文本搜索；已有失败案件读取指南前后 `case.json` 摘要相同，未启动新分析（`live-gui-result.json`）。历史 PCAP 第二版失败、首次类型错误、初版发布记录及本轮修复前失败均保留，不用本轮通过覆盖。

## 操作依据与限制

FTK Imager 菜单与导出按本机官方 8.3 用户手册核对；其余参考 [RECmd](https://github.com/EricZimmerman/RECmd)、[Wireshark Endpoints](https://www.wireshark.org/docs/wsug_html_chunked/ChStatEndpoints.html)、[Conversations](https://www.wireshark.org/docs/wsug_html_chunked/ChStatConversations.html)、[TLS](https://wiki.wireshark.org/TLS)、[SQLite Browser 只读参数](https://github.com/sqlitebrowser/sqlitebrowser/wiki/Command-line-interface)、[Volatility 3](https://volatility3.readthedocs.io/en/stable/getting-started-windows-tutorial.html)、[ALEAPP](https://github.com/abrignoni/ALEAPP)、[iLEAPP](https://github.com/abrignoni/iLEAPP)、[PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step)、[VeraCrypt 格式说明](https://veracrypt.io/en/VeraCrypt%20Volume%20Format%20Specification.html)。发布时应按实际安装版本确认菜单和支持格式。

本功能不等于这些人工软件已对比赛检材解析成功。不得据此宣称已打开未知容器、解密 TLS、恢复全部文件或得出计算机名。外部软件的实际 GUI 导入、解密、符号准备、手机解析和恢复需要真实对应材料，未包含在自动测试中。历史 PCAP 第二版两题失败与首次类型错误继续保留；进程时序测试的早期两项失败及后续修复分别见 [PROCESS_TIMING_REPAIR.md](PROCESS_TIMING_REPAIR.md)，不能把历史失败误称为仍未修复，也不能用后续成功覆盖原记录。

## 复审提示词

```text
复审人工操作指南后续四项修复（基线ebc8a03）。范围：src/forensic_agent/manual.py、reports/writer.py、web/app.js、tests/test_manual_guidance.py、tests/gui-client.test.mjs、通用指南、本验证文档及离线wheel/锁；关联核对既有store.py/gui.py读写边界。验收：首次复制增长且无来源登记时完整性优先，真正空间不足仍给storage，原状态/首次错误不变；A失败报告等待慢指南后切换历史B或启动任务B，A返回不得覆盖B报告/诊断/按钮/指南；纯TXT search因扫描限额partial时有具体人工工具、只读搜索、编码/大小写/行号/范围、CSV导出和来源记录，保留partial；示例在双PowerShell正确处理空格/特殊字面路径与关键词、UTF8/UTF16、已有输出与缺源，不自动运行或进入白名单；必要MD/JSON先于辅助指南持久化，辅助文件和file_error回写失败不能阻断正常报告/首个错误。严格证据/规划引用各一次预算/资源限制不变，发布及本机包分别匹配对应源码与安装。核对初版225/1、本轮最终全套和定向记录、修复前4失败/Node2失败及命令/浏览器首次检查失败；保留PCAP第二版两题失败与类型错误，不能将局部检查、保存状态或指南展示描述为真实比赛/全套通过。仅输出可操作发现：P1/P2/P3、准确文件行号、复现、实际影响、修复验收；无发现明确说明，列出未验证范围。
```

## 修复提示词

```text
本轮后续四项P2（增长完整性分流、慢指南后过期异常、纯文本partial接续、辅助文件写入顺序）已修复并验证；没有新复现时保持代码不变。只修复新复审确认的可操作发现，保留严格证据校验、规划与引用各一次预算、原失败状态/首次日志、资源和白名单，不开放Agent Shell或自动执行人工命令。先保留复现，再做最小修改与定向/必要相关回归；近满盘用可控配额模型，不删除断言或放宽生产限制，不反复筛选通过。保持原失败/环境失败记录与最新结果范围分明。更新通用指南、离线wheel/锁及验证文档，发布包与本机未提交功能包分别匹配对应源码/安装；每个已验证批次提交推送origin/main，不夹带其他未提交工作，不上传案件和本地证据。
```
