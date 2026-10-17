# 人工操作指南：实施与验证

## 目标与范围

当分析失败、停止或工具结果不完整时，报告和本机工作台提供按保存状态选择的人工接续步骤，说明工具、操作、应导出的文件及复核条件。通用版本见 [MANUAL_GUIDE.md](MANUAL_GUIDE.md)。指南是确定性模板，不依赖模型响应，也不运行工具、挂载镜像或删除文件。

范围：`src/forensic_agent/manual.py`、`evidence/store.py`、`reports/writer.py`、`gui.py`、`web/{app.js,index.html,app.css}`；`tests/test_manual_guidance.py`、`tests/test_gui.py`、`tests/gui-client.test.mjs`；本文、通用指南和离线 wheel/摘要锁。

## 行为与验收

- 失败或 partial 的报告附人工指南，并尝试保存独立 `manual-guide.md`；`report.json` 保留结构化 `manual_guidance`。辅助文件写入失败不能覆盖原错误或阻止主报告。
- 工作台提供通用入口。失败任务自动显示案件指南；报告缺失仍可从案件记录生成。案件指南读取失败可显示通用步骤，原任务错误保留。
- 副本登记前保留输入路径及计划文件数/字节数；容量或空间预检的失败仍不复制文件。既有案件缺少新字段可读取。
- 覆盖容量/空间、分卷与未知容器、Windows 计算机名、PCAP/TLS、SQLite、内存、手机、恢复、模型停止及完整性问题。未知格式不凭高熵断定加密工具；无密码或密钥不承诺解密；没有现场内存不虚构内存镜像。
- 工具入口检测只表示文件存在，不表示已能解析本题。人工导出链需操作者记录与复核；人工笔记、指南、截图不直接成为已通过引用校验的答案。
- 不改变状态、候选答案、首次失败日志、整次规划/引用纠正预算、证据校验、资源限制或工具白名单；不开放 Shell。
- 新 API 复用本机服务认证、来源校验和案件路径限制。恶意路径只按文本显示；并发请求不能让旧指南覆盖新指南。
- 发布源码、离线 wheel、锁和安装包逐文件一致；保留工作区其他未提交功能。

## 验证记录

初始定向验证：Python 26 passed / 1 skipped（Windows 符号链接权限）；页面脚本 8 passed。初始 JUnit：`local-state/manual-guidance-20261017/targeted-first.xml`。

复审覆盖正确性、测试、维护性、项目约束、安全、接口、可靠性、对抗输入、页面竞态、Agent 可访问性和既有经验，确认四项 P2，均已修复并作独立来源复核，无剩余已确认可操作发现：

| 问题 | 修复与验收 |
| --- | --- |
| 历史案件报告缺失只显示错误 | 报告请求失败仍读取案件指南；增加历史路径回归及真实页面检查 |
| 慢报告响应覆盖后来选择的通用指南 | 捕获指南请求代次并拒绝过时报告续接；增加延迟报告测试 |
| 裸 `.001` 未进入容器流程 | 数字卷号触发待确认流程，明确原始镜像分段不等于压缩包；验证 `.001`、`.002`、`.7z.001` |
| 根目录形式的错误 tshark 路径阻断全部指南 | 隔离 `with_name` 路径转换错误，继续显示入口待准备；验证通用和 PCAP 两路径 |

数字卷号发现经另一审查者独立确认；其余按确定代码路径与回归验证。原审查结果保留在本机 `Temp/compound-engineering/ce-code-review/manual-guidance-20261017/`。新增分类/坏路径测试先记录 **3 failed**（`review-before-fix.xml`），修复后指南模块 **15 passed**（`review-fixed.xml`）。页面脚本最终 **10 passed**。首次诊断/一次性规划纠正/引用纠正/PCAP 等受影响回归 **90 passed / 1 skipped**（`targeted-final.xml`）；这些检查有重叠，不能相加成独立测试数，也不代表整个本机工作树全套通过。

真实 Chrome 页面用 7 字节合成输入和 1 字节配额触发登记失败，验证自动指南、下载、实际缺失报告、重启视角下的历史入口、根因保留、通用指南、记录不变、390px 宽度、无页面异常及路径越界拒绝，11 项检查通过（`browser/result.json`、截图）。初次浏览器启动缺少 Playwright 附带浏览器，未进入页面/分析；改用本机已安装 Chrome 后验证，不下载浏览器。

现有工作台空闲时重启到新接口，仍使用 64 GiB 案件配置；已有空间不足案件可读取指南，`case.json` 内容摘要前后相同，未重跑分析或复制大检材（`live-gui-result.json`）。

离线发布与本机工作区分别打包，保留其他尚未提交的适配器：

| 对象 | SHA-256 | 文件核对 |
| --- | --- | --- |
| 已发布基线加本轮改动的 wheel | `f556ba7891cf73ae8517730739eb4f7e97314abb89508ab7419429d9a5e7af6e` | 34 个 Python/界面资源与发布源码、隔离安装一致 |
| 包含既有未提交功能的本机 wheel | `b949a6d01c604af1fc3aa04539b5daabb2f5230430a6db22ee3fd34bf273521f` | 36 个资源与实际工作树、当前安装一致 |

两套各 27 个 wheel 摘要、对应锁与实际文件一致，`pip check` 均通过。发布时暂存独立发布包及锁，本机包和未提交功能保留。首次打包校验脚本误用隔离解释器的控制台编码解读中文安装路径，逐文件检查因此中断；改用 ASCII JSON 传输路径后完成校验，未据此更改产品代码。记录为 `packages.json`、`final-package-consistency.json` 与 `package-commands.log`。

基于 `9713e69` 加本轮改动的独立发布源码/安装环境，完整回归一次执行：**225 passed / 1 skipped / 0 failed，447.37 秒**（`release-full.xml`）。跳过项为 `tests/test_gui.py:192`，Windows 符号链接创建权限不足。Ruff 和本轮暂存差异空白检查通过。本机含其他未提交功能的整个工作树没有再跑全套；其受影响检查为上述 90 passed / 1 skipped，加最后修复后的指南 15 passed，与发布基线完整回归分开记录。

全套成功仅限本次发布回归；浏览器/CLI 使用合成小文件，不代表未知比赛容器已成功解析，也不覆盖历史模型原题验收的失败记录。

## 操作依据与限制

FTK Imager 菜单与导出按本机官方 8.3 用户手册核对；其余参考 [RECmd](https://github.com/EricZimmerman/RECmd)、[Wireshark Endpoints](https://www.wireshark.org/docs/wsug_html_chunked/ChStatEndpoints.html)、[Conversations](https://www.wireshark.org/docs/wsug_html_chunked/ChStatConversations.html)、[TLS](https://wiki.wireshark.org/TLS)、[SQLite Browser 只读参数](https://github.com/sqlitebrowser/sqlitebrowser/wiki/Command-line-interface)、[Volatility 3](https://volatility3.readthedocs.io/en/stable/getting-started-windows-tutorial.html)、[ALEAPP](https://github.com/abrignoni/ALEAPP)、[iLEAPP](https://github.com/abrignoni/iLEAPP)、[PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step)、[VeraCrypt 格式说明](https://veracrypt.io/en/VeraCrypt%20Volume%20Format%20Specification.html)。发布时应按实际安装版本确认菜单和支持格式。

本功能不等于这些人工软件已对比赛检材解析成功。不得据此宣称已打开未知容器、解密 TLS、恢复全部文件或得出计算机名。外部软件的实际 GUI 导入、解密、符号准备、手机解析和恢复需要真实对应材料，未包含在自动测试中。历史 PCAP 第二版两题失败与首次类型错误继续保留；进程时序测试的早期两项失败及后续修复分别见 [PROCESS_TIMING_REPAIR.md](PROCESS_TIMING_REPAIR.md)，不能把历史失败误称为仍未修复，也不能用后续成功覆盖原记录。

## 复审提示词

```text
复审失败后的人工操作指南。范围：src/forensic_agent/manual.py、evidence/store.py、reports/writer.py、gui.py、web/{app.js,index.html,app.css}、tests/test_manual_guidance.py、tests/test_gui.py、tests/gui-client.test.mjs、docs/MANUAL_GUIDE.md、本文及离线wheel/锁。验收：失败/停止/partial有对应工具与可执行的人工步骤；空间与配额分开、分卷只从首卷处理、未知格式不猜加密工具或密码；人工输出需来源记录，不成为自动验证答案；来源变化先处理完整性；模型不可用及报告缺失仍可读指南；指南不得执行工具或改变状态/答案/首次日志/一次性纠正预算/白名单；辅助写入和读取失败保留原错误；API认证/来源/路径越界拒绝，恶意文本及异步响应安全；安装包与发布源码一致。核对最终验证和历史失败，不把局部检查或指南展示描述为比赛解题/全套通过。仅输出可操作发现：P1/P2/P3、准确文件行号、复现、实际影响、修复验收。无发现明确说明，并列出未验证范围。
```

## 修复提示词

```text
本次四项P2已修复并复核，无剩余已确认可操作发现；无新复现时保持代码不变。后续只按新复审的可操作发现修复人工操作指南，保留严格证据校验、规划与引用各一次纠正预算、原失败状态及首次日志，不扩大工具白名单或开放Shell。必要修改先保留复现，做定向验证与相关回归，记录失败与未验证范围；更新通用指南、离线wheel/锁及本文，每个已验证批次提交并推送origin/main，不上传案件和本地证据。
```
