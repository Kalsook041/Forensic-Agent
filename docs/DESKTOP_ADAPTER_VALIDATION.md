# 指定取证软件适配与清理记录（2026-10-18）

基线 `31bf36d`。本轮为六个指定入口补能力，同时保留原有工作区手机/磁盘适配器与新 UI，发布包只选择本轮改动。

## 能力与使用

| 入口 | 本轮可用范围 | 约束 |
|---|---|---|
| pecmd | 单个 Prefetch 文件导出 CSV、字面关键词筛选 | 接受 MAM/SCCA 文件头；无 VSS、目录遍历、自由参数 |
| mftecmd | 单个已导出 `$MFT` 的 CSV | 本版仅 FILE 头，不处理 `$J`、`$Boot`、整个镜像或文件恢复 |
| recmd | 单个 clean 注册表 hive 的 BasicSystemInfo 固定批次 | dirty hive 拒绝；无任意批次/键路径/正则/sync；未覆盖全部注册表问题 |
| sqlecmd | 单个关闭且 checkpoint 的 SQLite，按已安装 Maps 导出 CSV | 无任意 SQL/下载/映射路径，禁 blob 导出；映射可能转换时区，需核对保存映射 |
| autopsy | 已关闭且 checkpoint 的 `autopsy.db`：files/attributes 只读查询 | 不自动运行 Autopsy GUI、建案、ingest、原始镜像解析；不重验人工导出来源链 |
| veracrypt | 已确认格式容器的人工只读打开步骤 | 返回 blocked/exploratory；不执行挂载、不读取或记录密码，不算解密结果或答案 |

默认模型模式会收到上述能力说明；显式工具名也有规则路由。已有工作副本中的具体文件应选文件来源 ID；目录中多个文件会拒绝。PECmd 等筛选参数只参与 Python 字面量筛选，不进入外部命令。limit 默认为 200，最多 1000，超过后保留 partial。

Autopsy：先人工建案和导入镜像，完成需要的 ingest，关闭软件并导出 checkpoint 后的独立数据库，再交回 Agent。自动 ingest 依赖模块及报告配置，本轮未将其作为已支持自动能力。[官方 CLI 说明](https://www.sleuthkit.org/autopsy/docs/user-docs/4.23.0/command_line_ingest_page.html)。

关闭软件后数据库仍可能保持WAL模式，应通过SQLite备份接口或数据库工具生成独立副本，并确认副本journal_mode为DELETE；不要删除-wal或事务日志来绕过检查。

VeraCrypt：仅确认格式后，选择工作副本，在 Mount Options 勾选 Mount volume as read-only；凭据仅在软件界面输入。导出相关文件，记录容器摘要、内部路径、导出摘要、版本与时间，然后卸载挂载卷。不要将未知高熵文件视作已确认的 VeraCrypt 容器。[官方 Windows 参数文档](https://veracrypt.io/en/Command%20Line%20Usage%20for%20Windows.html)。

四个 EZTools 使用本机 `-h` 核对参数；RECmd 固定批次、SQLECmd Maps 在执行前复制到步骤目录，保存来源及摘要，和全部导出文件一同加入 output_hashes。没有生成 CSV 时返回 unsupported，不宣称完整 0。日志出现错误词时返回 partial；这是保守判定，需复核原始日志。

## 清理状态

用户已明确授权删除 D 盘 iLEAPP、弘连取证桌面和安装包。实际执行卸载与删除的工具调用被自动审批拒绝，理由仅为 `blocked by policy`，没有给出更具体原因；未改换删除方法绕过。**没有卸载或删除成功。**

- D 盘 `D:\iLEAPP` 仍在；E 盘 `E:\Forensics\iLEAPP\2026.4.4` 保留，Agent 配置原本已指向 E 盘。
- 弘连安装包 `D:\取证\downloads\火眼\ForensicDesktop_2.7.1.3561_x86_64.exe` 仍在。
- 卸载注册表及所检查的常见目录未找到已安装的弘连取证桌面；不能据此保证整机不存在便携副本。
- 本轮没有删除案件、镜像、样本或旧下载说明。

## 验证和首次失败

本地证据在 `local-state/adapter-refresh-20261018/`（首版）、`local-state/adapter-refresh-20261018-v2/`（兼容修复版）、`local-state/adapter-refresh-20261018-v3/`（最终规范化打包），不提交案件/样本。

- 首源码定向 13 通过；首次 Ruff 有未使用 import 和同一行多语句，已修。
- 扩展源码定向 42 通过、2 失败：`-I` worker 使用旧安装，不认识新增 autopsy/veracrypt 配置字段。保留 `targeted.xml`；更新安装后最终本机同组 44 通过，10.12 秒。
- 第一版冻结发布真实验收六入口均失败，原因为 Context 的 input_root 仅存在于本机额外开发改动中。修复为兼容旧 Context，首版 `real-tools.json` 不覆盖。
- 第二版发布安装全套首次完整运行：310通过、1权限跳过、0失败，380.00秒，v2 `release-full.xml`。
- 最终第三版发布安装全套首次完整运行：312通过、1权限跳过、0失败，328.74秒，v3 `release-full.xml`。跳过为Windows符号链接权限测试；此结果不替代真实比赛、Autopsy ingest或VeraCrypt挂载验收。
- 最终双包分别验证源码/wheel/安装的 39/41 项资源相等、27 项摘要锁及 pip check；最终提交暂存区另行核对。
- 全套启动后另增加旧Context兼容与RECmd固定批次快照两项回归，最终本机定向46通过，8.64秒；全套记录保持其启动时收集的测试集，不将新增两项混写成全套覆盖。

第三版修复发布组装的换行格式，运行源码AST逐文件与第二版相同；本机包同时重新冻结其他工作留下的当前UI。第二版一致性检查曾因本机app.css已变化失败，原记录保留。最终第三版发布/本机源码、wheel、安装与暂存区分别核对39/41项资源及27锁通过。config/local-tools.json以LF重新序列化，仅修改本轮六入口字段，未夹带本机其他工具条目变更。

最终发布 wheel SHA256：`989d70dd25a7293313880ee6a9a99a68517a919d30f8f35ab695e956c238d29d`；本机 wheel SHA256：`a717a6518ed4623522a6d080d667e4eb9832a58688f9110f39dc43408d960f6d`。本机包含此前额外适配器和 UI，两套分别对应自己的源码，不能混用摘要锁。最终本机安装定向46通过、14.03秒；Node客户端19通过；Ruff及暂存区diff检查通过。

在确认原工作台无活动任务后于57727刷新，保持8192上下文和64GiB配额、未启动分析，旧失败案件摘要不变。认证bootstrap确认六入口已进入本机目录；这只证明入口可见，不能替代上表各项实际能力验收。配置继续指向E盘iLEAPP，D盘删除仍被拒绝。

第二版非 editable 发布安装真实 worker 首次运行，见 `real-tools.json`：

| 验证 | 结果 |
|---|---|
| PECmd + 作者 Prefetch 仓库 Win10 CALC 样本 | ok，3 行，完整性通过，7 项输出摘要 |
| MFTECmd + 作者 MFT 仓库 Generated `$MFT` | partial，5 行上限，完整性通过，6 项输出摘要 |
| RECmd + python-registry UNICODE_TESTS hive | unsupported，无批次匹配 CSV；未验证正向系统信息解析 |
| SQLECmd + 合成 Android Calllog.db | partial，1 条通话记录，日志含错误提示，100 项输出摘要；不能当完整解析通过 |
| Autopsy + 合成案件 schema 数据库 | ok，1 条文件记录；不是实际 Autopsy ingest 生成的案件验收 |
| VeraCrypt + 合成调用 | blocked，1 条 exploratory 指引，未挂载/解密 |

公共样本来自 [Prefetch](https://github.com/EricZimmerman/Prefetch)、[MFT](https://github.com/EricZimmerman/MFT)、[python-registry](https://github.com/williballenthin/python-registry)，仅保存在本地验证目录。GitHub contents API 403 和 Registry 归档截断 BadZip 的取样失败保留，不把失败下载当工具失败或正向解析证据。

## 限制与历史问题

未验证：RECmd 正向系统 hive、真实 Autopsy 案件和 ingest、VeraCrypt 实际凭据/挂载/卸载、真实 48GiB 比赛题、所有 Windows 版本、实机断网。Autopsy 和 VeraCrypt 的能力边界是上表所述，不能称六款软件全功能自动化。

先前 PCAP 原题、类型、进程时序及中止全套的两项失败，按原文档保留；旧新题四项复审问题也未在本轮修复。最终本轮测试通过不能覆盖那些历史记录。工作区此前的手机/磁盘适配器及 UI 样式不夹带发布提交。

本轮聚焦代码核对没有新增且已复现、尚未处理的适配可操作发现。清理被拒绝与未验范围仍按本文明确保留，不能把它们描述为已完成。

## 复审提示词

复审本轮六入口适配。范围 tools/{windows_artifacts,desktop,params,registry,runner}.py、settings.py、doctor.py、manual.py、agent/loop.py、六份knowledge文档、test_windows_adapters.py、默认路径配置、离线wheel/锁及本文。验收：固定单文件参数、字面筛选不进入argv、无sync/VSS/任意SQL/映射路径；支持文件快照和全部输出有摘要，改变后完整性拒绝；dirty hive/WAL/日志/非格式拒绝；达到限制和工具日志错误保留partial，无CSV不当完整0；Autopsy只读真实表、拒绝视图/自由SQL且保留类型；VeraCrypt不挂载不收凭据，blocked/exploratory不能成为答案；旧Context兼容且worker安装一致；模型仍严格来源/字段/类型/原值校验，纠正预算及首次日志不变；发布/本机各自匹配，不夹旧脏改。核对首次失败、正向未验范围和清理被拒绝记录。仅输出可操作P1/P2/P3、准确行号、复现、影响、最小验收；无发现明确说明并列未验证范围。

## 修复提示词

按复审已复现可操作发现修复，不放宽工具参数/路径/只读/来源边界，不开放Shell、收集密码或把人工指引当答案。无新复现保持代码不变。清理操作已被自动审批拒绝，不改换工具或命令绕过；向操作者明确待处理路径。必要定向验证，保留两版首次失败和历史失败，更新包/锁及本文；每个已验证批次提交推送origin/main，不上传案件/公共样本/本地证据。
