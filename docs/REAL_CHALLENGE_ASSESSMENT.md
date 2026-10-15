# 公开电子取证真题流程评估（2026-10-15）

结论：当前 Agent 能运行部分基础取证工具，但不能认为已经具备独立完成综合电子取证真题的能力。本轮两道实际网络真题均未形成答案。已有 131 项回归通过说明既定边界的回归状态，不代表真题解题成功率。

## 来源与评估口径

优先使用出题方原文；国内题目来自具名参赛者的原始复盘，明确不视为官方标准答案。只根据题目所需流程评估，不把题解答案灌入模型。不重新跑相同题目筛选成功。人工接口调用、独立校验和自然语言模型自动解题分别记录。

- [Honeynet Forensic Challenge 2010 第1组](https://www.honeynet.org/challenges/forensic-challenge-1-pcap-attack-trace/)：官方题目，包含通信 IP、TCP 会话数、攻击时长、漏洞与 shellcode 分析。
- [美亚杯 2024 个人赛原始复盘](https://www.cnblogs.com/Joyooo/p/19382335)：手机、内存、E01 与 NTFS 等题目；参赛者记录，未取得原比赛检材，不使用其中答案作为实测结果。
- [数证杯 2024 决赛个人赛原始复盘](https://www.cnblogs.com/zzpu213/p/18692389)：计算机、手机、服务器等题目；参赛者记录，未取得原比赛检材。
- [Magnet Virtual Summit 2024 官方题目](https://www.magnetforensics.com/blog/2024-magnet-virtual-summit-ctf-winners-and-another-chance-to-play/)：iOS、Android 与编码/隐写；官方提供 iOS 16 全文件系统和 Android 12 数据集链接。本轮未取得可验证的相关图片或整套手机检材。
- [DFRWS 2021 官方挑战](https://dfrws.org/dfrws-2021-challenge/)：SD 卡、树莓派、手机、QNAP 三盘及多源关联；官方明确 RAID 可能需要重建。本轮只评估流程，没有下载整套大镜像。

检索使用 agent-reach 方法；Exa 后端未配置、gh CLI 不可用，使用现有网页搜索及可用 HTTPS 获取公开数据。未为本轮修改工具或模型配置。

## 真检材实测

官方 Honeynet 老下载站发生 TLS 错误，现代站对应路径返回 404。使用 [公开解题仓库中保存的 PCAP](https://github.com/cloudjunky/honeynet-attack-challenge/blob/master/attack-trace.pcap)。这是第三方保存副本，不能声称已用官方压缩包 SHA1 完成认证：官方公布的是 gzip 文件摘要，本轮只有解压后的 PCAP。

- 文件大小：189,103 字节；SHA256 `1a524565df030328987ccbcf804e9e472c891a4e482be5114d4f1d9d5937cedf`。
- 独立固定参数 TShark 全量校验：348 包，IP 为 `98.114.205.102`、`192.150.11.111`，5 个 TCP stream（编号0..4），首尾包间隔约16.219218秒。该校验只是评估基准，未提供给模型，不能算 Agent 新增统计能力。
- 现有人工接口 `pcap overview limit=1000`：状态 ok，349条证据（1条摘要+348条帧），完整性问题0。摘要仅包含包数与协议数量，没有完整 IP 集合、TCP 会话计数或时长字段。
- 本机既有 `qwen3.5:4b`，配置 max_steps=8、num_ctx=4096；使用实际 `.venv-offline` 包。每题只调用一次 analyze，内部正常重试和所有响应保留。

| 题目 | 首次实际结果 | 流程与定位 |
|---|---|---|
| Honeynet Q1：通信涉及哪些IP | stopped_duplicate；答案为空，约24.829秒 | 两次pcap overview（省略limit/显式limit=200），均partial且201条证据；随后重复请求被拦截。两个IP其实已出现在模型收到的observations中，故失败不能归因于TShark不能解析IP。案件 `E:/ForensicWork/20261015T153044Z-b606f0ae` |
| Honeynet Q3：TCP会话数量 | stopped_duplicate；答案为空，约9.140秒 | 同样重复概览，未形成完整会话数量证据。现有摘要没有distinct tcp.stream聚合，局部帧编号不能充当会话总数。案件 `E:/ForensicWork/20261015T153109Z-4c2489ac` |

原件 SHA256 未变化，案件完整性复核均无问题。只运行了这两道真实题，不能据此估算整套比赛成功率。禁止把独立 TShark 的正确结果算成模型答对。

证据与评估脚本保存在本地 `C:/Users/26822/.agent-reach/forensic-benchmark-20261015/`：`acquisition.json`、`reference.json`、`reference.stdout`、`adapter-check.json`、`honeynet-q1.json`、`honeynet-q3.json`、`model-results.json`、`fetch.py`、`evaluate.py`。案件、下载检材和原始输出不提交远端。

其他获取失败：Magnet nicedog 官方 Drive 链接404；picoCTF cat.jpg 官方旧主机TLS错误，未取得样本。没有用自建图片替代它们冒充真题实测。

## 对应流程与当前缺口

| 真题流程 | 当前可用环节 | 无法完成或尚未验证的环节 |
|---|---|---|
| 美亚2024 Emma Q1：聊天附件关联照片定位 | 已导出SQLite可查看结构/按单字段筛选；图片可提取GPS元数据 | 微信消息结构、照片库跨表/跨文件关联、手机导出与应用路径语义没有专用适配器；未用原检材验收 |
| 美亚2024 Emma Q2：指定时间之后给某联系人打电话的次数 | SQLite单表计数模板 | 模板只有一个字段的 IS ? 筛选，不能直接表达时间范围加联系人组合条件；缺少Cocoa时间规范化及可引用的条件聚合。人工自由SQL为exploratory，不能冒充模型证据 |
| 美亚2024 内存Q59/Q60：进程识别、导出后SHA256 | 普通已登记文件可算SHA256；Volatility独立安装 | 无内存适配器、插件约束和导出物登记链，不能自动从RAW导出进程再核验；真实内存未验收 |
| 美亚2024 U盘Q63/Q65/Q66：E01文件系统、删除文件、Run List | TSK/Autopsy独立安装；普通导出文件可登记 | 无E01/分区/文件系统/删除项/MFT数据运行解析的Agent接口。先前合成FAT12测试不证明能完成此真题 |
| 数证2024 计算机Q2/Q10：RDP来源及登录失败时序统计 | 人工导出EVTX后可用evtx/evtxecmd筛选事件 | 从镜像发现/导出正确日志、按用户排序关联与有来源的时间窗口统计未形成完整流程 |
| 数证2024 计算机Q4/Q6：分区/邮件附件MD5 | 已登记文件可计算SHA256 | hash适配器没有MD5；VHD加载、邮件容器与附件导出也无适配器。不能把SHA256当作题目要求的MD5 |
| Magnet2024：系统构建号、设备属性、应用记录、删除消息 | 导出文本/数据库/照片可进行部分基础查询 | 二进制plist、系统与App专用解释、删除数据恢复和完整手机分析未接入。ALEAPP/iLEAPP已安装不代表可自动调用 |
| Honeynet：SMB漏洞、shellcode与攻击链重建 | PCAP现有帧号/IP/tcp.stream及DNS/HTTP/TLS有限字段 | 缺SMB/RPC细节字段、端口/完整会话摘要、流重组、对象/载荷导出和shellcode分析；未实测后续题 |
| DFRWS2021：QNAP三盘与跨设备关联 | 通用登记、SHA256、报告 | RAID重建、NAS文件系统和统一多源时间线不在适配器内；不能自动完成 |

还存在规模边界：默认副本上限10GiB、文件数10,000、压缩单成员512MiB、工具内存2GiB；模型只看到有限来源/记录预览。遇到大镜像、手机备份或大量记录，需要独立的资源规划、分批检索与分页设计，不能直接取消partial标记。

## 建议实施顺序

1. 先将当前两道PCAP题固定为真实验收集：摘要产生完整可引用IP集合和会话统计，规范化默认参数后的重复检测，给有限纠错反馈；不能提高预算无限重试。Q1/Q3须在不提供答案的情况下输出正确引用。
2. 受控增加SQLite时间范围、多条件、必要关联与聚合/时间转换，记录真实SQL、绑定值、原始行和派生定位；仍拒绝模型自由SQL。
3. 接入TSK/E01和现有RECmd/MFTECmd/PECmd，补齐分区到文件/注册表/执行痕迹的来源链。然后处理Volatility离线符号与受控导出、ALEAPP/iLEAPP输出解析及应用时间语义。
4. 根据国内题集加入MD5、二进制plist、回收站、邮件容器等明确需求；OCR、隐写、解密和RAID作为独立范围，不通过任意Shell接口兜底。

本轮仅评估，没有修改生产代码、开放白名单或接入新能力。
