# PCAP 与规划流程优化（2026-10-16）

后续复审发现VLAN内层IP缺失、AH后TCP缺失的完整0误报，以及全文件题验收未核对scope共三项P2，现已修复。完整回归204通过/1跳过及原题环境恢复后授权补验的完整记录见 [三项P2修复验证](PCAP_REPAIR_VALIDATION.md)。下文保留最初三版实现与原题记录，历史“最终”仅指当时第三版；最新复审/修复提示词以新文档为准。

## 目标与范围

修复公开真题评估中“能读取但反复调用概览、无法形成答案”的缺口。本轮仅优化现有 PCAP 适配器、有限规划循环和必要验收；没有新增任意 Shell、自由 TShark filter、模型自由 SQL 或手机/内存/磁盘镜像适配器。

## 实现

- PCAP overview 首条证据提供全匹配输出的 IP 集合/数量、distinct TCP 会话数、TCP/UDP 端口、精确时间范围。使用 derived 分类并记录聚合依据与筛选 scope，不能把局部明细当作全局统计。
- 新增受控 `ip_address`、`tcp_stream` 交集筛选及 `offset` 分页。IP 必须是规范 IPv4/IPv6 字面量，拒绝接口 scope ID 和表达式；原 `protocol` 枚举不变。
- 明细分页继续标记 partial/truncated，`has_more`、`next_offset` 指明下一页；末页省略了前页也不会冒充完整明细。IP 名单最多1000项，另有完整性标志。
- 请求通过参数模型填充默认值后比较；省略参数与显式默认值不会导致工具再执行。整次调查最多允许一次重复决策纠正，有独立响应/失败日志，仍重复就停止。
- finish 保持当前来源完整性、grounding、字段、原值及 JSON 类型校验。一次规划纠正与已有一次引用纠正分别有界，不靠工具步骤数计算重试额度。
- PCAP overview 的模型预览保留完整摘要和首帧，减少相似帧占用上下文；`record_count`、`preview_incomplete` 仍明示省略，完整证据留在案件中。没有提高 `num_ctx=4096`、`num_predict=1536` 或重试预算。
- 采集长度和网络/传输头完整性分别核对。头部缺失时完整计数为 null，并提供 observed 计数和独立完整性标记；只有载荷截断时可保留完整头部支持的统计，但结果仍为 partial。
- `.venv-offline` 与离线 wheel/摘要锁同步，运行依赖、工具白名单和资源限制保持。

固定字段及显示筛选依据为 [TShark 官方手册](https://www.wireshark.org/docs/man-pages/tshark.html) 和 [TCP 字段参考](https://www.wireshark.org/docs/dfref/t/tcp.html)。未加入新依赖。

## 验证与复审过程

第一版定向回归：规划/引用/原边界35项通过；PCAP工作流与原DNS/HTTP共24项通过。第一版完整回归162 passed / 1 skipped，143.14秒，记录 `local-state/optimization-full-v1.xml`。跳过项是 Windows 符号链接创建权限。

第一版实际离线环境对原Q1/Q3提示各调用一次 analyze，均 completed。Q1正确引用完整IP列表；Q3首次将数值5写成字符串，严格校验拒绝后，经一次 claim-repair 改成数值5才接受。原失败与纠正响应分别保留。记录 `local-state/pcap-workflow-checks/20261016T021214530795Z/results.json`，案件 `E:/ForensicWork/20261016T021216Z-9fec9618` 和 `E:/ForensicWork/20261016T021242Z-cb5e8d24`。没有重新运行相同实现来筛选成功。

独立PCAP边界复审复现P2：合法snaplen截断到IPv4头后，TShark正常退出而未生成TCP stream，第一版误报完整0会话。修复前证据在 `local-state/pcap-boundary-review-20261016T101259/result.json`。现已修复；同一原始单帧检材经独立真实 run_tool 复核，返回 partial/truncated、tcp_session_count=null、observed_tcp_session_count=0、tcp_statistics_complete=false；完整IPv4头仍支持两个IP地址。复核记录 `local-state/pcap-boundary-review-20261016T101259/recheck-result.json`。另补Ethernet/IP/TCP头缺失、载荷截断、TCP非首片和IPv6扩展头缺失共8个真实TShark边界用例。

第二版完整回归169 passed / 1 skipped，151.50秒，记录 `local-state/optimization-full-v2.xml`。本次运行期间最后补充了IPv6扩展头缺失边界，故仍以第三版完整回归作为最终验收。

第二版实际离线环境对Q1/Q3各一次analyze均失败，记录 `local-state/pcap-workflow-checks/20261016T022111555873Z/results.json`，案件分别为 `E:/ForensicWork/20261016T022113Z-bbae6998`、`E:/ForensicWork/20261016T022136Z-88caa6fb`。两题工具统计均正确；Q1首次响应 prompt_eval_count=4089/4096、eval_count=7、done_reason=length，随后仍重复请求；Q3重新决策及引用纠正将实际true/5写成false/null，被严格拒绝。结合请求大小及后续prompt token数显著减少，判断存在上下文不足及服务裁剪。没有把失败归因于检材或放松引用校验。

据此第三版减少overview帧预览；[Ollama上下文说明](https://docs.ollama.com/context-length)及[chat API统计字段](https://docs.ollama.com/api/chat)用于解释上下文容量和实际token计数。此改动后的实际首次完整运行结果如下，未向模型提供独立参考值：

| 题目 | 最终结果 | 有界纠正与原始记录 |
|---|---|---|
| Q1：实际通信IP | completed；98.114.205.102、192.150.11.111；25.047秒 | 一次重复决策纠正，工具仅执行一次；正常/纠正提示分别2697/2824 token。案件 `E:/ForensicWork/20261016T022727Z-54fffd50` |
| Q3：整个文件TCP会话数 | completed；数值5；9.671秒 | 首次将5及true写成字符串，被严格拒绝；一次claim-repair后原类型值通过，工具仅执行一次。正常/纠正提示分别2705/2826 token。案件 `E:/ForensicWork/20261016T022752Z-5773647e` |

第三版记录 `local-state/pcap-workflow-checks/20261016T022725241647Z/results.json`：人工适配器检查、报告复核后答案、来源完整性及独立参考比较均通过；每题仅一次analyze。第一/二/三版全部原始响应、纠正及失败均保留，不合并成“首次无错误”。

第三版定向回归74 passed，81.84秒，记录 `local-state/optimization-final-targeted.xml`。最终完整回归171 passed / 1 skipped / 0 failed，160.94秒，记录 `local-state/optimization-full-final.xml`。唯一跳过项是 `tests/test_gui.py:160`，本机无Windows符号链接创建权限。Ruff和差异空白检查通过。独立最终只读复审未发现新增可复现P1/P2/P3；其未代替实际模型、安装包一致性与全套验证。

最终wheel SHA256 `5d0bc01b4ae9ce184fdbcb3ddd55414be53803b82d4920120c009323544406f1`，75,705字节。已同步离线摘要/requirements锁并重装`.venv-offline`，pip check通过；27个wheel摘要全部一致，30个Python模块在源码、wheel及本机安装之间逐字节一致，记录 `local-state/optimization-package-final.json`。旧版本失败记录与先前119 passed / 2 failed / 1 skipped的历史回归记录保持，不用本轮通过覆盖。

## 实测材料与限制

使用既有Honeynet公开保存副本：189,103字节、SHA256 `1a524565df030328987ccbcf804e9e472c891a4e482be5114d4f1d9d5937cedf`。来源和官方gzip摘要未认证的限制保持 [原评估说明](REAL_CHALLENGE_ASSESSMENT.md)。独立完整TShark参考统计不注入模型，题目没有预置答案。下载检材、案件、原始输出和模型响应仅保留本地。

可运行 `scripts/verify-pcap-workflow.py --sample <PCAP绝对路径>`，使用项目Python。每次生成独立结果目录，每题仅一次analyze；内置有界纠正全部保留。它检查报告复核后的最终答案及完整性，与独立全量参考比较。

仍未验证大规模或复杂协议的全部题目、多源多步上下文极限、完整手机/内存/磁盘镜像流程或物理断网冷启动；本轮没有实现TCP载荷重组/对象导出、TLS解密、SMB漏洞或shellcode分析。统计基于实际捕获与本次筛选范围，不保证覆盖未捕获网络活动。单次工具、上下文、文件规模和结果上限保持既有设置。两道题成功不能推出整场比赛成功率。

## 复审提示词

```text
复审PCAP与规划流程优化，范围 src/forensic_agent/tools/{structured,params,registry}.py、agent/loop.py、knowledge/pcap.md、tests/test_pcap_workflow.py、tests/test_decision_repair.py、scripts/verify-pcap-workflow.py、离线wheel/锁及本验证文档。验收：IP/会话统计来自完整匹配输出并有来源；筛选scope不能扩成全文件；分页/名单上限保留partial；采集截断、分片、IPv6扩展头缺失导致无法确定数量时不能声称完整0；固定参数拒绝注入；overview压缩预览保留摘要、真实省略标记和完整案件证据；等价默认请求不重复执行；整次最多一次规划纠正、一次引用纠正且日志不覆盖；来源变化/探索性/字段类型值不符仍拒绝；安装包与源码一致。核对最终回归及各版原题首次完整运行记录，保留第二版两题失败与首次类型错误，不能将局部检查描述为全套通过。仅输出可操作发现：P1/P2/P3、文件行号、复现、实际影响、最小修复验收；无发现明确说明，列出未验证范围。
```

## 修复提示词

```text
本轮已复现的snaplen截断完整0误报和PCAP概览上下文溢出已修复，最终只读复审无新增可操作发现。无新复现时保持代码不变。若有新发现，仅修复PCAP统计/分页/筛选、规划有界恢复及相关证据完整性；保留partial、严格字段和值校验、固定参数与资源限制，不开放任意Shell/filter/SQL，不提高预算无限重试。保留每版所有模型结果和失败记录，先诊断再改版本，不靠重跑筛选成功；实施必要定向验证及修改后的原题验收，核对报告最终状态，更新离线wheel/锁及文档，每个已验证修改批次推送origin/main，案件和检材不上传。
```
