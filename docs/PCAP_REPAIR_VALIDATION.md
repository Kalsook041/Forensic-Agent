# PCAP 复审三项 P2 修复验证（2026-10-16）

## 范围与行为

本轮处理 `b6cfa7c` 之后只读复审发现的三项 P2。修改 PCAP 完整性判定、真实回归、验收脚本及其判定测试，保留原规划与引用循环。没有新增适配器、自由 Shell/filter/SQL、运行依赖或资源/重试额度。

1. VLAN 内层 IP 缺失：固定字段增加 `vlan.etype`，内层类型参与应有 IPv4/IPv6 头的判定。原长58字节、只采集18字节Ethernet/VLAN头的样本现在返回 partial，IP/TCP完整计数为 null，相关完整性为 false；observed 计数保留。
2. AH 后 TCP 缺失：固定字段增加 `ah.next_header`，参与后继TCP/UDP及内层IP检查。原长98字节、只采集78字节的IPv6→AH→TCP样本现在返回 partial、TCP总数null/完整性false，两个IP地址及IP完整性true保留。AH自身缺失且后继未知时保守降低网络/传输完整性。完整头部、仅载荷截断时，已确认的头部统计仍完整，结果仍partial。
3. 全文件题验收：`answers_pass()` 按 `evidence_id` 定位实际 `pcap_summary`，检查题目来源、capture/overview scope、请求无筛选、状态、grounding、完整性和逐claim原值。Q1要求IP统计和名单完整，允许列表及数组元素引用、名单排序不影响集合核验；Q3要求TCP统计完整且值严格为int。数值相同的filtered、不完整、错误来源及错误字段值均拒绝；分页明细partial且全局摘要完整仍可通过。最终判定继续在报告生成后执行。

字段已核对本机 `tshark -G fields` 与官方 [VLAN参考](https://www.wireshark.org/docs/dfref/v/vlan.html)、[AH参考](https://www.wireshark.org/docs/dfref/a/ah.html)。不引入新的命令入口。

## 失败复现与定向验证

- 先用旧生产实现运行新增14个真实TShark组合：6 failed / 8 passed / 32 deselected，19.79秒。失败为IPv4/IPv6的VLAN内层IP缺失、AH自身缺失、AH后TCP缺失。记录 `local-state/pcap-repair-20261016/red-tests.txt`，真实案件与原输出保存在 `red-cases/`。
- 修复后完整PCAP测试文件46 passed，51.23秒；记录 `green-tests.txt`、`green-cases/`。覆盖完整VLAN/AH、缺失头部和只缺载荷的IPv4/IPv6样本，以及原有分页、筛选、名单上限及分片边界。
- 验收脚本旧判定：11 failed / 4 passed，记录 `validation-before.xml`。新判定19 passed，记录 `validation-after.xml`；覆盖不同IP排序、数组元素引用、空名单有对应引用通过、仅无关引用拒绝，以及scope/来源/类型/完整性和报告作废条件。原失败不覆盖。
- 独立复核原两个检材得到预期null/完整性结果，原检材哈希不变，verify_current无问题；证据 `local-state/pcap-repair-20261016/review/planning/original-repros.json`。独立15项封装/载荷回归通过，未发现新增可复现P1/P2/P3。

最终完整回归204 passed / 1 skipped / 0 failed，205.39秒，记录 `local-state/pcap-repair-20261016/full-final.xml`。唯一跳过项仍是 `tests/test_gui.py:160` 的Windows符号链接创建权限。Ruff与差异空白检查通过。该完整回归与定向记录分别保留。

实际离线安装包原题验收首次遇到环境失败：本地127.0.0.1:11434没有监听进程，Q1/Q3均为model_unavailable，尚未产生模型推理或工具调用。记录 `local-state/pcap-workflow-checks/20261016T025007178394Z/results.json`，案件 `E:/ForensicWork/20261016T025009Z-cf4bfe1e`、`E:/ForensicWork/20261016T025012Z-88c03024`。已保留失败，没有把它重命名为成功或声称本轮每题仅一次analyze。

用户明确允许恢复本机服务后各补验一次，作为“一版一次analyze”的环境恢复例外。初始自写后台启动命令被自动审批以blocked by policy拦截；随后使用已核对的项目 `scripts/start-ollama.ps1` 受控入口成功启动，仅监听127.0.0.1、禁用云功能，没有下载模型或更改上下文/重试额度。discover确认Ollama 0.40.4与既有qwen3.5:4b，记录 `local-state/pcap-repair-20261016/ollama-restored.json`。

经用户授权的实际模型补验，两题各一次analyze，均completed并通过新的来源/scope/完整性验收，记录 `local-state/pcap-workflow-checks/20261016T025523335275Z/results.json`：

| 题目 | 结果 | 原始响应与纠正 |
|---|---|---|
| Q1通信IP | 98.114.205.102、192.150.11.111；21.344秒 | 工具执行一次，无纠正，无警告；案件 `E:/ForensicWork/20261016T025525Z-9327e794` |
| Q3全文件TCP会话数 | 数值5；8.937秒 | 首次把5、true和observed计数5写成字符串，严格校验拒绝；一次claim-repair后引用数值5通过，工具执行一次。案件 `E:/ForensicWork/20261016T025547Z-5f21ebec` |

Q3正常/纠正提示分别2728/2875 token，仍在原4096配置内。首次错误与纠正日志分别保存，不追加工具调用。人工适配器检查、报告复核后的最终答案与完整性、独立全量参考比较和样本未变检查均通过。连接失败与授权补验是两个明确区分的记录，不合并成“首次无错误”；没有再次模型重跑筛选成功。

离线wheel SHA256 `f5be1a3e138b3383e92abcb47c89d7bf657e6b454c06f6a3d3f1bc21b1e579a2`、75,767字节；摘要锁和requirements锁同步，本机`.venv-offline`已重装，pip check通过。27个wheel摘要及30个Python模块/3个web资源在源码、wheel、安装之间逐字节一致；实际导入路径确认是`.venv-offline/Lib/site-packages`。记录 `local-state/pcap-repair-20261016/package-final.json`。

## 历史记录保留

原三版真题与回归记录见 [PCAP与规划流程优化](PCAP_WORKFLOW_OPTIMIZATION.md)，不改写第二版Q1 stopped_duplicate、Q3 insufficient_evidence，以及第一/三版Q3字符串值拒绝和一次纠正。更早119 passed / 2 failed / 1 skipped的记录仍保留于原验证文档，后续通过不覆盖历史失败。

本轮开始时为37个旧响应、案件、结果和复现文件建立SHA256清单 `local-state/pcap-repair-20261016/history-before.json`，结束核对全部未变，记录 `history-after.json`。

旧案件纯判定回放记录 `validation-preserved-cases.json`：第三版两题满足新判定、第二版两题仍失败；第一版缺后来新增的明确IP/TCP完整性标志，不能按新版条件回溯宣称当前通过。这是未重新生成报告、完整性入口stubbed的判定回放，不代表真实模型重跑或重新认证旧案件。

## 边界与未验证范围

原题仍使用已有Honeynet第三方保存副本及原始提示，不向模型注入独立参考值；其来源认证限制保持原评估说明。每题每实现版本只运行一次analyze，所有正常、失败及有界纠正响应保留。

本轮未穷举所有链路封装、IPv6扩展组合、大规模或多源上下文极限；未新增磁盘/手机/内存自动流程、TCP载荷重组、TLS解密或物理断网冷启动验收。源码和脚本中的安全边界、一次规划纠正和一次引用纠正、来源与原始输出复核、严格JSON字段值校验保持。

## 复审提示词

```text
复审本次三项P2修复，范围src/forensic_agent/tools/structured.py的固定字段与完整性判定、tests/test_pcap_workflow.py、knowledge/pcap.md、scripts/verify-pcap-workflow.py、tests/test_pcap_workflow_validation.py、离线wheel/锁、本验证文档及相关历史记录。验收：VLAN内层IP头缺失不能完整0；AH自身缺失未知不得完整，AH后TCP缺失时保留独立IP完整性；完整VLAN/AH和只缺载荷统计正确、partial保持；全文件题必须引用同来源capture摘要，filtered/隐藏filter/不完整/错误来源/字段类型原值错误不得通过，分页partial但完整摘要可通过；列表顺序、数组元素引用与有明确引用的完整空名单正常；报告复核后判断最终状态；规划和引用各一次纠正、白名单及资源边界不变；源码/wheel/安装一致。核对修复前失败、最终204通过/1跳过完整回归与本版原题环境失败及经用户授权的补验，保留第二版两题失败和所有首次类型错误，不把定向通过写成全套通过或把补验写成首次无错误。仅输出可操作发现：P1/P2/P3、文件行号、复现、实际影响、修复验收；无发现明确说明，列未验证范围。
```

## 修复提示词

```text
本轮三项P2已按原复现修复，独立聚焦复核无新增可复现问题。无新复现时保持代码不变。若复审给出新发现，仅修复对应完整性或验收判定，不扩大协议能力、工具白名单、Shell/filter/SQL、资源或纠正预算。保留partial、observed/null与独立完整性，来源及原始输出变化和严格JSON字段值继续拒绝；正常及异常日志不覆盖。先保留失败再最小修复并做必要验证；生产源码变化时更新离线wheel/摘要锁/安装，核对一致性。保留每版原题首次结果及历史失败，不反复重跑筛选成功；文档如实区分定向和全套。每个已验证修改批次提交并推送origin/main，不上传检材、案件或本地证据。
```
