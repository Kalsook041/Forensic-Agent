# 2026-10-15 可用性复审修复

范围仅包含工具启动器原生参数转发、Agent finish 引用的一次纠正，以及必要验证和离线安装包同步。新工具仍未接入 Agent 自动分析。

## 改动与验收

- `scripts/forensic-tools.ps1` 从原始位置参数读取工具名，其余参数原样传递，避免 `-t` 抢占命名 Tool 参数。白名单、SHA256 检查、原生退出码、局部环境恢复保持有效。
- `src/forensic_agent/agent/loop.py` 在 finish 引用校验失败后反馈错误，允许一次额外模型响应。该响应只允许 finish；额外工具请求被拒绝。原响应、首次拒绝、纠正响应或异常分别保存。纠正后重新验证当前完整性和全部引用，`validate_claims` 未放宽。
- `.venv-offline` 已重新安装更新后的本项目 wheel；安装模块与源码逐字节一致，`pip check` 通过。离线 wheel 与两份摘要锁同步。

## 实际结果

- 双 PowerShell 真实工具验证：16/16 通过，包含 `mmls -t dos` 分区读取，ALEAPP/iLEAPP `-t fs` 解析且 TSV 含已知值、含空格路径、`-V`、默认清单、失败退出码、未知工具与环境恢复。记录 `local-state/launcher-checks/20261015T130517142189Z/results.json`。
- 引用纠错定向回归：8/8 通过。涵盖错误字段改正、再次字段错误、错误值、纠正阶段请求工具、无效 JSON、探索性结果、首次 finish 前和纠正请求期间来源变化。记录 `local-state/claim-repair-unit.xml`。
- 原失败案件 `E:/ForensicWork/20261015T124003Z-b36808e9` 在独立副本重放：首次 `n` 被拒绝，第二次 `values[0]` 接受 3，原案件未改。记录 `local-state/claim-repair-checks/20261015T131210093468Z/replay-result.json`。
- 真实本地模型 SQLite 题首次调用成功：`E:/ForensicWork/20261015T130828Z-81775e9a`，答案 3、引用 `values[0]`。关键词题首次调用成功：`E:/ForensicWork/20261015T131210Z-81270e13`，答案 `FLAG-TEXT-2026`。未重复模型题来筛选成功结果。
- 全套 Python 回归：119 passed、2 failed、1 skipped，351.85 秒。失败为既有的 `test_timeout_kills_process_tree`（0.25 秒内没有打印 started）与 `test_descendant_holding_pipes_is_killed[False]`（0.5 秒内父进程未退出）。本轮未修改进程实现或放宽超时测试。跳过项为 Windows 符号链接权限。
- 两项失败单独诊断仍失败，记录 `local-state/process-timing-diagnostic.xml`。补充观测使用 2 秒诊断预算，未改生产设置或测试：简单启动约 0.187 秒，受限代理加父子进程正常退出约 0.485 秒；超时任务和正常退出任务均未遗留子进程标记或线程。记录 `local-state/process-timing-observations.json`。这些观测支持调查短预算的时序假设，但不能替代原测试通过，两项失败仍保留。
- Ruff 与差异空白检查通过。

验证脚本自身首次存在两项问题，均保留事实记录：复制案件没有重定位副本路径，被完整性边界拦截；汇总文件原子替换发生 WinError 5。已修正重放路径，并改为每项先写独立结果、最终一次性写汇总。此前已完成的真实 SQLite 案件通过 `--sqlite-case` 记录，未重新调用模型。首次定向测试的编码错误已修正。原失败记录位于 `local-state/claim-repair-checks/20261015T130828420719Z`。

## 尚未验证与边界

### 本次再次复审新增发现（已按附带修复提示词处理）

P1：`src/forensic_agent/agent/loop.py` 原纠错异常分支跳过完整性复核。复现：首次 finish 同时含有效 `values[0]` 和无效 `n`；第二请求期间原件或副本变化，随后抛出 JSON/请求异常。旧实现仍提交首次有效子集并标记 completed。两个新增回归用例均在修复前失败（`local-state/review-failed-repair-before.xml`）。已把纠正后的完整性复核移到成功/异常分支共同出口，保持一次纠正上限；原件和副本变化均停止且不提交答案。纠错测试扩展为 10/10 通过（`local-state/review-claim-repair-after.xml`）。离线 wheel、摘要锁与本机安装同步更新。

P2：`scripts/verify-claim-repair.py` 原实时/复用案件验收先计算 passed，再调用会重新检查证据的 generate_report。工作副本变化时，原表达式记录 passed=true/state=completed，但报告已将状态改成 evidence_changed 并清空答案。修复前真实脚本表达式复现见 `local-state/review-livecheck-before.json`。已提取可测试的 case_result，先生成报告，再读取最终状态/答案、核查原件/副本/原始输出完整性，并确认预期工具实际执行。新增 6/6 测试通过（`local-state/review-livecheck-after.xml`），覆盖原件、副本、原始输出变化、答案失效及工具不符。

本次相关完整性回归 24/24 通过（`local-state/review-integrity-regression.xml`），Ruff/差异空白检查通过；27 个 wheel 哈希及 30 个 Python 模块在源码、wheel、本机安装之间一致。新的完整验证脚本使用原真实模型案件各复核一次，未重新调用模型，两项均通过并明确记录 reused_case=true；保存失败案件再次独立重放通过。记录 `local-state/claim-repair-checks/20261015T132700148664Z/results.json`。启动器未改，核对此前 16 项真实检查证据，无新增可操作发现。

上方 119 passed / 2 failed / 1 skipped 是前一轮完整回归记录，保持原样；本次定向通过不代表全套回归通过。

真实模型仅两个题，不能据此保证复杂题可靠性。未做物理断网冷启动、真实内存镜像、完整手机提取、大磁盘深度分析或真实删除恢复验收。TLS 明文仍依赖匹配密钥；partial 标记保持。新工具适配器、分页和资源设计不在此次范围内。

## 复审提示词

```text
复审本次工具启动与引用纠错修复。范围：scripts/forensic-tools.ps1、scripts/verify-forensic-tools.py、src/forensic_agent/agent/loop.py、tests/test_claim_repair.py、scripts/verify-claim-repair.py、tests/test_claim_repair_validation.py，以及离线 wheel/摘要锁。验收：双 PowerShell 正确转发 -t/-V 和空格路径，保持白名单、哈希、环境恢复与退出码；finish 只能纠正一次、不追加工具调用；首次错误记录不覆盖；来源变化/探索性结果/错误字段值继续被拒绝，尤其覆盖混合有效/无效引用后纠正请求失败时的变化；验证汇总须在报告复核后读取最终状态/答案，变化的副本或原始输出不能误报通过；安装包与运行源码一致。核对 docs/TOOLS_REPAIR_VALIDATION.md 和已有验证证据，保留全套回归的两项失败，禁止把局部成功描述为全套通过。仅输出可操作发现：P1/P2/P3、文件行号、复现、实际影响、修复验收；无发现明确说明，并列出未验证范围。
```

## 修复提示词

```text
复审新增的 P1（纠正请求异常时跳过完整性复核）和 P2（汇总在报告复核前误报通过）已修复，定向及相关回归通过。后续无新可复现发现时保持代码不变。若发现回归，须保留一次性纠错预算和严格证据校验；异常和成功路径都检查原件/副本，最终验收不能先于报告复核；不扩大工具白名单或开放 Shell。若继续调查既有进程时序测试，先核实子进程启动耗时与树清理，区分测试时序假设和功能缺陷，不通过删除断言、放宽生产边界或反复重跑筛选通过。实施必要定向验证，记录失败，更新离线包/锁与验证文档；每个已验证的修改批次提交并推送 origin/main，不上传案件和本地证据。
```
