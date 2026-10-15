# 0.1.1 审查修复与验证

日期：2026-10-15，Windows 11 x64 / Python 3.12.13 / RTX 3060 Laptop 6GB。

已执行 `docs/FIX_PROMPT.md`，原整体审查中的 **2 项 P1、6 项 P2 已修复**。原审查与复现保留在 `local-state/reviews/20261015-overall`，作为修复前记录。

## 修复对应关系

| 原问题 | 当前行为 | 回归证据 |
|---|---|---|
| P1：模型 SQL 常量成为答案证据 | 模型只有 schema/columns/count/rows 模板；实际表列校验和参数绑定。人工自由 SQL 为 exploratory，窗口链不升级分类 | 模型自由 SQL/伪造 operator 身份拒绝；人工常量与三层窗口引用拒绝；合法模板仍可用 |
| P1：SQLite 未登记 WAL 改变结果 | 主库及 WAL/SHM/journal 集合登记、验证；每步使用核对后的独立分析副本 | 主库哈希不变而新增 WAL 仍拒绝；注册 WAL 替换/缺失拒绝；合法 WAL 多次查询快照摘要不变 |
| P2：结束/报告只信任历史完整性 | finish/report 复核原件、副本和已记录原始输出；变化使答案失效并保留历史；CLI 状态/退出码同步 | finish 期间修改；报告重建前原件/副本/raw_output 修改；取消持久化；CLI 三入口复核失败 |
| P2：长中文命中正文被省略 | 摘要保留较长正文；省略字段提供有限窗口路由，保留来源/字段/偏移 | 长中文、emoji 字段、窗口返回及引用；探索结果不借窗口成为答案 |
| P2：尾部题目约束被截断 | CLI/Case/API/模型统一 1000 字符，完整保留接受题目，超限明确提示拆分 | 1000 字符尾部约束保留；1001 及以上明确拒绝 |
| P2：TAR `.`/`./` 失败 | 规范化 TAR 前导点路径，根成员必须为目录，保留原成员定位 | 普通 TAR、规范化冲突、内部 `..`、链接、Windows 危险名称 |
| P2：UTF-32 LE BOM 误判 UTF-16 | 先识别更长 BOM；支持 UTF-32 LE/BE，坏编码明确 partial | LE/BE 中文文本命中；损坏尾部返回 partial 和警告 |
| P2：无 Job 的版本探测逃逸超时 | 可信启动代理先等待，加入 Job 后才释放目标；结束/超限清理后代与管道 | 无 Job 调用、分配失败不启动目标、后代管道/延迟写入、输出上限 |

主要源码：`agent/{loop,ollama}.py`、`tools/{registry,params,runner,basic,sqlite_support,archives,process,_startup_proxy}.py`、`evidence/{store,values}.py`、`reports/writer.py`、`cli.py`、`doctor.py`。新回归在 `tests/test_review_fixes.py`、`test_tar_review.py`、`test_process_review.py`；既有测试按安全接口更新，没有降低失败标准。

## 实际验证结果

以下日志除特别注明外均在 `local-state/fix-20261015`。

| 检查 | 结果与记录 |
|---|---|
| 修复针对性测试 | 24 项通过，17.62 秒；`targeted-final.log` |
| 最终安装版本全套测试 | **103 项通过，119.83 秒**；`installed-tests.log` |
| Ruff / pip check | 通过；安装环境终端输出为 All checks passed / No broken requirements found |
| 实际 10 适配器冒烟 | 全部通过，完整性问题为空；`smoke-installed.json`。EVTX partial 为预设展示上限；EvtxECmd 五个指定事件完整返回 |
| 实际本机 Ollama | qwen3.5:4b Q4_K_M（4.2B）三类题通过：FLAG-TEXT-2026、Forensic Fixture、messages 计数 3；`live-model-installed.json` 与 `.log` |
| Windows PowerShell 5.1 | 中文路径和 JSON 参数通过；`local-state/launcher-check.json` |
| doctor | 实际安装环境运行完成，支持工具版本检查正常；`doctor-installed.json` |
| 本地包安装 | 0.1.1，no-index/no-cache-dir/require-hashes，27 个锁定 wheel；`offline-build.log`、`offline-install.log` |
| 发布一致性 | 非 editable；全部安装 Python 源码与当前源码一致；27 个 wheel SHA256 正确，锁文件只有一个项目版本；`release-consistency.json` |

运行路径为 `D:\取证\.venv-offline\Lib\site-packages\forensic_agent`。本项目 wheel SHA256：`93e5ce3dc662f553920a9f01c540b1a757cae5d8bc28a72416a91d4b0a340eb3`。旧 0.1.0 wheel 保留在目录中，但不在当前锁文件和摘要清单中，安装严格使用锁定的 0.1.1。

真实模型报告：

- 文本：`E:\ForensicWork\20261015T075828Z-5ef841c8\report.md`
- 元数据：`E:\ForensicWork\20261015T075854Z-34006074\report.md`
- SQLite：`E:\ForensicWork\20261015T075901Z-61734c3b\report.md`

## 复审与验证边界

两份聚焦复审均为 **未发现可操作问题**：`postfix-security.json` 独立验证自由 SQL 拒绝、真实标识符、三层探索性窗口、未登记 WAL、原始输出篡改；`postfix-agent.json` 核对模板/模型身份、窗口、题目完整传递和 finish/report。根任务另复核 TAR/启动代理及报告/CLI 状态衔接，并完成最终安装验收。各 JSON 明确记录未检查项目，结果不代表安全性证明。

当前无需新增软件或下载模型。遵循用户选择，未初始化 CodeGraph；无 Git 历史，本轮源码/测试等备份在 `local-state/fix-20261015/baseline`。

**物理断网后的 Ollama 与 Agent 冷启动仍未执行**。本轮没有关闭网络、改防火墙、重启已有 Ollama 或下载模型。现有服务监听全部接口；用户需先退出，再断网并用 `scripts/start-ollama.ps1` 启动回环服务，运行 `.venv-offline\Scripts\python.exe scripts/offline-acceptance.py`。README 提供完整命令，脚本拒绝把在线测试记作离线通过。

48 小时稳定性、历年真题、大型恶意数据和其他 Windows 电脑兼容性未验证；Job 是资源限制而非完整漏洞/文件系统沙箱。PECmd/MFTECmd/RECmd/SQLECmd 当前只做路径和版本登记，分析适配器在后续范围。

可复用提示词：`docs/FIX_PROMPT.md`（已执行）、`docs/POST_FIX_REVIEW_PROMPT.md`（只读复审）、`docs/POST_FIX_REPAIR_PROMPT.md`（本次无新 actionable finding，没有新失败时保持代码不变）。
