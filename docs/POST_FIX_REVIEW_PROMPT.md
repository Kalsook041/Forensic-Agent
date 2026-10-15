# 修复后复审提示词

请对 `D:\取证` 的 0.1.1 修复版本做只读复审。先阅读 `docs/FIX_PROMPT.md`、`local-state/reviews/20261015-overall/review.md`、`WORK_STATE.md` 和当前代码；可与 `local-state/fix-20261015/baseline` 比较。项目无 Git 历史，CodeGraph 未初始化且用户已选择暂不建索引。

范围：模型 SQLite 查询模板与 origin、探索性结果分类、证据窗口继承来源、数据库与 WAL/SHM/journal 的完整集合校验和每步副本、finish/report 当前复核、1000 字符一致限制、UTF-32、TAR 点路径与冲突、无显式 Job 的受限启动代理，以及离线 wheel/锁文件与真实运行版本的一致性。

验收标准：
- 模型自拟 SQL 常量、人工探索 SQL 及其证据窗口不能获得答案依据身份；合法 schema/columns/count/rows 模板仍可用。
- 新增/缺失/替换 WAL 等伴随文件必须被拒绝；合法 WAL 内容可反复查询，登记快照不被 SQLite 修改。
- 模型解释期间或报告重建前的原件、副本、已记录原始输出变化能被发现，历史证据保留且不维持无警告的正常答案。
- 长中文正文可见或能经静态窗口工具读取并准确引用；已接受题目完整传递，超限明确拒绝。
- 常见 TAR 点路径可提取，危险路径/链接/规范化冲突仍拒绝；UTF-32 LE/BE 正确检索，损坏编码明确报告。
- Job 分配成功前目标程序不能启动；超时、输出超限或正常根进程退出后，没有持有管道的残留后代导致无界等待。
- 保持单 Agent、CLI、离线、白名单、shell=False、原件保护；不得以禁用基本能力绕过审查问题。

参考检查：`.venv\Scripts\python.exe -X utf8 -m pytest tests -q`、Ruff、`scripts/smoke_test.py`、`scripts/live-model-acceptance.py`、`scripts/verify-launcher.py`；用已安装离线环境复核最终 wheel。不要下载模型、安装新工具、重启已有 Ollama、改网络/PATH 或执行用户真实检材中的程序。物理断网冷启动未实际执行前不得视为已通过。

仅报告已证实的当前问题，排除已明确披露的后续能力与验证边界。每条 actionable finding 提供：P0/P1/P2/P3、文件绝对路径和精确行号、触发条件、可观察后果、复现或代码证据、具体修复方向与所需验证。按严重性排序并去重；若没有 actionable findings，明确写“未发现可操作问题”，列出实际检查及未验证范围，不修改代码。
