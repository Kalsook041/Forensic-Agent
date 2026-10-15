# GUI 交付与验证（2026-10-15）

## 最新调整：题目驱动的简化界面

用户要求粘贴题目详情后由 Agent 自主决定工具，并提供本机 Obsidian《10-用Agent解电子取证题.md》参考。现已改为居中单列表单：检材＋题目详情＋开始分析；默认 `mode=model`，高级执行方式/手动工具/环境检查折叠，分析或打开历史后在下方显示结果。题目框提示背景、时间/时区、答案格式和已尝试步骤，不增加必填字段。

未改分析核心、模型提示词、工具白名单或取证边界。1000字符上限仍在；移除 textarea 的静默截断，超长原文完整保留并通过原生验证提示拆题。

本轮验证：

- `node --test tests/gui-client.test.mjs`：4 passed，覆盖完整题干原样提交至模型、示例恢复自动分析、超长输入/手动模式验证、连接恢复保留任务错误。
- `python -m pytest tests/test_gui.py -q`：10 passed、1 skipped（Windows 符号链接权限），7.35秒；未改核心，因此未重复全部核心回归。
- 简化后的真实浏览器表单自主选 `search`；案件 `20261015T085702Z-92a7a053`，状态 `completed`，答案引用 `step0001:r00001.text = FLAG-TEXT-2026`，原始定位含 `line=2`；请求 `origin=model`。
- 浏览器验证1005字符保留且阻止超长提交，手动工具可从高级选项访问并切回自动分析，默认高级选项关闭。
- 1365×900桌面与390×844窄屏检查：无整页横溢、无脚本 error/warn。截图 `simple-desktop.png`、`simple-mobile.png` 位于 `.impeccable/review/`。
- JS语法检查通过；设计记录与sidecar同步当前单列布局。检测器仍为正则降级，提示既有颜色/字号的文档覆盖建议；未当作完整质量通过或顺手改动既有色彩系统。
- 根代理聚焦复审：默认流程、折叠高级入口、原文传递、原生校验、输出展开、旧服务边界均未发现新增可操作问题。

本轮复审提示词：

> 请审查 D:\取证 本轮 GUI 简化：src/forensic_agent/web/{index.html,app.css,app.js}、tests/gui-client.test.mjs 及相关设计/操作文档。验收：默认只需检材和题目，提交 action=analyze/mode=model；示例不会切到规则；完整题干原样传入；超长保留并拒绝提交；规则/手动工具/环境检查在高级选项可用；运行、历史报告、重核验/下载和服务守卫兼容；桌面与窄屏可操作。运行Node专项和tests/test_gui.py，检查simple-desktop/mobile截图。按优先级、文件:行号、触发步骤、影响、最小修复建议输出有证据的发现；无发现请明确，不扩大功能范围。

本轮修复提示词：

> 当前聚焦复审无新增 actionable findings，请保持代码不变。如新复审确认范围内问题，先按触发步骤复现再做最小修复，保留默认模型自主选工具、题干原文、超长提示和高级入口；运行相关Node/Python检查及必要浏览器验证，按“发现→修改→验证→剩余限制”报告，不以规则模式冒充模型规划，不引入自由命令或SQL执行。

以下为首版交付的历史记录。

## 交付

双击项目根目录的 `启动取证界面.cmd`，或执行 `./forensic-gui.ps1`。本机自动选择空闲端口并打开浏览器。
界面支持文件/文件夹路径、自然语言模型分析、规则模式、9 个常用直接工具、JSON 参数说明、环境检查、进度、历史报告、重新核验和保存。
GUI 经已有 CLI 执行取证操作，未修改证据、模型、工具进程或报告核心。工作目录继续使用现有配置。

服务仅绑定 `127.0.0.1`；固定静态资源映射、Host/Origin/session token 校验、CSP、纯文本安全报告渲染。
采用 Python 标准库的本地线程 HTTP 服务，未新增运行依赖。[Python 官方 HTTP 服务文档](https://docs.python.org/3.12/library/http.server.html) 说明其浏览器并发连接行为；本项目仅用于本机操作。

## 已验证

- `python -m pytest tests/test_gui.py tests/test_boundaries.py tests/test_review_fixes.py -q`：50 passed，1 skipped（32.69 秒）。跳过项是 Windows 创建符号链接缺少权限；未计为通过。
- `node --test tests/gui-client.test.mjs`：1 passed。短暂断线提示出现，恢复连接后清除，同时保留原任务错误。
- Ruff 检查新增 Python 文件通过；`node --check src/forensic_agent/web/app.js` 通过。
- 接口测试真实执行规则搜索，检查原件内容不变、报告含 FLAG、禁止并发任务和运行中退出；修改测试检材后重新核验返回失败并持久化 `evidence_changed`。
- 接口拒绝外来 Origin、Host、错误 token、跨站请求、静态路径穿越及非法请求；检查题目长度和检材/工作目录包含关系。
- 浏览器真实执行合成文本样例，得到 `FLAG-TEXT-2026`；直接 SHA256 工具成功。打开历史报告、重新核验和下载 Markdown 报告成功。
- 浏览器刷新恢复服务端最新任务结果；环境检查结果成功显示。浏览器控制台未记录 error/warn。
- 1365×1000 桌面及390×844窄屏检查；窄屏空状态和报告状态的 `scrollWidth == clientWidth == 390`。
- Windows PowerShell 启动器用现有 `.venv-offline` 成功启动新服务，并经退出接口正常关闭。默认自动端口工作正常；本机固定8765端口被系统拒绝，所以没有将其写成默认值。
- wheel 构建通过；包内包含 GUI Python 文件、HTML/CSS/JS 和 GUI entry point。当前 `build/gui-dist` 是新构建；旧 `offline/wheelhouse` 未自动替换。

## 独立审查

当前工具未提供命名的 impeccable agent 类型，使用独立、无会话历史的代理承担 finish reviewer 和 documenter 角色。
设计检测器执行一次，但本机缺少 HTML parser modules，仅正则降级检查，未发现匹配项；不能将此计为完整检查。独立审查额外核算了主要配色对比度。

| 审查项 | 最终结论 |
| --- | --- |
| 设计契约与响应式 | 通过 |
| 功能与服务边界 | 通过 |
| Craft floor | 通过 |
| 连接恢复状态 P2 | 已修复，resolved |
| 整体 finish verdict | 通过，无遗留可操作发现 |

唯一 P2 是短暂断线后旧告警不消失。已隔离连接告警和任务告警，并通过专项测试，独立审查确认 resolved。
截图保存在 `.impeccable/review/`，包含 desktop/mobile 空状态、报告状态与最终确认图。

## 验证限制

系统文件选择对话框没有完成自动化点选验证；已确认当前 Python 能导入 tkinter，路径粘贴链路已实际通过。
本轮没有重复运行完整模型题集或物理断网冷启动；已有核心模型验证记录仍见 `FIX_VALIDATION.md`。
GUI 本轮通过原有本地服务显示模型可用，模型分析命令构造复用 CLI；不能据此新增跨机器、物理断网或连续运行的通过声明。

## 可直接使用的复审提示词

> 请独立审查 D:\取证 新增简易本地浏览器 GUI。范围是 src/forensic_agent/gui.py、gui_picker.py、web/、forensic-gui.ps1、启动取证界面.cmd、pyproject.toml 和 GUI 测试。验收：双击启动、检材文件/目录、模型/规则分析、常用直接工具、进度/错误、历史报告/重核验/保存；单任务不阻塞页面；保持 CLI 副本/哈希/白名单边界；只监听回环、无外部资源或新增运行依赖；桌面和窄屏无阻断。先阅读 PRODUCT.md、DESIGN.md、WORK_STATE.md 和 docs/GUI_VALIDATION.md。运行相关 Python 测试、node --test tests/gui-client.test.mjs、Ruff、JS 语法检查，检查 .impeccable/review/ 截图。只报告有证据的可操作发现，格式：优先级、文件:行号、触发步骤、实际影响、最小修复建议；明确验证限制。没有发现时直接说明，不扩大功能范围。

## 可直接使用的修复提示词

> 原独立审查唯一 P2“短暂断线恢复后旧连接告警未消失”已修复并复核 resolved；最终无遗留 actionable findings。保持代码不变，不增加功能或视觉调整。如复审出现新的有证据且在 GUI 范围内的问题，逐项按复审触发步骤复现并做最小修复，保留 CLI 和取证安全边界。重点验收：故障时连接提示出现，成功轮询后消失，任务错误仍保留；规则样例、重复任务保护、报告重核验/保存、回环与会话保护继续通过。运行相关检查并按“发现→修复文件→验证结果→剩余限制”报告，禁止以跳过、弱化测试或隐藏错误宣称修复。
