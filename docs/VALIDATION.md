# 验证记录

日期：2026-10-15（Asia/Shanghai）。平台：Windows 11 x64 / Python 3.12.13 / RTX 3060 Laptop 6GB。

## 当前 0.1.1 修复版本

整体审查的 2 项 P1、6 项 P2 已修复，详见 `docs/FIX_VALIDATION.md`。最终非 editable 离线安装版本 **103 项测试通过（119.83 秒）、Ruff/pip check 通过、10 个实际适配器冒烟通过、3 类实际模型题通过、PowerShell 5.1 启动器通过**。27 个锁定 wheel 与安装源码一致性检查通过。
记录位于 `local-state/fix-20261015`；物理断网冷启动仍未验证。以下保留首版实现和历史验证，历史 57 项/9 个适配器数字不是当前版本结果。

## 已核实

- 用户 PATH 已新增 7-Zip、Wireshark 和 EZTools 的四个目录，保留原顺序；ExifTool/Ollama 已有项，不重复添加。备份见 local-state。
- 从持久化用户和系统 PATH 构造的新进程环境能找到 7z、tshark、exiftool、ollama、EvtxECmd、PECmd、MFTECmd、RECmd 和 SQLECmd。
- 已实际调用 ExifTool 13.59、TShark 4.6.9、7-Zip 26.04、Python SQLite 和 python-evtx 0.8.1。
- 三类基础 CLI 样例：文本第二行 FLAG-TEXT-2026；图片 Author=Forensic Fixture；messages 计数=3。
- SQLite WAL 内的已提交数据能够通过工作快照查询；禁止 DELETE、ATTACH、扩展加载及写入 PRAGMA。
- ZIP/TAR/GZIP 解包和 7z 内容列表已实际运行；7z/RAR 解包明确 unsupported。
- PCAP DNS/HTTP 帧定位及协议统计，真实公共 EVTX 样本解析通过。
- EZTools EvtxECmd 2026.5.0 已实际调用；事件 6005 的五个 Record ID 与 python-evtx 解析结果一致。其余四个 EZTools 只检测路径/版本，尚无分析适配器。
- 已在新虚拟环境使用 no-index、no-cache-dir、require-hashes 由本地 27 个 wheel 完成安装，并运行测试与真实工具冒烟。
- Windows PowerShell 5.1 启动器实测中文路径和 JSON 参数通过；脚本使用 UTF-8 BOM，启动器优先离线环境。
- 本机 Ollama 0.40.4 / qwen3.5:4b Q4_K_M（4.2B）实际执行三类基础题通过。模型、原始交互、报告路径与已知答案核对记录在 local-state/live-model-acceptance.json。

完整执行结果保存在 `local-state/environment.json`、`smoke-clean.json`、`offline-install.log` 和最终测试日志。
样例报告路径由 `smoke-clean.json` 给出，全部原件完整性复核没有发现差异。

0.1.0 首版安装验证：**57 项测试通过（40.78 秒），ruff 通过，9 个真实适配器冒烟通过，3 类真实模型题通过，pip check 无依赖问题**。EVTX 冒烟中的 partial 是预设展示上限，原生 EvtxECmd 的五个指定事件完整返回。
离线 wheel 更新安装日志是 `local-state/offline-refresh-final.log`；最终测试为 `tests-final.log`，模型运行日志为 `live-model-final.log`。代码已装入干净创建的 `.venv-offline`，没有依赖源码目录的可编辑安装。

## 安全与故障验证

覆盖：白名单及未知参数拒绝；原件与工作副本变化；WAL；危险压缩成员、大小写冲突、文件与目录冲突、链接、炸弹；磁盘余量不足；Job 建立/分配失败；工作进程超时和子进程终止；输出超限；用户取消及复核中断；损坏 EVTX/PCAP/SQLite/ZIP；缺少外部工具；伪造证据与字段值；恶意检材指令；非本地模型 URL、云模型名称、重定向及未允许 API。

混合目录搜索跳过非文本时会返回 partial；EVTX 测试故意设低数量上限，partial 表示结果未穷尽，不是测试绕过。
短中文 GB18030 文本的统计误判已修复为中文 Windows 编码优先尝试，同时仍明确标记推断。
审查修复还包括副本文件系统时间不能冒充原件、启动前持久化命令、子进程持有输出管道时的清理，以及不完整操作记录的报告恢复。
模型复验曾出现 SQLite 题误选 archive 并重复调用，程序停止且未生成答案。已补充工具用途、明确 SQLite 流程，并在生成约束中移除不支持的工具/来源组合；修复后重新通过三类题。这是有限样例验证，不代表其他题目均能正确选择工具。
引用校验支持安全数组索引，拒绝负索引、越界、表达式和字符串冒充数值。大 EVTX 结果摘要保留真实事件字段，不把截断预览伪装成可引用字段。

## 尚未验证

- 关闭网络后的 Ollama 和 Agent 冷启动：尚未实际关闭外部网络，不宣称通过。
- 48 小时连续运行稳定性、全部历年真题、大型损坏数据集和其他 Windows 电脑兼容性。

模型协议、引用校验及停止条件测试使用明确标识的模拟模型响应；工具链和最终冒烟使用真实程序及物理样本文件，两者分开记录。

## 如何补齐最后的验收

本机软件与模型已就绪，当前无需再安装。已有 Ollama 服务在全部接口监听；启动脚本拒绝抢占。请先自行退出已有服务，断网后用启动脚本启动回环 CLI 服务，再运行 offline-acceptance.py。
脚本核对网络状态、冷启动记录与监听 PID，执行三类模型题和全部工具冒烟，并生成带时间的验收 JSON。
