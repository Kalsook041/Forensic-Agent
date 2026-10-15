# 添加取证工具适配器

适配器是受信任的项目代码，通过静态注册实现插件式扩展。检材、压缩包、模型响应不能提供插件代码。

## 必要接口

1. 在 `tools/params.py` 定义继承 `StrictModel` 的参数模型：拒绝未知字段，约束枚举、长度和数量。不要开放 `argv`、可执行路径或自由输出路径。
2. 在 `tools` 实现函数，接收 `Context` 和已验证参数，返回 `ToolResult`。从 `ctx.sources` 读取已登记副本，使用 `ToolRecord(source_id, locator, data)` 提供可核查定位。
3. 在 `tools/registry.py` 的 `REGISTRY` 添加静态 `Adapter`。模型只能从这些 ID 选择工具。
4. 新外部程序还需添加 `ToolPaths` 字段、doctor 的版本探测模板与发现规则，并在 TOML 写入实际绝对路径。
5. 外部程序通过 `ctx.external` 调用，参数由适配器固定构造。工具结果以 JSON、CSV 等明确格式解析，原始输出和版本另存。
6. 新文件只能位于 `ctx.step_dir`。返回 `Artifact(path, parent_id, member)` 后，父进程检查路径、计算摘要并分配新的来源 ID。

`ToolResult.status` 含 `ok / partial / failed / blocked / unsupported`。达到数量上限或跳过相关数据必须标明 partial；无法读取和损坏输入不能返回成功。
`ToolRequest.origin` 区分 `operator / model`；Agent 必须强制把模型请求设为 `model`，不能接受模型自行声称人工身份。需要更严格的模型接口时，为 `Adapter.model_params` 指定独立参数模型；生成约束与运行时校验均使用它，人工接口保留兼容参数。
`ToolRecord.grounding` 区分 `evidence / derived / exploratory`。派生结果必须保留实际来源与变换定位；探索性结果不能支持模型答案。通用读取器必须继承父结果分类，禁止借二次包装升级可信度。`evidence_window` 就遵循这个约定，并且只读取已有合法证据的有限字符串切片。
执行器保存原始输出摘要，工具结束、模型 finish 与报告重建会复核当前来源与输出。发现变化时不能把历史成功结果继续当作当前有效答案。
普通工具 60 秒、PCAP 180 秒、内存 2GiB、CPU 50%、输出 16MiB，受 Windows Job 及父进程监控。适配器不能从模型参数提高这些限额。

## Windows 原生工具

例如扩展 EvtxECmd 或其他本地 Windows 取证程序时：只提供确定的只读分析子命令，把工作副本和固定步骤目录作为输入输出，保留原始 CSV/JSON 和命令记录。
不要加入“模型提供 PowerShell 代码”或“任意命令执行”接口。需要可信辅助脚本时，应随项目审查和发布，参数只允许已登记来源及受控输出。

## 必须补充的验证

- 正常物理样本与已知答案；实际执行工具，不只 mock。
- 缺少程序、版本失败、损坏检材、非零退出、超时、输出超限。
- 来源 ID 越界、额外参数、路径穿越和重解析点。
- 原件 SHA256 在成功与失败后保持一致；派生文件来源链和报告定位可核对。

更新依赖后在开发阶段重建离线 wheelhouse；正式运行期间不安装依赖、不查版本更新、不联网。

## 当前边界

Windows Job 是资源限制，不是完整的文件系统沙箱。工具以当前用户权限执行，安全边界还依赖可信维护的二进制、只读参数模板、副本隔离和输入检查。
SQL 工具使用 read-only URI、query_only、trusted_schema=OFF、内存临时存储、授权回调与进度超时。模型只可用 schema/columns/count/rows 模板，查询实际表与列，绑定筛选值；人工自由 SQL 一律标为 exploratory。查询在核对完整伴随文件集合之后建立的逐步副本中执行，不能直接打开登记快照。
