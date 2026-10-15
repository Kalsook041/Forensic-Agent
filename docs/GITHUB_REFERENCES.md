# 相关 GitHub 仓库与借鉴建议

核查日期：2026-10-15。核对范围：官方 README、GitHub 仓库元数据与许可证标识；不等同于完整运行或安全审计。
python-evtx 已作为 Python 依赖；EvtxECmd 复用本机已安装程序。其他仓库暂作设计与后续扩展参考。

| 仓库 | 可借鉴内容 | 本项目用途 | 许可证标识 | 最近推送 UTC |
|---|---|---|---|---|
| [python-evtx](https://github.com/williballenthin/python-evtx) | EVTX 二进制 XML 解析与真实测试样本 | 已接入并实际验证 | Apache-2.0 | 2026-10-06 |
| [SQLECmd](https://github.com/EricZimmerman/SQLECmd) | SQLite Map 与固定查询模板 | 后续识别常见应用数据库，减少模型自由构造 SQL | MIT | 2026-04-28 |
| [EvtxECmd/evtx](https://github.com/EricZimmerman/evtx) | Windows 事件映射与结构化导出 | 已接入本机可执行程序，与 python-evtx 交叉验证 | MIT | 2026-06-17 |
| [Dissect target](https://github.com/fox-it/dissect.target) | 插件接口、不同数据源的统一查询与记录 | 参考模块边界，镜像能力留到后续阶段 | AGPL-3.0 | 2026-09-25 |
| [Hindsight](https://github.com/RyanDFIR/hindsight) | 浏览器资料解析、时间线、CLI、JSONL/SQLite 输出 | 根据真题扩展浏览器历史和下载记录 | Apache-2.0 | 2026-10-14 |
| [ForensicAgent](https://github.com/FBR65/ForensicAgent) | 原子证据关联、规则校验、输出 grounding 与审计 | 借鉴证据字段校验与失败报告；其多 Agent/GraphRAG 不纳入第一版 | MIT | 2026-08-24 |
| [NFI local-llm-chat-report-benchmark](https://github.com/NetherlandsForensicInstitute/local-llm-chat-report-benchmark) | 小上下文分段提取、Trace ID 校验和报告评测 | 后续用已知答案与真实引用评价 Qwen3，而不只检查文字是否流畅 | Apache-2.0 | 2026-01-27 |

离线准备时，SQLECmd/EvtxECmd 的 Maps 必须预先下载和固定摘要；EvtxECmd 适配器已记录本机 Maps 摘要，正式运行不开放 `--sync`。
Dissect 各子项目许可证需按具体仓库核对，这里只记录 dissect.target 的标识。
NFI 评测项目包含模型服务、tokenizer 和多阶段评测配置，借鉴评测方法，不把整套研究流程当成本机已验证能力。

## 另外发现的相似 Agent

- [CTF-Agent](https://github.com/hvbhanot/CTF-Agent)：有 Ollama 和 forensics 类别、工具调用及解题指标，但公开接口包含 `shell` 与 `python_exec`，也有远程靶机流程。可研究解题流程和测评指标，不能照搬其执行权限。GitHub API 许可证标识为 NOASSERTION，未确认可直接复制的具体条款。
- [DeepTrace AI](https://github.com/A7med668/deeptrace-ai)：README 描述了确定性分析后才调用 Ollama、有限上下文及证据与解释分离。仓库元数据未识别许可证；当前只作为设计阅读材料，未引入代码。

## 当前采用与后续优先级

当前保留单 Agent、静态工具白名单、工作副本、来源 ID、字段和值精确校验及有限循环。
完成真实模型与断网冷启动验收后，再优先评估 SQLECmd 风格的数据库模板和 Hindsight 浏览器适配器；镜像解析另开后续阶段。
