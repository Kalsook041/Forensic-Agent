# 本机模型上下文 8K（2026-10-17）

用户指定将当前模型上下文调为8K。`config/default.toml` 的 `num_ctx` 由4096改为8192；`scripts/start-ollama.ps1` 的服务默认 `OLLAMA_CONTEXT_LENGTH` 同步8192。模型仍为qwen3.5:4b，num_predict=1536、工具预算、超时和检材限额保持原值。已有服务无须为环境变量强制重启，应用每次 `/api/chat` 显式发送 num_ctx=8192。标准及64GiB入口均读取配置；旧内容寻址配置不原地改写。

验证：配置解析为8192；真实本地模型一次自检收到finish响应，实际请求options为temperature=0/num_ctx=8192/num_predict=1536，Ollama `/api/ps` 返回context_length=8192。自检约14.76秒，包含模型加载，不能据此推断一般任务速度或8K满载性能。

确认GUI55556没有运行任务后，通过认证API正常退出并刷新大检材入口。新内容寻址profile包含8192上下文、64GiB副本限额；新服务可读通用和旧失败案件指南，未启动分析，旧案件case.json哈希不变。旧profile保持原样。证据保留于 `local-state/context-8k-20261017/{live-model.json,live-gui-result.json}`，不上传本地案件或配置profile。

本轮只改配置及启动脚本，无Python源码/协议变更，无须重建离线wheel/锁；默认ModelSettings在不加载任何项目配置时仍为4096，显式自定义配置也以自己的num_ctx为准。实际GUI和项目默认配置已使用8192。未增加工具结果预览上限、未把完整48GiB输出塞入上下文；未重跑全套、比赛题、8K满载/长时间性能或实机断网验证。8K提供更大上下文容量，不保证分析更快。

复审提示词：复审本轮8K配置，范围config/default.toml、scripts/start-ollama.ps1及本文。核对仅修改上下文参数，真实请求及Ollama运行上下文均8192，num_predict和其他边界保持；内容寻址配置不篡改，刷新GUI前确认空闲，现有案件不变；不把自检当全套/满载/比赛成功。仅报告可操作P1/P2/P3、文件行号、复现、影响、修复验收；无发现明确说明及未验证范围。

修复提示词：本轮聚焦核对未发现可操作问题；无新复现保持配置不变。若有本轮可操作发现，最小修复并重新核对实际请求和加载配置，不扩大工具权限或结果上限；保留失败记录，每个已验证批次提交推送origin/main，不上传案件、凭据或本机profile。
