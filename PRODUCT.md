# Forensic Agent

<!-- impeccable:product-schema 1 -->

## Platform
web

## Users
本机操作者，用于离线取证竞赛和检材分析。用户要求简易 GUI，并确认采用本地浏览器界面。

## Product Purpose
主流程只需选择检材、粘贴题目详情、开始分析，由本地模型自主规划并调用白名单工具。手动工具、规则模式与环境检查位于折叠的高级选项，结果在使用时展开。

## Operating Context
Windows 10/11、Python 3.12，本地 Ollama。项目根目录为 D:\取证，默认案件目录由 config/default.toml 决定。

## Capabilities and Constraints
- 复用已有分析与报告模块；先登记副本并核对哈希，解析工具读取副本。
- 提供模型分析和显式规则模式，题目限制 1..1000 字符。
- 浏览器界面只监听 127.0.0.1，所有样式和脚本随项目提供，离线可用。
- 仅本机单任务交互，不提供远程服务、账户或任意命令执行。
- 现有 CLI 及取证边界保持兼容。

## Evidence on Hand
README.md、config/default.toml、examples/检材 和已有测试提供真实功能与合成样例。样例必须标注为合成。

## Product Principles
- 让用户从检材和问题直接进入自动分析，不要求先选工具或填写参数。
- 一个题目框容纳题干、背景、时间/时区、答案格式与已尝试步骤；参考用户的《10-用Agent解电子取证题.md》。
- 清楚区分运行、完成、证据不足和失败。
- 保留案件、证据定位和中文报告供人工复核。
