# RECmd
单个已导出的注册表hive运行固定BasicSystemInfo批次，适合计算机名/系统基础信息。
需要regf头且事务序号一致；dirty hive拒绝，先人工重放日志并保留交接记录。
本版不提供任意注册表键、正则、批次路径或sync参数。没有CSV表示不支持/失败，不能声称完整0。
当前Hive未覆盖的问题应换相关Hive或人工Registry Explorer，不从本机系统取答案。
