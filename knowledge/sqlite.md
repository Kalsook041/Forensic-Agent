# SQLite 题
程序已将数据库与 WAL 一起复制并核对哈希；模型直接分析现有工作副本。
先调用 sqlite 工具，params={"query":"schema"} 列出结构，再根据实际表和字段选择模板。
计数：{"query":"count","table":"messages"}。
字段：{"query":"columns","table":"messages"}。
记录：{"query":"rows","table":"messages","columns":["body"],"limit":20}。
按值筛选：{"query":"rows","table":"messages","filter_column":"id","filter_value":1}。
模型禁止提交 sql/parameters 或任意表达式；表与字段必须来自实际结构。
archive 只用于压缩包，不能复制或查询 SQLite 数据库。
查询只在副本执行；保留 SQL、绑定参数、列名和结果行。
区分数据库存储值、SQL 常量、计算结果和 COUNT 聚合；不能把生成的常量当作原始证据。
