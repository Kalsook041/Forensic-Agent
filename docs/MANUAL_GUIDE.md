# 人工操作指南

工作台分析失败时会按案件状态显示对应步骤；也可点击“通用人工操作指南 · 工具与处理步骤”。新生成的失败报告附相同步骤，案件目录另存 `manual-guide.md`。工作台支持“保存指南”。

本文件由 `forensic_agent.manual` 的通用模板生成，未检测本机工具入口。命令中的占位路径必须替换，需使用 PowerShell；不要原样执行。


本指南读取已保存的任务状态，未重新核验检材完整性；所列步骤待人工执行，不是取证结论，也没有自动运行所列软件。

- "按输入类型选择流程；指南不会执行操作或生成题目答案。"

## 先处理来源变化或副本缺失

- 工具：Windows 文件资源管理器；Windows 系统工具。
  官方说明：https://support.microsoft.com/windows
1. 暂停基于该案件给出结论，保留原始错误、报告、模型响应和工具日志。
2. 对照报告的原件路径、工作副本路径和 SHA-256，确认是移动、清理、文件变化还是读盘失败。
3. 原件曾移动时，恢复到原登记路径并核对摘要；工作副本已清理时，不能把旧报告的历史检查当作当前检查。
4. 确认输入完整后重新登记或恢复正确副本，再重新核验；不要改写案件 JSON、关闭哈希检查或沿用已失效答案。

交回 Agent：
- 保留错误报告和清理/移动记录；输入恢复前不要把历史候选作为新答案交回。

## 副本容量或工作盘空间不足

- 工具：Windows 文件资源管理器；Windows 系统工具。
  官方说明：https://support.microsoft.com/windows
- 工具：FTK Imager；静态说明，未检测本机入口。
  官方说明：https://www.exterro.com/ftk-downloads/ftk-imager-8-3
1. 在“此电脑”查看案件工作盘空闲量。案件副本配额和磁盘空闲量是两项独立检查，提高配额不会释放空间。
2. 估算原始下载包、解包产物、Agent 工作副本和工具导出各占多少空间；完整镜像登记仍会再复制一份。
3. 查看历史失败案件的 snapshots 大小。只在明确确认清理范围后删除可重建的旧副本，保留原件、报告和日志。
4. 镜像在配额内但空间不足时，优先换工作盘；或用人工工具只读查看镜像，只导出本题需要的少量文件。
5. 确需较大副本且空间足够时，使用“启动大检材界面.cmd”的 64 GiB 配置。逐卷单独提交不能替代整套分析。

交回 Agent：
- 把选出的少量痕迹文件及导出记录交回 Agent；不要反复提交同一份大镜像来释放空间。

## 分卷、压缩包或格式未确认的容器

- 工具：7-Zip；静态说明，未检测本机入口。
  官方说明：https://www.7-zip.org/
- 工具：FTK Imager；静态说明，未检测本机入口。
  官方说明：https://www.exterro.com/ftk-downloads/ftk-imager-8-3
- 工具：VeraCrypt（仅用于已确认的对应格式）；静态说明，未检测本机入口。
  官方说明：https://veracrypt.io/en/Documentation.html
1. 先核对格式、卷编号、大小及随包摘要。.001 也可能是原始镜像分段，不能仅凭后缀认定压缩包。
2. 发布方说明是分卷压缩包时，将同组所有卷放在同一目录，在 7-Zip 打开 .001 或指定的首卷。
3. 先查看清单和“测试”结果；空间足够且没有已验证的解包结果时，再解压到新目录。后续卷不分别解压。
4. 解包后核对文件名、大小和校验结果。无扩展名不等于损坏；不要靠改扩展名或全文搜索来确认格式。
5. 磁盘镜像用 FTK Imager 的 File → Add Evidence Item → Image File 尝试只读打开；打不开时记录完整错误。
6. 格式仍未知时，查发布方的容器格式、软件版本、密码/PIM/密钥文件说明。高熵不能单独证明它是 VeraCrypt。
7. 只有发布方明确指定 VeraCrypt 时，才用其 Select File 和只读挂载选项打开；网盘提取码不能自行当作容器密码。

交回 Agent：
- 找到题目指定的实际镜像或痕迹文件后再交回；保留卷清单、测试/解包日志和内部文件路径。

## 从 Windows 镜像人工查询计算机名

- 工具：FTK Imager；静态说明，未检测本机入口。
  官方说明：https://www.exterro.com/ftk-downloads/ftk-imager-8-3
- 工具：Autopsy；静态说明，未检测本机入口。
  官方说明：https://www.autopsy.com/download/
- 工具：RECmd；静态说明，未检测本机入口。
  官方说明：https://github.com/EricZimmerman/RECmd
1. 先确认哪份镜像对应题目中的 DEMO/目标笔记本，并确认操作系统；不要用其他设备的名称代替。
2. 在 FTK Imager 用 File → Add Evidence Item → Image File 载入受支持的镜像，展开分区和文件系统。
3. 找到 Windows\System32\config\SYSTEM，使用文件的 Export Files 导出到新目录；存在 SYSTEM.LOG1/LOG2 时一起保留。
4. 用 RECmd 对导出的 SYSTEM 副本查询 Select 键的 Current 值，再选择对应 ControlSet；例如 Current=1 对应 ControlSet001。
5. 读取该 ControlSet 下 Control\ComputerName\ComputerName 键的 ComputerName 值，保存原始输出和键路径。
6. 也可在 Autopsy 新建案件、Add Data Source 选择镜像后提取该文件。若镜像/加密层打不开，先处理容器，不跳过到注册表。

待替换路径的 PowerShell 示例（复制前先核对参数）：
```powershell
& "RECmd.exe 的完整路径" -f "SYSTEM副本路径" --kn "Select" --vn "Current" --details
& "RECmd.exe 的完整路径" -f "SYSTEM副本路径" --kn "ControlSet001\Control\ComputerName\ComputerName" --json "新导出目录" --jsonf "computer-name.json"
```

交回 Agent：
- 命令中的路径是待替换示例，第二条的 ControlSet001 也必须按实际 Current 值修改。
- 第一条显示 Current，请保存控制台原始输出；第二条导出整个目标键的 JSON，再核对其中 ComputerName 值。
- 交回 RECmd 原始输出 TXT/JSON 或 CSV，并记录镜像摘要、SYSTEM 摘要、导出路径、键名和工具版本。
- 查询对象是导出副本；本机环境变量 COMPUTERNAME 不能回答离线镜像的计算机名。

## PCAP 统计、筛选结果不完整或 TLS 无明文

- 工具：Wireshark；静态说明，未检测本机入口。
  官方说明：https://www.wireshark.org/docs/
1. 在 Wireshark 用 File → Open 打开同一份 PCAP/PCAPNG，记录题目要求的筛选条件和时间范围。
2. 查 IP 用 Statistics → Endpoints 的 IPv4/IPv6 页；查会话用 Statistics → Conversations 的 TCP 等对应页。
3. 核对 Limit to display filter：全文件题清除筛选限制，筛选范围题保留原筛选，不能扩大范围后套用计数。
4. 用 Copy 导出统计表为 CSV/JSON，保留筛选表达式。截图、分页首屏和截断输出不能证明完整名单或完整 0。
5. 检查采集截断和协议头缺失提示。TLS 只有取得适用的会话密钥后才尝试解密；没有密钥时只分析可见字段。
6. 有合法取得的 key log 时，在 Edit → Preferences → Protocols → TLS 中配置对应文件，保留解密设置与结果说明。

交回 Agent：
- 交回统计 CSV/JSON、筛选条件和原 PCAP 摘要；明确统计范围、截断限制及 TLS 明文是否实际取得。

## SQLite 查询超出自动模板或返回不完整

- 工具：DB Browser for SQLite；静态说明，未检测本机入口。
  官方说明：https://sqlitebrowser.org/
1. 把数据库和同目录的 -wal/-shm/-journal 伴随文件一起保存为副本，保留源路径和摘要。
2. 在 DB Browser for SQLite 以只读方式打开副本，先查看 Database Structure，再在 Execute SQL 使用 SELECT 查询。
3. 明确表名、筛选条件、时间单位和时区；不要用 UPDATE/DELETE、保存变更或关闭 WAL 来凑出结果。
4. 通过导出查询结果保存 CSV；记录完整 SQL、行数以及是否有 LIMIT，分页预览不代表全部记录。

待替换路径的 PowerShell 示例（复制前先核对参数）：
```powershell
& "DB Browser for SQLite.exe 的完整路径" --read-only "数据库副本路径"
```

交回 Agent：
- 交回 CSV 与完整 SQL、数据库/伴随文件摘要；任意 SQL 的人工输出仍需复核，不能伪装成已通过自动引用校验。

## 已有内存镜像的人工分析

- 工具：Volatility 3；静态说明，未检测本机入口。
  官方说明：https://volatility3.readthedocs.io/en/stable/
1. 先确认实际存在内存镜像。题面称现场未固定内存时，不能从普通磁盘镜像生成或假定已有现场内存。
2. 用已安装的 Volatility 3 对内存副本先运行 windows.info；缺少符号时准备匹配符号后复查，记录首个错误。
3. 确认镜像可解析后，再按问题运行 windows.pslist 或 windows.netscan 等插件，保留插件名与参数。
4. 保存 JSON/TXT 输出、工具版本和原内存镜像摘要。没有实际解析成功时，不用空输出证明没有进程或连接。

待替换路径的 PowerShell 示例（复制前先核对参数）：
```powershell
& "vol.exe 的完整路径" --offline -f "内存副本路径" -r json windows.info
```

交回 Agent：
- 交回所需插件的 JSON/TXT 及符号/错误说明；当前指南不承诺 Agent 已接入内存自动适配器。

## 手机文件系统或备份的人工解析

- 工具：ALEAPP；静态说明，未检测本机入口。
  官方说明：https://github.com/abrignoni/ALEAPP
- 工具：iLEAPP；静态说明，未检测本机入口。
  官方说明：https://github.com/abrignoni/iLEAPP
1. 确认输入是 Android/iOS 文件系统导出、备份还是加密物理镜像，并保留完整目录结构和来源说明。
2. Android 用 ALEAPP，iOS 用 iLEAPP；按工具支持的目录/ZIP/TAR 类型选择输入，并把输出写到新目录。
3. 不要把 LEAPP 当作解锁设备或解密任意物理镜像的工具；不支持的备份或加密层需先取得正确导出。
4. 在生成的报告里定位本题所需项目，核对源文件、记录时间和时区，再选对应 TSV/CSV/JSON。

交回 Agent：
- 只交回本题所需报告表和关联原始文件，记录手机/备份标识、来源路径、解析版本与摘要。

## 删除文件恢复或按特征恢复

- 工具：PhotoRec；静态说明，未检测本机入口。
  官方说明：https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step
- 工具：Autopsy；静态说明，未检测本机入口。
  官方说明：https://www.autopsy.com/download/
1. 在副本或只读镜像上操作，确认源镜像与恢复输出不是同一个文件/写入目标。
2. PhotoRec 选择源镜像和目标分区，在 File Opt 勾选需要的类型，再选择未分配区或全分区范围。
3. 把恢复文件写到有空间的新目录，物理盘恢复时使用其他磁盘；不要写回待恢复的源分区。
4. 保留恢复日志、搜索范围及文件摘要。按特征恢复不保证找回原文件名、目录、时间或全部碎片。

交回 Agent：
- 交回目标恢复文件和日志，说明哪些元数据缺失；恢复文件不能自行证明原路径或原始文件名。

## 模型不可用、重复调用或调查停止

1. 先查看本报告的状态与第一个错误；保留失败响应，不把重试后的结果覆盖到首次记录。
2. 模型不可用时，在工作台“检查环境”确认本地服务和模型；也可在“高级选项”选择手动指定白名单工具。
3. 重复调用、无进展或步数耗尽时，先确认输入格式和已执行步骤，再把问题缩小到一个可验证目标。
4. 不能因停止而取消严格引用、追加 Shell 或把工具警告当作答案；人工输出交回后另行分析和校验。

交回 Agent：
- 保留首次错误、已执行步骤和精简后的问题；手动工具成功也不等于原题已全部完成。

## 先确认输入和本题所需文件

1. 核对题目和选中的检材是否对应；DEMO、正式容器、手机和 NAS 不能凭名称互相替代。
2. 确认选中的是分卷包、内部容器、实际镜像还是已经导出的痕迹文件，再选择对应人工流程。
3. 无法识别时记录文件名、大小、工具错误和发布方打开说明；不要靠猜密码、改扩展名或重跑全文搜索下结论。
4. 在工作台“人工操作指南”查看其他方向；优先导出本题需要的小文件，保留完整来源记录。

交回 Agent：
- 交回实际痕迹文件或原始工具报告，以及题目、来源和操作记录。

## 人工导出的交接记录

保留原镜像/检材摘要、设备标识、内部文件路径或偏移、导出文件摘要、工具版本、实际参数、时间与时区。
完成上述处理、确认来源可复核后，交回本题需要的小文件或原始报告，再创建分析任务。Agent 会校验交回文件；原镜像到人工导出之间的来源链仍需操作者记录和复核，不代表已自动验证。
人工笔记、截图和本指南不能直接充当已通过引用校验的答案；partial、截断和失败记录继续保留。
