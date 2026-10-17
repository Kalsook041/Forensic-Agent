"""Deterministic operator guidance. These instructions never execute tools or supply claims."""

import json
from pathlib import Path
import re

TOOLS = {
    "explorer": ("Windows 文件资源管理器", None, "https://support.microsoft.com/windows"),
    "seven_zip": ("7-Zip", "seven_zip", "https://www.7-zip.org/"),
    "ftk_imager": ("FTK Imager", None, "https://www.exterro.com/ftk-downloads/ftk-imager-8-3"),
    "veracrypt": ("VeraCrypt（仅用于已确认的对应格式）", None, "https://veracrypt.io/en/Documentation.html"),
    "autopsy": ("Autopsy", None, "https://www.autopsy.com/download/"),
    "recmd": ("RECmd", "recmd", "https://github.com/EricZimmerman/RECmd"),
    "wireshark": ("Wireshark", "tshark", "https://www.wireshark.org/docs/"),
    "sqlitebrowser": ("DB Browser for SQLite", None, "https://sqlitebrowser.org/"),
    "volatility3": ("Volatility 3", None, "https://volatility3.readthedocs.io/en/stable/"),
    "aleapp": ("ALEAPP", "aleapp", "https://github.com/abrignoni/ALEAPP"),
    "ileapp": ("iLEAPP", "ileapp", "https://github.com/abrignoni/iLEAPP"),
    "photorec": ("PhotoRec", None, "https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step"),
}

# Menu names and command syntax are operator instructions, never model/tool requests.
WORKFLOWS = {
    "integrity": {
        "title": "先处理来源变化或副本缺失",
        "tools": ["explorer"],
        "steps": [
            "暂停基于该案件给出结论，保留原始错误、报告、模型响应和工具日志。",
            "对照报告的原件路径、工作副本路径和 SHA-256，确认是移动、清理、文件变化还是读盘失败。",
            "原件曾移动时，恢复到原登记路径并核对摘要；工作副本已清理时，不能把旧报告的历史检查当作当前检查。",
            "确认输入完整后重新登记或恢复正确副本，再重新核验；不要改写案件 JSON、关闭哈希检查或沿用已失效答案。",
        ],
        "exports": ["保留错误报告和清理/移动记录；输入恢复前不要把历史候选作为新答案交回。"],
    },
    "storage": {
        "title": "副本容量或工作盘空间不足",
        "tools": ["explorer", "ftk_imager"],
        "steps": [
            "在“此电脑”查看案件工作盘空闲量。案件副本配额和磁盘空闲量是两项独立检查，提高配额不会释放空间。",
            "估算原始下载包、解包产物、Agent 工作副本和工具导出各占多少空间；完整镜像登记仍会再复制一份。",
            "查看历史失败案件的 snapshots 大小。只在明确确认清理范围后删除可重建的旧副本，保留原件、报告和日志。",
            "镜像在配额内但空间不足时，优先换工作盘；或用人工工具只读查看镜像，只导出本题需要的少量文件。",
            "确需较大副本且空间足够时，使用“启动大检材界面.cmd”的 64 GiB 配置。逐卷单独提交不能替代整套分析。",
        ],
        "exports": ["把选出的少量痕迹文件及导出记录交回 Agent；不要反复提交同一份大镜像来释放空间。"],
    },
    "archive": {
        "title": "分卷、压缩包或格式未确认的容器",
        "tools": ["seven_zip", "ftk_imager", "veracrypt"],
        "steps": [
            "先核对格式、卷编号、大小及随包摘要。.001 也可能是原始镜像分段，不能仅凭后缀认定压缩包。",
            "发布方说明是分卷压缩包时，将同组所有卷放在同一目录，在 7-Zip 打开 .001 或指定的首卷。",
            "先查看清单和“测试”结果；空间足够且没有已验证的解包结果时，再解压到新目录。后续卷不分别解压。",
            "解包后核对文件名、大小和校验结果。无扩展名不等于损坏；不要靠改扩展名或全文搜索来确认格式。",
            "磁盘镜像用 FTK Imager 的 File → Add Evidence Item → Image File 尝试只读打开；打不开时记录完整错误。",
            "格式仍未知时，查发布方的容器格式、软件版本、密码/PIM/密钥文件说明。高熵不能单独证明它是 VeraCrypt。",
            "只有发布方明确指定 VeraCrypt 时，才用其 Select File 和只读挂载选项打开；网盘提取码不能自行当作容器密码。",
        ],
        "exports": ["找到题目指定的实际镜像或痕迹文件后再交回；保留卷清单、测试/解包日志和内部文件路径。"],
    },
    "windows": {
        "title": "从 Windows 镜像人工查询计算机名",
        "tools": ["ftk_imager", "autopsy", "recmd"],
        "steps": [
            "先确认哪份镜像对应题目中的 DEMO/目标笔记本，并确认操作系统；不要用其他设备的名称代替。",
            "在 FTK Imager 用 File → Add Evidence Item → Image File 载入受支持的镜像，展开分区和文件系统。",
            "找到 Windows\\System32\\config\\SYSTEM，使用文件的 Export Files 导出到新目录；存在 SYSTEM.LOG1/LOG2 时一起保留。",
            "用 RECmd 对导出的 SYSTEM 副本查询 Select 键的 Current 值，再选择对应 ControlSet；例如 Current=1 对应 ControlSet001。",
            "读取该 ControlSet 下 Control\\ComputerName\\ComputerName 键的 ComputerName 值，保存原始输出和键路径。",
            "也可在 Autopsy 新建案件、Add Data Source 选择镜像后提取该文件。若镜像/加密层打不开，先处理容器，不跳过到注册表。",
        ],
        "commands": [
            '& "RECmd.exe 的完整路径" -f "SYSTEM副本路径" --kn "Select" --vn "Current" --details',
            '& "RECmd.exe 的完整路径" -f "SYSTEM副本路径" '
            '--kn "ControlSet001\\Control\\ComputerName\\ComputerName" '
            '--json "新导出目录" --jsonf "computer-name.json"',
        ],
        "exports": [
            "命令中的路径是待替换示例，第二条的 ControlSet001 也必须按实际 Current 值修改。",
            "第一条显示 Current，请保存控制台原始输出；第二条导出整个目标键的 JSON，再核对其中 ComputerName 值。",
            "交回 RECmd 原始输出 TXT/JSON 或 CSV，并记录镜像摘要、SYSTEM 摘要、导出路径、键名和工具版本。",
            "查询对象是导出副本；本机环境变量 COMPUTERNAME 不能回答离线镜像的计算机名。",
        ],
    },
    "pcap": {
        "title": "PCAP 统计、筛选结果不完整或 TLS 无明文",
        "tools": ["wireshark"],
        "steps": [
            "在 Wireshark 用 File → Open 打开同一份 PCAP/PCAPNG，记录题目要求的筛选条件和时间范围。",
            "查 IP 用 Statistics → Endpoints 的 IPv4/IPv6 页；查会话用 Statistics → Conversations 的 TCP 等对应页。",
            "核对 Limit to display filter：全文件题清除筛选限制，筛选范围题保留原筛选，不能扩大范围后套用计数。",
            "用 Copy 导出统计表为 CSV/JSON，保留筛选表达式。截图、分页首屏和截断输出不能证明完整名单或完整 0。",
            "检查采集截断和协议头缺失提示。TLS 只有取得适用的会话密钥后才尝试解密；没有密钥时只分析可见字段。",
            "有合法取得的 key log 时，在 Edit → Preferences → Protocols → TLS 中配置对应文件，保留解密设置与结果说明。",
        ],
        "exports": ["交回统计 CSV/JSON、筛选条件和原 PCAP 摘要；明确统计范围、截断限制及 TLS 明文是否实际取得。"],
    },
    "sqlite": {
        "title": "SQLite 查询超出自动模板或返回不完整",
        "tools": ["sqlitebrowser"],
        "steps": [
            "把数据库和同目录的 -wal/-shm/-journal 伴随文件一起保存为副本，保留源路径和摘要。",
            "在 DB Browser for SQLite 以只读方式打开副本，先查看 Database Structure，再在 Execute SQL 使用 SELECT 查询。",
            "明确表名、筛选条件、时间单位和时区；不要用 UPDATE/DELETE、保存变更或关闭 WAL 来凑出结果。",
            "通过导出查询结果保存 CSV；记录完整 SQL、行数以及是否有 LIMIT，分页预览不代表全部记录。",
        ],
        "exports": ["交回 CSV 与完整 SQL、数据库/伴随文件摘要；任意 SQL 的人工输出仍需复核，不能伪装成已通过自动引用校验。"],
        "commands": ['& "DB Browser for SQLite.exe 的完整路径" --read-only "数据库副本路径"'],
    },
    "memory": {
        "title": "已有内存镜像的人工分析",
        "tools": ["volatility3"],
        "steps": [
            "先确认实际存在内存镜像。题面称现场未固定内存时，不能从普通磁盘镜像生成或假定已有现场内存。",
            "用已安装的 Volatility 3 对内存副本先运行 windows.info；缺少符号时准备匹配符号后复查，记录首个错误。",
            "确认镜像可解析后，再按问题运行 windows.pslist 或 windows.netscan 等插件，保留插件名与参数。",
            "保存 JSON/TXT 输出、工具版本和原内存镜像摘要。没有实际解析成功时，不用空输出证明没有进程或连接。",
        ],
        "commands": ['& "vol.exe 的完整路径" --offline -f "内存副本路径" -r json windows.info'],
        "exports": ["交回所需插件的 JSON/TXT 及符号/错误说明；当前指南不承诺 Agent 已接入内存自动适配器。"],
    },
    "mobile": {
        "title": "手机文件系统或备份的人工解析",
        "tools": ["aleapp", "ileapp"],
        "steps": [
            "确认输入是 Android/iOS 文件系统导出、备份还是加密物理镜像，并保留完整目录结构和来源说明。",
            "Android 用 ALEAPP，iOS 用 iLEAPP；按工具支持的目录/ZIP/TAR 类型选择输入，并把输出写到新目录。",
            "不要把 LEAPP 当作解锁设备或解密任意物理镜像的工具；不支持的备份或加密层需先取得正确导出。",
            "在生成的报告里定位本题所需项目，核对源文件、记录时间和时区，再选对应 TSV/CSV/JSON。",
        ],
        "exports": ["只交回本题所需报告表和关联原始文件，记录手机/备份标识、来源路径、解析版本与摘要。"],
    },
    "recovery": {
        "title": "删除文件恢复或按特征恢复",
        "tools": ["photorec", "autopsy"],
        "steps": [
            "在副本或只读镜像上操作，确认源镜像与恢复输出不是同一个文件/写入目标。",
            "PhotoRec 选择源镜像和目标分区，在 File Opt 勾选需要的类型，再选择未分配区或全分区范围。",
            "把恢复文件写到有空间的新目录，物理盘恢复时使用其他磁盘；不要写回待恢复的源分区。",
            "保留恢复日志、搜索范围及文件摘要。按特征恢复不保证找回原文件名、目录、时间或全部碎片。",
        ],
        "exports": ["交回目标恢复文件和日志，说明哪些元数据缺失；恢复文件不能自行证明原路径或原始文件名。"],
    },
    "planning": {
        "title": "模型不可用、重复调用或调查停止",
        "tools": [],
        "steps": [
            "先查看本报告的状态与第一个错误；保留失败响应，不把重试后的结果覆盖到首次记录。",
            "模型不可用时，在工作台“检查环境”确认本地服务和模型；也可在“高级选项”选择手动指定白名单工具。",
            "重复调用、无进展或步数耗尽时，先确认输入格式和已执行步骤，再把问题缩小到一个可验证目标。",
            "不能因停止而取消严格引用、追加 Shell 或把工具警告当作答案；人工输出交回后另行分析和校验。",
        ],
        "exports": ["保留首次错误、已执行步骤和精简后的问题；手动工具成功也不等于原题已全部完成。"],
    },
    "triage": {
        "title": "先确认输入和本题所需文件",
        "tools": [],
        "steps": [
            "核对题目和选中的检材是否对应；DEMO、正式容器、手机和 NAS 不能凭名称互相替代。",
            "确认选中的是分卷包、内部容器、实际镜像还是已经导出的痕迹文件，再选择对应人工流程。",
            "无法识别时记录文件名、大小、工具错误和发布方打开说明；不要靠猜密码、改扩展名或重跑全文搜索下结论。",
            "在工作台“人工操作指南”查看其他方向；优先导出本题需要的小文件，保留完整来源记录。",
        ],
        "exports": ["交回实际痕迹文件或原始工具报告，以及题目、来源和操作记录。"],
    },
}


def _literal(value):
    # Keep untrusted names and diagnostics on one line, outside executable examples.
    return json.dumps(str(value), ensure_ascii=False).replace("`", "\\u0060")


def _local_file(path):
    try:
        candidate = Path(path)
        return candidate.is_absolute() and not str(path).startswith(("\\\\", "//")) and candidate.is_file()
    except (OSError, ValueError, TypeError):
        return False


def _tool_inventory(settings):
    configured = {}
    if settings is None:
        return configured
    path = settings.knowledge_dir.parent / "config" / "local-tools.json"
    try:
        if _local_file(path) and path.stat().st_size <= 1024**2:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            configured = data.get("tools", {}) if isinstance(data, dict) else {}
            if not isinstance(configured, dict):
                configured = {}
    except (OSError, ValueError):
        pass
    return configured


def _tool_info(identity, settings, inventory):
    name, setting, url = TOOLS[identity]
    entry = inventory.get(identity, {})
    path = getattr(settings.tools, setting, None) if settings is not None and setting else None
    if identity == "wireshark" and path:
        try:
            path = Path(path).with_name("Wireshark.exe")
        except (OSError, ValueError, TypeError):
            path = None
    if not path and isinstance(entry, dict):
        path = entry.get("executable")
    found = bool(path and _local_file(path))
    status = "Windows 系统工具" if identity == "explorer" else (
        "静态说明，未检测本机入口" if settings is None else (
            "检测到入口文件；未针对本任务验证解析能力" if found else "未检测到配置入口；请手动确认或从官方准备"))
    return {"id": identity, "name": name, "path": str(path) if found else None,
            "entry_found": found, "status": status, "official_url": url}


def build_manual_guidance(case=None, *, settings=None, inventory=None):
    """Build advisory text without inspecting evidence contents, running tools, or changing the case."""
    settings = settings or (case.settings if case is not None else None)
    manifest = case.manifest if case is not None else {}
    state = manifest.get("state", "general")
    steps = manifest.get("steps", [])
    incomplete = [step for step in steps if (step.get("result") or {}).get("status") not in {"ok", None}]
    needed = case is None or state not in {"completed", "completed_without_model", "tool_completed"} or bool(incomplete)
    reasons = [f"案件状态：{state}"] if case is not None else ["按输入类型选择流程；指南不会执行操作或生成题目答案。"]
    for step in incomplete:
        reasons.append(f"{step.get('id', '步骤')} / {step.get('request', {}).get('tool_id', '工具')}："
                       f"{(step.get('result') or {}).get('status')}")
    warnings = "\n".join(str(x) for x in manifest.get("warnings", []))
    paths = [str(x.get("original_path") or x.get("working_path") or "") for x in manifest.get("sources", [])]
    input_path = manifest.get("input_path") or (paths[0] if paths else None)
    names = [Path(x).name.casefold() for x in [*paths, str(input_path or "")]]
    question = str(manifest.get("question", "")).casefold()
    kinds = {str(step.get("request", {}).get("tool_id", "")) for step in steps}
    selected = []
    integrity = state == "evidence_changed" or any(x in warnings for x in (
        "复制期间源文件变化", "副本哈希验证失败", "检材在复制期间变化"))
    if case is None:
        selected = list(WORKFLOWS)
    elif needed and integrity:
        selected = ["integrity"]
    elif needed:
        if state == "intake_failed" and any(x in warnings for x in ("上限", "磁盘空间不足", "磁盘余量")):
            selected.append("storage")
        if "archive" in kinds or any(re.search(r"\.(7z|zip|rar|tar|gz)(\.\d+)?$|\.\d{3}$", x)
                                     or "分卷" in x for x in names):
            selected.append("archive")
        if any(x in question for x in ("计算机名", "主机名", "computername", "注册表")) or any(
                x in {"system", "ntuser.dat"} or x.endswith(".hive") for x in names):
            selected.extend(["archive", "windows"])
        if "pcap" in kinds or any(x.endswith((".pcap", ".pcapng")) for x in names):
            selected.append("pcap")
        if "sqlite" in kinds or any(x.endswith((".sqlite", ".sqlite3", ".db")) for x in names):
            selected.append("sqlite")
        if any(x in question for x in ("内存", "memory", "进程")) or any(x.endswith((".dmp", ".vmem")) for x in names):
            selected.append("memory")
        if kinds & {"aleapp", "ileapp"} or any(x in question for x in ("手机", "android", "ios", "iphone")):
            selected.append("mobile")
        if any(x in question for x in ("恢复", "删除文件", "recovery")):
            selected.append("recovery")
        if state in {"model_unavailable", "model_failed", "stopped_duplicate", "stopped_no_progress", "stopped_budget"}:
            selected.append("planning")
        if not selected:
            selected.append("triage")
    selected = list(dict.fromkeys(selected))
    inventory = _tool_inventory(settings) if inventory is None else inventory
    workflows = []
    for identity in selected:
        workflow = WORKFLOWS[identity]
        workflows.append({"id": identity, **workflow,
                          "tools": [_tool_info(x, settings, inventory) for x in workflow["tools"]]})
    frozen_limits = manifest.get("settings", {}).get("limits", {})
    budget = frozen_limits.get("snapshot_bytes", settings.limits.snapshot_bytes if settings else None)
    if type(budget) is not int or budget < 1:
        budget = None
    guidance = {"schema_version": 1, "needed": needed, "state": state, "reasons": reasons,
                "input_path": input_path, "snapshot_plan": manifest.get("snapshot_plan"),
                "snapshot_bytes": budget,
                "workflows": workflows}
    guidance["text"] = render_manual_guidance(guidance)
    return guidance


def render_manual_guidance(guidance):
    lines = ["# 人工操作指南", "", "本指南读取已保存的任务状态，未重新核验检材完整性；"
             "所列步骤待人工执行，不是取证结论，也没有自动运行所列软件。", ""]
    lines.extend(f"- {_literal(reason)}" for reason in guidance["reasons"])
    if guidance["input_path"]:
        lines.extend(["", "登记输入：" + _literal(guidance["input_path"])])
    if guidance["snapshot_bytes"] is not None:
        label = "当前配置" if guidance["state"] == "general" else "该案件"
        lines.append(f"{label}的副本总量配额：{guidance['snapshot_bytes']:,} 字节（"
                     f"{guidance['snapshot_bytes'] / 1024**3:.2f} GiB）。")
    if guidance["snapshot_plan"]:
        lines.append("复制前登记信息：" + _literal(guidance["snapshot_plan"]))
    if not guidance["needed"]:
        lines.extend(["", "本次状态和步骤没有触发人工接续；仍可在工作台打开通用指南。"])
    for workflow in guidance["workflows"]:
        lines.extend(["", "## " + workflow["title"], ""])
        for tool in workflow["tools"]:
            lines.append(f"- 工具：{tool['name']}；{tool['status']}。")
            if tool["path"]:
                lines.append("  已配置入口：" + _literal(tool["path"]))
            lines.append(f"  官方说明：{tool['official_url']}")
        lines.extend(f"{i}. {step}" for i, step in enumerate(workflow["steps"], 1))
        if workflow.get("commands"):
            lines.extend(["", "待替换路径的 PowerShell 示例（复制前先核对参数）：", "```powershell",
                          *workflow["commands"], "```"])
        lines.extend(["", "交回 Agent：", *["- " + text for text in workflow["exports"]]])
    lines.extend(["", "## 人工导出的交接记录", "",
                  "保留原镜像/检材摘要、设备标识、内部文件路径或偏移、导出文件摘要、工具版本、实际参数、时间与时区。",
                  "完成上述处理、确认来源可复核后，交回本题需要的小文件或原始报告，再创建分析任务。Agent 会校验交回文件；"
                  "原镜像到人工导出之间的来源链仍需操作者记录和复核，不代表已自动验证。",
                  "人工笔记、截图和本指南不能直接充当已通过引用校验的答案；partial、截断和失败记录继续保留。", ""])
    return "\n".join(lines)
