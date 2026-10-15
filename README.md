# Forensic Agent

Windows 本地取证助手。每个案件会把检材复制到独立目录并校验 SHA256；分析工具处理副本。模型给出的解释是待人工核对的线索。

## 环境

- Windows 10/11 x64、CPython 3.12 x64、PowerShell。
- 命令行和图形界面可不接模型运行；自然语言分析需要本机 Ollama 和配置的模型（默认 `qwen3.5:4b`）。
- ExifTool、Wireshark、7-Zip、EZTools 等只在使用对应适配器时需要。运行 `.\forensic.ps1 doctor` 查看检测结果。

首次运行前，编辑 `config/default.toml`：把 `work_dir` 改为可写的案件保存目录，并把要使用的外部工具路径改成当前电脑上的绝对路径。默认配置含有开发机路径。

## 安装与快速验证

在项目根目录运行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\forensic.ps1 doctor
$evidence = Join-Path $PWD 'examples\检材\线索.txt'
.\forensic.ps1 tool search --evidence $evidence --params '{"keyword":"FLAG"}'
```

样例应找到第二行 `FLAG-TEXT-2026`。图形界面运行 `.\forensic-gui.ps1`，或双击 `启动取证界面.cmd`。界面仅监听本机地址。

## 使用本地模型（可选）

先安装 Ollama，并在联网时下载模型；标签要与 `config/default.toml` 的 `[model].name` 一致（默认 `qwen3.5:4b`）。准备好模型后运行：

```powershell
ollama pull qwen3.5:4b
.\scripts\start-ollama.ps1
.\forensic.ps1 analyze --evidence $evidence --question '搜索关键词 FLAG，并引用原文行'
```

## 离线安装（可选）

仓库内的 wheelhouse 适用于 CPython 3.12 x64。创建离线 Python 环境：

```powershell
.\scripts\setup-offline.ps1
.\forensic.ps1 doctor
```

Python 包以外的工具、Ollama 和模型须提前准备。安装脚本不会覆盖已有环境。要验证断网冷启动，先退出已有 Ollama 服务并手动断开外部网络，再运行：

```powershell
.\scripts\start-ollama.ps1
.\.venv-offline\Scripts\python.exe scripts\offline-acceptance.py
```

更多适配器开发说明见 [`docs/ADAPTERS.md`](docs/ADAPTERS.md)，验证记录见 [`docs/VALIDATION.md`](docs/VALIDATION.md)。
