"use strict";
const $ = (id) => document.getElementById(id);
const token = document.querySelector('meta[name="session-token"]').content;
let tools = {}, currentCase = null, currentReport = "", modelName = "本地模型", maxQuestion = 1000;
let busy = false, finishedTask = null, polling = false, stopped = false;
const names = {inventory:"文件清单与类型",hash:"SHA256 哈希",search:"文本搜索",metadata:"文件元数据",archive:"压缩包",pcap:"网络流量",sqlite:"SQLite 数据库",evtx:"Windows 事件日志",evtxecmd:"EZTools 事件日志"};
const defaults = {search:{keyword:"FLAG"},metadata:{fields:["Author"]},archive:{action:"list"},pcap:{protocol:"overview"},sqlite:{query:"schema"}};
const states = {completed:"分析完成",completed_without_model:"规则模式完成",tool_completed:"工具完成",evidence_changed:"完整性检查未通过",insufficient_evidence:"证据不足",model_unavailable:"模型不可用",tool_failed:"工具失败",model_failed:"模型响应失败",cancelled:"已取消",ready:"已登记",intake_failed:"检材登记失败",stopped_budget:"达到步数上限",stopped_duplicate:"重复调用已停止",stopped_no_progress:"无新增证据已停止"};

function notice(message = "", info = false) { $("notice").textContent = message; $("notice").hidden = !message; $("notice").className = info ? "info" : ""; }
function connectionNotice(message = "") { $("connection-notice").textContent = message; $("connection-notice").hidden = !message; }
async function api(path, data) {
  const response = await fetch(path, {method:data === undefined ? "GET" : "POST", headers:{"X-Session-Token":token, ...(data === undefined ? {} : {"Content-Type":"application/json"})}, ...(data === undefined ? {} : {body:JSON.stringify(data)})});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `请求失败（${response.status}）`);
  return result;
}
function setBusy(value) {
  busy = value; $("input-fields").disabled = value; $("doctor").disabled = value;
  $("shutdown").disabled = value; $("verify").disabled = value;
  $("start").querySelector("span").textContent = value ? "正在执行，请稍候…" : $("execution-mode").value === "tool" ? "运行指定工具" : "开始分析";
}
function modeChanged() {
  const mode = $("execution-mode").value;
  $("analysis-fields").hidden = mode === "tool"; $("tool-fields").hidden = mode !== "tool";
  $("question").required = mode !== "tool";
  $("start").querySelector("span").textContent = mode === "tool" ? "运行指定工具" : "开始分析";
  $("model-name").textContent = mode === "model" ? `${modelName} 自动选择工具` : mode === "rules" ? "基础规则模式 · 不使用模型规划" : "手动工具模式";
  questionChanged();
}
function questionChanged() {
  const count = $("question").value.length, overLimit = count > maxQuestion;
  $("question-count").textContent = `${count} / ${maxQuestion}`;
  $("question-count").classList.toggle("over-limit", overLimit);
  $("question").setCustomValidity(overLimit && $("execution-mode").value !== "tool" ? `题目超过 ${maxQuestion} 字符，请拆分问题；已保留完整输入。` : "");
}
function toolChanged() {
  const id = $("tool-id").value, tool = tools[id];
  $("tool-description").textContent = tool?.description || "";
  $("tool-params").value = JSON.stringify(defaults[id] || {}, null, 2);
  $("tool-schema").textContent = JSON.stringify(tool?.parameters || {}, null, 2);
}
function renderCases(cases) {
  $("case-count").textContent = cases.length;
  $("case-list").replaceChildren();
  if (!cases.length) { const p = document.createElement("p"); p.className = "help"; p.textContent = "尚无案件。完成一次分析后会显示在这里。"; $("case-list").append(p); }
  for (const item of cases) { const button = document.createElement("button"); button.type = "button"; button.className = "case-item"; const title = document.createElement("strong"), detail = document.createElement("small"); title.textContent = item.question; detail.textContent = `${states[item.state] || item.state} · ${item.id}`; button.append(title, detail); button.addEventListener("click", () => { if (busy) return notice("请等待当前任务结束后再打开历史报告。"); showReport(item.id).catch(e => notice(e.message)); }); $("case-list").append(button); }
}
function inline(parent, text) {
  for (const part of text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)) { const tag = part.startsWith("`") && part.endsWith("`") ? "code" : part.startsWith("**") && part.endsWith("**") ? "strong" : null; if (tag) { const el = document.createElement(tag); el.textContent = part.slice(tag === "code" ? 1 : 2, tag === "code" ? -1 : -2); parent.append(el); } else parent.append(document.createTextNode(part)); }
}
function renderReport(text) {
  const root = $("report"); root.replaceChildren(); const lines = text.split(/\r?\n/); let code = null, table = null;
  for (const line of lines) {
    if (line.startsWith("```")) { if (code) code = null; else { code = document.createElement("pre"); root.append(code); } table = null; continue; }
    if (code) { code.textContent += line + "\n"; continue; }
    if (line.startsWith("|")) {
      if (/^\|[\s:|\-]+\|?$/.test(line)) continue;
      if (!table) { const wrap = document.createElement("div"); wrap.className = "table-scroll"; table = document.createElement("table"); wrap.append(table); root.append(wrap); }
      const row = document.createElement("tr"), heading = !table.children.length;
      for (const cell of line.replace(/^\||\|$/g, "").split("|")) { const el = document.createElement(heading ? "th" : "td"); inline(el, cell.trim()); row.append(el); } table.append(row); continue;
    }
    table = null;
    if (!line.trim()) continue;
    const heading = line.match(/^(#{1,3})\s+(.*)$/), el = document.createElement(heading ? `h${heading[1].length}` : "p"); inline(el, heading ? heading[2] : line); root.append(el);
  }
}
async function showReport(id, fresh = false) {
  const data = await api(`/api/report?case=${encodeURIComponent(id)}`);
  currentCase = id; currentReport = data.text;
  $("output").hidden = false;
  $("empty-state").hidden = true; $("running-state").hidden = true; $("diagnostics").hidden = true;
  $("report").hidden = false; $("report-actions").hidden = false; $("report-meta").hidden = false;
  $("report-meta").textContent = `${fresh ? "本次生成的报告" : "已保存报告 · 查看时未重新核验，可点击上方按钮复核"} · ${new Date(data.saved_at).toLocaleString("zh-CN")}\n${data.path}`;
  $("output-title").textContent = "取证报告";
  if (!fresh) { $("task-status").textContent = "历史报告"; $("task-status").className = "status"; }
  renderReport(data.text);
}
async function renderTask(task) {
  if (!task) return;
  $("output").hidden = false;
  setBusy(task.status === "running");
  $("task-status").className = `status ${task.status}`;
  $("task-status").textContent = task.status === "running" ? "正在执行" : task.status === "failed" ? states[task.result?.state] || "未正常完成" : "已完成";
  $("logs").replaceChildren(); for (const line of task.logs) { const li = document.createElement("li"); li.textContent = line; $("logs").append(li); }
  $("log-count").textContent = `${task.logs.length} 条记录`;
  $("running-state").hidden = task.status !== "running";
  if (task.status === "running" || finishedTask === task.id) return;
  finishedTask = task.id;
  if (task.error) notice(task.error);
  if (task.case) {
    try { await showReport(task.case, true); }
    catch (error) {
      const cause = task.error || task.result?.error || "任务已结束";
      notice(`${cause}\n报告未生成或暂不可读：${error.message}。案件 ID：${task.case}`);
      $("report").hidden = true; $("report-actions").hidden = true; $("report-meta").hidden = true;
      $("diagnostics").hidden = false;
      $("diagnostics").textContent = JSON.stringify({...task.result, error:cause, case:task.case, report_error:error.message}, null, 2);
      $("output-title").textContent = "任务失败详情";
    }
  }
  else { $("diagnostics").hidden = false; $("diagnostics").textContent = JSON.stringify(task.result || {error:task.error}, null, 2); $("output-title").textContent = task.action === "doctor" ? "环境检查结果" : "任务结果"; }
  try { renderCases((await api("/api/cases")).cases); } catch (error) { notice(`无法更新历史案件：${error.message}`); }
}
async function start(data) {
  if (busy) return;
  notice(); setBusy(true);
  try {
    const result = await api("/api/start", data);
    currentCase = null; currentReport = ""; $("report-actions").hidden = true; $("report").hidden = true; $("report-meta").hidden = true; $("diagnostics").hidden = true; $("empty-state").hidden = true;
    $("output-title").textContent = data.action === "doctor" ? "环境检查" : "分析结果";
    $("progress-panel").open = true;
    await renderTask(result.task);
  } catch (error) { notice(error.message); setBusy(false); }
}
async function poll() {
  if (polling || stopped) return;
  polling = true;
  try { const data = await api("/api/task"); connectionNotice(); if (data.task && (data.task.status === "running" || data.task.id !== finishedTask)) await renderTask(data.task); }
  catch (error) { connectionNotice(`本地服务连接中断：${error.message}。请确认启动器仍在运行，连接恢复后会自动更新。`); }
  finally { polling = false; }
}
$("execution-mode").addEventListener("change", modeChanged);
$("question").addEventListener("input", questionChanged);
$("tool-id").addEventListener("change", toolChanged);
$("analysis-form").addEventListener("submit", event => {
  event.preventDefault(); let params = {}; const mode = $("execution-mode").value;
  if (mode === "tool") { try { params = JSON.parse($("tool-params").value); if (!params || typeof params !== "object" || Array.isArray(params)) throw new Error(); } catch { notice("工具参数必须是有效的 JSON 对象，例如 {\"keyword\":\"FLAG\"}。"); $("advanced").open = true; $("tool-params").focus(); return; } }
  start({action:mode === "tool" ? "tool" : "analyze", evidence:$("evidence").value, question:$("question").value, mode:mode === "tool" ? "model" : mode, tool_id:$("tool-id").value, params});
});
for (const kind of ["file","directory"]) $("pick-" + kind).addEventListener("click", async () => { const button = $("pick-" + kind); button.disabled = true; notice("请在系统弹出的选择窗口中选择检材。", true); try { const data = await api("/api/pick", {kind}); if (data.path) $("evidence").value = data.path; notice(); } catch (error) { notice(error.message); } finally { button.disabled = false; } });
$("doctor").addEventListener("click", () => start({action:"doctor"}));
$("verify").addEventListener("click", () => { if (currentCase) start({action:"report", case:currentCase}); });
$("download").addEventListener("click", () => { const blob = new Blob([currentReport], {type:"text/markdown;charset=utf-8"}), url = URL.createObjectURL(blob), link = document.createElement("a"); link.href = url; link.download = `${currentCase || "forensic"}-report.md`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
$("shutdown").addEventListener("click", async () => { try { const data = await api("/api/shutdown", {}); stopped = true; setBusy(true); notice(data.message, true); } catch (error) { notice(error.message); } });
async function init() {
  try {
    const data = await api("/api/bootstrap"); tools = data.tools;
    $("workdir").textContent = `案件保存于 ${data.work_dir}`; modelName = data.model; maxQuestion = data.max_question;
    for (const [id, label] of Object.entries(names)) if (tools[id]) { const option = document.createElement("option"); option.value = id; option.textContent = `${label}${tools[id].available ? "" : "（需检查环境）"}`; $("tool-id").append(option); }
    toolChanged(); renderCases(data.cases); modeChanged(); setBusy(false);
    $("sample").hidden = !data.sample;
    $("sample").addEventListener("click", () => { $("execution-mode").value = "model"; modeChanged(); $("evidence").value = data.sample; $("question").value = '题目：这份文本记录中包含 FLAG 的完整原始文本行是什么？请给出行号和检材来源。'; questionChanged(); notice("已填入合成示例，点击“开始分析”后由模型自动选择工具。", true); });
    if (data.task) { $("empty-state").hidden = true; await renderTask(data.task); }
    setInterval(poll, 1000);
  } catch (error) { notice(`界面初始化失败：${error.message}。请刷新页面或重新运行启动器。`); }
}
init();
