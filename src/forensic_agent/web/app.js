"use strict";
const $ = (id) => document.getElementById(id);
const token = document.querySelector('meta[name="session-token"]').content;
let tools = {}, currentCase = null, currentReport = "", modelName = "本地模型", maxQuestion = 1000;
let busy = false, finishedTask = null, polling = false, stopped = false;
let activeTaskId = null;
let liveTaskId = null, liveSignature = "";
let manualText = "", manualCase = null, manualRequest = 0, reportRequest = 0;
let nextQuestionCase = null;
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
  $("next-question-fields").disabled = value;
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
  for (const item of cases) {
    const entry = document.createElement("div"), row = document.createElement("div"), view = document.createElement("button");
    row.className = "case-row"; view.type = "button"; view.className = "case-item";
    const title = document.createElement("strong"), detail = document.createElement("small");
    title.textContent = item.question; detail.textContent = `${states[item.state] || item.state} · ${item.id}`; view.append(title, detail);
    view.addEventListener("click", () => { if (busy) return notice("请等待当前任务结束后再打开历史报告。"); showReport(item.id).catch(e => notice(e.message)); });
    const buttons = document.createElement("div"); buttons.className = "case-buttons";
    for (const [text, action] of [["继续当前题目", () => continueCase(item.id)], ["添加新题", () => chooseNewQuestion(item.id)]]) {
      const button = document.createElement("button"); button.type = "button"; button.className = "case-resume";
      button.textContent = text; button.disabled = !item.can_continue; button.addEventListener("click", action); buttons.append(button);
    }
    row.append(view, buttons); entry.append(row);
    for (const question of item.questions || []) {
      const button = document.createElement("button"); button.type = "button"; button.className = "case-question";
      button.textContent = `${question.id} · ${question.question}`; button.disabled = !question.has_report;
      button.addEventListener("click", () => { if (busy) return notice("请等待当前任务结束后再打开历史题目报告。"); showReport(item.id, false, question.id).catch(e => notice(e.message)); });
      entry.append(button);
    }
    $("case-list").append(entry);
  }
}
function chooseNewQuestion(id) {
  if (busy) return notice("请等待当前任务结束后再添加新题。");
  nextQuestionCase = id; $("next-question-case").textContent = `复用案件：${id}`;
  $("next-question-panel").hidden = false; $("next-question").focus();
}
function continueCase(id) {
  if (busy) return notice("请等待当前任务结束后再继续案件。");
  const mode = $("execution-mode").value;
  if (mode === "tool") return notice("继续案件请先选择“自动选择工具”或“规则模式”。");
  start({action:"continue", case:id, mode});
}
function inline(parent, text) {
  for (const part of text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)) { const tag = part.startsWith("`") && part.endsWith("`") ? "code" : part.startsWith("**") && part.endsWith("**") ? "strong" : null; if (tag) { const el = document.createElement(tag); el.textContent = part.slice(tag === "code" ? 1 : 2, tag === "code" ? -1 : -2); parent.append(el); } else parent.append(document.createTextNode(part)); }
}
function renderReport(text, root = $("report")) {
  root.replaceChildren(); const lines = text.split(/\r?\n/); let code = null, table = null;
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
async function showManualGuide(id = null, onlyIfNeeded = false) {
  const request = ++manualRequest;
  manualText = ""; manualCase = id;
  $("manual-download").disabled = true; $("manual-status").textContent = "正在读取人工步骤…";
  try {
    let data, fallback = "";
    try { data = await api(`/api/manual-guide${id ? `?case=${encodeURIComponent(id)}` : ""}`); }
    catch (error) {
      if (!id) throw error;
      data = await api("/api/manual-guide");
      fallback = `案件指南暂不可读：${error.message}。以下是通用步骤，请按实际输入选择。`;
    }
    if (request !== manualRequest) return;
    if (typeof data.text !== "string") throw new Error("服务没有返回指南文本");
    if (onlyIfNeeded && !data.needed && !fallback) { $("manual-panel").hidden = true; return; }
    manualText = data.text;
    manualCase = fallback ? null : id;
    $("manual-panel").hidden = false;
    $("manual-status").textContent = fallback || (id ? "根据保存的案件状态生成；不会自动执行这些操作。" : "通用指南，请按本题输入选择对应方向。");
    renderReport(manualText, $("manual-text")); $("manual-download").disabled = false;
  } catch (error) {
    if (request !== manualRequest) return;
    $("manual-panel").hidden = false; $("manual-text").replaceChildren();
    $("manual-status").textContent = `人工指南暂不可读：${error.message}。原任务诊断仍保留。`;
  }
}
async function showReport(id, fresh = false, question = null) {
  const request = ++reportRequest, guideAtStart = manualRequest;
  let data;
  try { data = await api(`/api/report?case=${encodeURIComponent(id)}${question ? `&question=${encodeURIComponent(question)}` : ""}`); }
  catch (error) {
    if (request !== reportRequest) return;
    if (guideAtStart === manualRequest) await showManualGuide(id);
    if (request !== reportRequest) return;
    throw error;
  }
  if (request !== reportRequest) return;
  currentCase = id; currentReport = data.text;
  $("output").hidden = false;
  $("empty-state").hidden = true; $("running-state").hidden = true; $("diagnostics").hidden = true;
  $("report").hidden = false; $("report-actions").hidden = false; $("report-meta").hidden = false;
  $("verify").hidden = Boolean(data.archived);
  $("report-meta").textContent = `${fresh ? "本次生成的报告" : "已保存报告 · 查看时未重新核验，可点击上方按钮复核"} · ${new Date(data.saved_at).toLocaleString("zh-CN")}\n${data.path}`;
  $("output-title").textContent = "取证报告";
  if (!fresh) { $("task-status").textContent = "历史报告"; $("task-status").className = "status"; }
  renderReport(data.text);
  if (data.archived) { ++manualRequest; manualText = ""; manualCase = null; $("manual-panel").hidden = true; $("manual-download").disabled = true; }
  else if (guideAtStart === manualRequest) await showManualGuide(id, true);
}
async function renderTask(task) {
  if (!task) return;
  const running = task.status === "running" || task.status === "cancelling";
  activeTaskId = running ? task.id : null;
  $("cancel-task").hidden = !running;
  $("cancel-task").disabled = task.status === "cancelling";
  $("cancel-task").textContent = task.status === "cancelling" ? "正在中止…" : "中止分析";
  $("output").hidden = false;
  setBusy(running);
  $("task-status").className = `status ${task.status}`;
  $("task-status").textContent = task.status === "cancelling" ? "正在中止" : task.status === "cancelled" ? "已中止" : task.status === "running" ? "正在执行" : task.status === "failed" ? states[task.result?.state] || "未正常完成" : "已完成";
  $("logs").replaceChildren(); for (const line of task.logs) { const li = document.createElement("li"); li.textContent = line; $("logs").append(li); }
  $("log-count").textContent = `${task.logs.length} 条记录`;
  $("running-state").hidden = !running;
  const sections = task.report_sections || [];
  const signature = JSON.stringify(sections);
  if (liveTaskId !== task.id || signature !== liveSignature) {
    liveTaskId = task.id; liveSignature = signature;
    $("live-sections").replaceChildren();
    for (const section of sections) {
      const block = document.createElement("section"), heading = document.createElement("h4");
      const status = document.createElement("p"), content = document.createElement("pre");
      block.className = "live-section"; heading.textContent = section.title;
      status.className = "help"; status.textContent = `${section.question_id} · ${section.status}`;
      content.textContent = section.text; block.append(heading, status, content); $("live-sections").append(block);
    }
  }
  $("live-report").hidden = !sections.length;
  $("live-status").textContent = running ? "阶段内容仍待核验；工具输出不是最终答案，页面约每秒更新。" :
    task.status === "cancelled" ? "任务已中止。以下保留已收到的阶段内容，未完成最终核验，不是最终答案。" :
    task.status === "failed" || task.result?.state === "evidence_changed" ? "本次未正常完成或完整性未通过；阶段内容仅供诊断，以最终报告的限制为准。" :
    "阶段记录已保留，最终答案和限制以下方完整报告为准。";
  if (running || finishedTask === task.id) return;
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
  else { $("diagnostics").hidden = false; $("diagnostics").textContent = JSON.stringify(task.result || {error:task.error}, null, 2); $("output-title").textContent = task.action === "doctor" ? "环境检查结果" : "任务结果"; if (["failed", "cancelled"].includes(task.status)) await showManualGuide(); }
  try { renderCases((await api("/api/cases")).cases); } catch (error) { notice(`无法更新历史案件：${error.message}`); }
}
async function start(data) {
  if (busy) return;
  notice(); setBusy(true);
  try {
    const result = await api("/api/start", data);
    $("next-question-panel").hidden = true; nextQuestionCase = null;
    currentCase = null; currentReport = ""; $("report-actions").hidden = true; $("report").hidden = true; $("report-meta").hidden = true; $("diagnostics").hidden = true; $("empty-state").hidden = true;
    $("live-report").hidden = true; $("live-sections").replaceChildren(); liveTaskId = null; liveSignature = "";
    ++manualRequest; ++reportRequest; manualText = ""; manualCase = null; $("manual-panel").hidden = true; $("manual-download").disabled = true;
    $("output-title").textContent = data.action === "doctor" ? "环境检查" : data.action === "continue" ? "继续案件" : data.action === "new_question" ? "分析新题" : "分析结果";
    $("progress-panel").open = true;
    await renderTask(result.task);
  } catch (error) { notice(error.message); setBusy(false); }
}
async function poll() {
  if (polling || stopped) return;
  polling = true;
  try { const data = await api("/api/task"); connectionNotice(); if (data.task && (["running", "cancelling"].includes(data.task.status) || data.task.id !== finishedTask)) await renderTask(data.task); }
  catch (error) { connectionNotice(`本地服务连接中断：${error.message}。请确认启动器仍在运行，连接恢复后会自动更新。`); }
  finally { polling = false; }
}
$("execution-mode").addEventListener("change", modeChanged);
$("question").addEventListener("input", questionChanged);
$("next-question-form").addEventListener("submit", event => {
  event.preventDefault(); if (busy || !nextQuestionCase) return;
  const question = $("next-question").value.trim(), mode = $("execution-mode").value;
  if (!question || question.length > maxQuestion) return notice(`请输入 1..${maxQuestion} 字符的新题目；已保留完整输入。`);
  if (mode === "tool") return notice("添加新题请先选择自动选择工具或规则模式。");
  start({action:"new_question", case:nextQuestionCase, question, mode});
});
$("cancel-next-question").addEventListener("click", () => { nextQuestionCase = null; $("next-question-panel").hidden = true; });
$("cancel-task").addEventListener("click", async () => {
  const id = activeTaskId;
  if (!id || $("cancel-task").disabled) return;
  $("cancel-task").disabled = true;
  try {
    const result = await api("/api/cancel", {id});
    if (activeTaskId === id && result.task?.id === id) await renderTask(result.task);
  } catch (error) { if (activeTaskId === id) { notice(`中止请求失败：${error.message}；任务可能仍在运行。`); $("cancel-task").disabled = false; } }
});
$("tool-id").addEventListener("change", toolChanged);
$("analysis-form").addEventListener("submit", event => {
  event.preventDefault(); let params = {}; const mode = $("execution-mode").value;
  if (mode === "tool") { try { params = JSON.parse($("tool-params").value); if (!params || typeof params !== "object" || Array.isArray(params)) throw new Error(); } catch { notice("工具参数必须是有效的 JSON 对象，例如 {\"keyword\":\"FLAG\"}。"); $("advanced").open = true; $("tool-params").focus(); return; } }
  start({action:mode === "tool" ? "tool" : "analyze", evidence:$("evidence").value, question:$("question").value, mode:mode === "tool" ? "model" : mode, tool_id:$("tool-id").value, params});
});
for (const kind of ["file","directory"]) $("pick-" + kind).addEventListener("click", async () => { const button = $("pick-" + kind); button.disabled = true; notice("请在系统弹出的选择窗口中选择检材。", true); try { const data = await api("/api/pick", {kind}); if (data.path) $("evidence").value = data.path; notice(); } catch (error) { notice(error.message); } finally { button.disabled = false; } });
$("doctor").addEventListener("click", () => start({action:"doctor"}));
$("manual-guide").addEventListener("click", async () => { await showManualGuide(); $("manual-text").focus(); });
$("manual-download").addEventListener("click", () => { if (!manualText) return; const url = URL.createObjectURL(new Blob([manualText], {type:"text/markdown;charset=utf-8"})), link = document.createElement("a"); link.href = url; link.download = `${manualCase || "general"}-manual-guide.md`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
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
