import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import test from 'node:test';

const clientCode = await readFile(new URL('../src/forensic_agent/web/app.js', import.meta.url), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

async function readyClient() {
  const nodes = new Map(), requests = [];
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {
      value: id === 'execution-mode' ? 'model' : '', textContent:'', hidden:true, disabled:false,
      listeners:{}, classList:{toggle(){}}, addEventListener(name, callback){this.listeners[name] = callback;},
      querySelector(){return node(id + '-span');}, setCustomValidity(value){this.validityMessage = value;},
      append(){}, replaceChildren(){}, focus(){},
    });
    return nodes.get(id);
  };
  const context = vm.createContext({
    document:{getElementById:node, querySelector:() => ({content:'session'}),
      createElement:tag => node('created-' + tag), createTextNode:value => ({textContent:value})},
    setInterval(){}, setTimeout(){},
    fetch:async (url, options) => {
      let result = {};
      if (url === '/api/bootstrap') result = {tools:{}, model:'local-model', max_question:1000,
        work_dir:'C:/cases', cases:[], sample:'C:/evidence/sample.txt', task:null};
      if (url === '/api/start') {
        requests.push(JSON.parse(options.body));
        result = {task:{id:'task-1',status:'running',logs:[]}};
      }
      return {ok:true,json:async () => result};
    },
  });
  vm.runInContext(clientCode, context);
  await settle();
  return {node,context,requests};
}

test('default form sends the complete question to the model without choosing a tool', async () => {
  const {node,requests} = await readyClient();
  const question = '题目：统计聊天记录。\n时区：UTC+8。\n要求：回答 messages 表记录数并引用依据。';
  node('evidence').value = 'C:/evidence/chat.sqlite';
  node('question').value = question;
  node('analysis-form').listeners.submit({preventDefault(){}});
  await settle();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].action, 'analyze');
  assert.equal(requests[0].mode, 'model');
  assert.equal(requests[0].question, question);
  assert.equal(node('output').hidden, false);
});

test('sample restores model planning even after a rules selection', async () => {
  const {node,requests} = await readyClient();
  node('execution-mode').value = 'rules';
  node('sample').listeners.click();
  assert.equal(node('execution-mode').value, 'model');
  assert.match(node('question').value, /FLAG/);
  node('analysis-form').listeners.submit({preventDefault(){}});
  await settle();
  assert.equal(requests[0].mode, 'model');
});

test('continue sends only a case identity and selected planning mode', async () => {
  const {node,context,requests} = await readyClient();
  node('execution-mode').value = 'rules';
  vm.runInContext('continueCase("case-48g")', context);
  await settle();
  assert.deepEqual(requests, [{action:'continue',case:'case-48g',mode:'rules'}]);
  assert.equal(node('output-title').textContent, '继续案件');
});

test('new question uses the selected case without an evidence path', async () => {
  const {node,context,requests} = await readyClient();
  vm.runInContext('chooseNewQuestion("existing-case")', context);
  node('next-question').value = '下一题：计算机名称是什么？';
  node('next-question-form').listeners.submit({preventDefault(){}});
  await settle();
  assert.deepEqual(requests, [{action:'new_question',case:'existing-case',question:'下一题：计算机名称是什么？',mode:'model'}]);
  assert.equal(node('output-title').textContent, '分析新题');
  assert.equal(node('next-question-panel').hidden, true);
});

test('invalid new question stays intact and cancellation sends no task', async () => {
  const {node,context,requests} = await readyClient();
  vm.runInContext('chooseNewQuestion("existing-case")', context);
  node('next-question').value = '题'.repeat(1001);
  node('next-question-form').listeners.submit({preventDefault(){}});
  assert.equal(requests.length, 0);
  assert.equal(node('next-question').value.length, 1001);
  assert.equal(node('next-question-panel').hidden, false);
  node('cancel-next-question').listeners.click();
  assert.equal(node('next-question-panel').hidden, true);
  assert.equal(requests.length, 0);
});

test('archived question report cannot regenerate the current question or show its guide', async () => {
  const {node,context} = await readyClient();
  const urls = [];
  context.fetch = async url => {
    urls.push(url);
    return {ok:true,json:async () => ({text:'# 上一题报告',archived:true,path:'history/report.md',saved_at:'now'})};
  };
  await vm.runInContext('showReport("case-1", false, "q0001")', context);
  assert.deepEqual(urls, ['/api/report?case=case-1&question=q0001']);
  assert.equal(node('verify').hidden, true);
  assert.equal(node('manual-panel').hidden, true);
});

test('missing failure report preserves the intake cause and displays diagnostics', async () => {
  const {node,context} = await readyClient();
  context.fetch = async url => ({
    ok:!url.startsWith('/api/report'),
    json:async () => url.startsWith('/api/report') ? {error:'report.md 不存在'} : {cases:[]},
  });
  await vm.runInContext(`renderTask({id:'failed-intake',status:'failed',case:'case-1',action:'analyze',
    error:'检材总量 48 GiB 超过副本上限 10 GiB',
    result:{state:'intake_failed'},logs:['任务结束，退出码 2。']})`, context);
  assert.match(node('notice').textContent, /48 GiB.*10 GiB/);
  assert.match(node('notice').textContent, /报告/);
  assert.equal(node('diagnostics').hidden, false);
  assert.match(node('diagnostics').textContent, /intake_failed/);
  assert.equal(node('report-actions').hidden, true);
  assert.equal(node('task-status').textContent, '检材登记失败');
});

test('failure guide survives a missing report without replacing the original error', async () => {
  const {node,context} = await readyClient();
  context.fetch = async url => ({
    ok:!url.startsWith('/api/report'),
    json:async () => url.startsWith('/api/report') ? {error:'报告不存在'} :
      url.startsWith('/api/manual-guide') ? {needed:true,text:'# 人工操作指南\n用 FTK Imager 导出 SYSTEM。'} : {cases:[]},
  });
  await vm.runInContext(`renderTask({id:'manual-failure',status:'failed',case:'case-2',action:'analyze',
    error:'工作磁盘空间不足',result:{state:'intake_failed'},logs:[]})`, context);
  assert.match(node('notice').textContent, /工作磁盘空间不足/);
  assert.equal(node('manual-panel').hidden, false);
  assert.equal(node('manual-download').disabled, false);
  assert.match(vm.runInContext('manualText', context), /FTK Imager/);
  assert.equal(vm.runInContext('manualCase', context), 'case-2');
});

test('general fallback and help errors do not overwrite the task diagnostic', async () => {
  const {node,context} = await readyClient();
  let generalWorks = true;
  context.fetch = async url => {
    if (url.startsWith('/api/report')) return {ok:false,json:async () => ({error:'报告不可读'})};
    if (url.includes('/api/manual-guide?')) return {ok:false,json:async () => ({error:'案件记录不可读'})};
    if (url === '/api/manual-guide') {
      if (!generalWorks) throw new Error('help service unavailable');
      return {ok:true,json:async () => ({needed:true,text:'# 通用人工操作指南'})};
    }
    return {ok:true,json:async () => ({cases:[]})};
  };
  await vm.runInContext(`renderTask({id:'fallback',status:'failed',case:'case-3',action:'analyze',
    error:'原始容量错误',result:{state:'intake_failed'},logs:[]})`, context);
  assert.match(node('notice').textContent, /原始容量错误/);
  assert.match(node('manual-status').textContent, /案件记录不可读.*通用步骤/);
  assert.equal(vm.runInContext('manualCase', context), null);
  generalWorks = false;
  await vm.runInContext('showManualGuide()', context);
  assert.match(node('manual-status').textContent, /help service unavailable/);
  assert.match(node('notice').textContent, /原始容量错误/);
  assert.equal(node('manual-download').disabled, true);
});

test('late help response cannot replace newer guidance and contents remain text', async () => {
  const {node,context} = await readyClient();
  let resolveOld;
  context.fetch = async url => {
    if (url.includes('case=old')) return new Promise(resolve => { resolveOld = resolve; });
    return {ok:true,json:async () => ({needed:true,text:'# 新指南\n<script>globalThis.injected=true</script>'})};
  };
  const old = vm.runInContext('showManualGuide("old")', context);
  await vm.runInContext('showManualGuide("new")', context);
  resolveOld({ok:true,json:async () => ({needed:true,text:'旧指南'})});
  await old;
  assert.match(vm.runInContext('manualText', context), /新指南/);
  assert.equal(vm.runInContext('manualCase', context), 'new');
  assert.equal(context.injected, undefined);
  assert.equal(node('manual-panel').hidden, false);
});

test('historical case without a report still loads its case guidance', async () => {
  const {node,context} = await readyClient();
  context.fetch = async url => ({ok:!url.startsWith('/api/report'), json:async () =>
    url.startsWith('/api/report') ? {error:'历史报告不可读'} : {needed:true,text:'# 历史案件人工步骤'}});
  await assert.rejects(vm.runInContext('showReport("history")', context), /历史报告不可读/);
  assert.equal(node('manual-panel').hidden, false);
  assert.equal(vm.runInContext('manualCase', context), 'history');
  assert.match(vm.runInContext('manualText', context), /历史案件/);
});

test('a slow report cannot replace subsequently selected general guidance', async () => {
  const {node,context} = await readyClient();
  let resolveReport;
  context.fetch = async url => {
    if (url.startsWith('/api/report')) return new Promise(resolve => {resolveReport=resolve;});
    return {ok:true,json:async () => ({needed:true,text:'# 用户主动打开的通用指南'})};
  };
  const report = vm.runInContext('showReport("old-case")', context);
  await vm.runInContext('showManualGuide()', context);
  resolveReport({ok:true,json:async () => ({id:'old-case',text:'# 旧报告',path:'report.md',saved_at:'now'})});
  await report;
  assert.equal(vm.runInContext('manualCase', context), null);
  assert.match(vm.runInContext('manualText', context), /通用指南/);
  assert.equal(node('manual-panel').hidden, false);
});

for (const next of ['history', 'new-task']) test(`stale failure after a slow guide preserves ${next}`, async () => {
  const {node,context} = await readyClient();
  let resolveGuide;
  context.fetch = async url => {
    if (url === '/api/report?case=old') return {ok:false,json:async () => ({error:'old report missing'})};
    if (url === '/api/manual-guide?case=old') return new Promise(resolve => {resolveGuide=resolve;});
    if (url === '/api/start') return {ok:true,json:async () => ({task:{id:'new-task',status:'running',logs:[]}})};
    if (url.startsWith('/api/report')) return {ok:true,json:async () => ({text:'# Report B',path:'B/report.md',saved_at:'now'})};
    if (url.startsWith('/api/manual-guide')) return {ok:true,json:async () => ({needed:true,text:'# Guide B'})};
    return {ok:true,json:async () => ({cases:[]})};
  };
  const old = vm.runInContext(`renderTask({id:'old-task',case:'old',status:'failed',action:'analyze',
    error:'old original error',result:{state:'intake_failed'},logs:[]})`, context);
  await settle();
  assert.equal(typeof resolveGuide, 'function');
  if (next === 'history') await vm.runInContext('showReport("B")', context);
  else await vm.runInContext('start({action:"analyze"})', context);
  resolveGuide({ok:true,json:async () => ({needed:true,text:'# Old guide'})});
  await old;
  assert.equal(node('diagnostics').hidden, true);
  if (next === 'history') {
    assert.equal(node('report').hidden, false);
    assert.equal(node('report-actions').hidden, false);
    assert.equal(node('output-title').textContent, '取证报告');
    assert.equal(vm.runInContext('currentCase', context), 'B');
    assert.equal(vm.runInContext('manualCase', context), 'B');
    assert.equal(vm.runInContext('manualText', context), '# Guide B');
  } else {
    assert.equal(node('running-state').hidden, false);
    assert.equal(node('manual-panel').hidden, true);
    assert.equal(node('output-title').textContent, '分析结果');
    assert.equal(node('notice').textContent, '');
    assert.equal(node('input-fields').disabled, true);
  }
});

test('long pasted text stays intact and manual tool mode clears hidden question validation', async () => {
  const {node} = await readyClient();
  const longQuestion = '长题干'.repeat(400);
  node('question').value = longQuestion;
  node('question').listeners.input();
  assert.equal(node('question').value, longQuestion);
  assert.match(node('question').validityMessage, /超过 1000/);
  node('execution-mode').value = 'tool';
  node('execution-mode').listeners.change();
  assert.equal(node('question').validityMessage, '');
  assert.equal(node('question').required, false);
  assert.equal(node('tool-fields').hidden, false);
});

test('temporary disconnection clears on recovery and preserves the task error', async () => {
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {textContent:'', hidden:true, className:'', addEventListener(){}});
    return nodes.get(id);
  };
  let connected = false;
  const context = vm.createContext({
    document:{getElementById:node, querySelector:() => ({content:'test-session'}), querySelectorAll:() => []},
    setInterval(){}, setTimeout(){},
    fetch:async () => {
      if (!connected) throw new Error('temporary network failure');
      return {ok:true, json:async () => ({task:null})};
    },
  });
  const code = await readFile(new URL('../src/forensic_agent/web/app.js', import.meta.url), 'utf8');
  vm.runInContext(code, context);
  await new Promise(resolve => setImmediate(resolve));
  vm.runInContext('notice("证据完整性检查未通过")', context);
  await vm.runInContext('poll()', context);
  assert.equal(node('connection-notice').hidden, false);
  assert.match(node('connection-notice').textContent, /连接中断/);
  assert.equal(node('notice').textContent, '证据完整性检查未通过');
  connected = true;
  await vm.runInContext('poll()', context);
  assert.equal(node('connection-notice').hidden, true);
  assert.equal(node('connection-notice').textContent, '');
  assert.equal(node('notice').textContent, '证据完整性检查未通过');
  assert.equal(node('notice').hidden, false);
});
