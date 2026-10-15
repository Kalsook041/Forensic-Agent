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
