// Drives the headless Chromium next to it, for `sv run`. Node's standard library only.
//
// It shares Chromium's network (`--network container:<browser>`), so it reaches the DevTools port
// on 127.0.0.1 and the app by its name on the fenced network, and nothing else. It reads one job
// from the environment and prints one line of JSON: the result of each action, in order.
//
// SV_JOB = base64 of {"app": "http://app:8080", "cookies": [[name, value]], "actions": [...]}
// Actions:
//   {"goto": "/path"}                     -> {"status": 200, "path": "/where/it/ended"}
//   {"fill": "/path", "text": "..."}      -> {"status", "found": bool, "after": {"status", "path"}}
//   {"eval": "expression"}                -> {"value": ...}
//   {"wait": 500}                         -> {}

const job = JSON.parse(Buffer.from(process.env.SV_JOB || '', 'base64').toString('utf8'));
const DEVTOOLS = 'http://127.0.0.1:9223';
const LOAD_MS = 10000;
// However the page behaves, the job ends: what was answered so far is printed, and `sv` counts a
// short list as the browser not having finished.
const JOB_MS = 120000;
const results = [];
setTimeout(() => {
  console.log(JSON.stringify(results));
  process.exit(0);
}, JOB_MS).unref();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function devtools() {
  for (let i = 0; i < 40; i++) {
    try {
      const v = await (await fetch(`${DEVTOOLS}/json/version`)).json();
      return v.webSocketDebuggerUrl.replace(/^ws:\/\/[^/]+/, 'ws://127.0.0.1:9223');
    } catch {
      await sleep(250);
    }
  }
  throw new Error('the browser did not answer');
}

const ws = new WebSocket(await devtools());
let next = 0;
const waiting = new Map();
const listeners = new Set();
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && waiting.has(d.id)) {
    waiting.get(d.id)(d);
    waiting.delete(d.id);
  } else {
    for (const l of listeners) l(d);
  }
};
await new Promise((resolve, reject) => {
  ws.onopen = resolve;
  ws.onerror = reject;
});
const send = (method, params = {}, sessionId) =>
  new Promise((resolve) => {
    const id = ++next;
    waiting.set(id, resolve);
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });

const { result: { browserContextId } } = await send('Target.createBrowserContext');
const { result: { targetId } } = await send('Target.createTarget', { url: 'about:blank', browserContextId });
const { result: { sessionId } } = await send('Target.attachToTarget', { targetId, flatten: true });
const page = (method, params) => send(method, params, sessionId);
await page('Page.enable');
await page('Network.enable');

for (const [name, value] of job.cookies || []) {
  await page('Network.setCookie', { name, value, url: job.app, path: '/' });
}

// The status of the last page the tab loaded, and whether its load has finished.
let status = 0;
let loaded = false;
listeners.add((d) => {
  if (d.sessionId !== sessionId) return;
  if (d.method === 'Network.responseReceived' && d.params.type === 'Document') {
    status = d.params.response.status;
  }
  if (d.method === 'Page.loadEventFired') loaded = true;
});

async function settle() {
  const until = Date.now() + LOAD_MS;
  while (!loaded && Date.now() < until) await sleep(50);
  await sleep(300);
}

async function where() {
  const r = await page('Runtime.evaluate', { expression: 'location.pathname + location.search', returnByValue: true });
  return r.result?.result?.value ?? '';
}

async function goto(path) {
  status = 0;
  loaded = false;
  await page('Page.navigate', { url: new URL(path, job.app).href });
  await settle();
  return { status, path: await where() };
}

// Types into the first box a person would type text into, in the first form that has one, and
// submits that form the way its button would.
const FILL = (text) => `(() => {
  const boxes = 'textarea, input:not([type]), input[type=text], input[type=search]';
  for (const form of document.forms) {
    const box = form.querySelector(boxes);
    if (!box) continue;
    box.value = ${JSON.stringify(text)};
    box.dispatchEvent(new Event('input', { bubbles: true }));
    if (form.requestSubmit) form.requestSubmit(); else form.submit();
    return true;
  }
  return false;
})()`;

for (const action of job.actions || []) {
  try {
    if ('goto' in action) {
      results.push(await goto(action.goto));
    } else if ('fill' in action) {
      const opened = await goto(action.fill);
      loaded = false;
      status = 0;
      const r = await page('Runtime.evaluate', { expression: FILL(action.text), returnByValue: true });
      const found = r.result?.result?.value === true;
      if (found) await settle();
      results.push({ ...opened, found, after: { status, path: await where() } });
    } else if ('eval' in action) {
      const r = await page('Runtime.evaluate', { expression: action.eval, returnByValue: true, awaitPromise: true });
      results.push({ value: r.result?.result?.value ?? null });
    } else if ('wait' in action) {
      await sleep(Math.min(action.wait, 5000));
      results.push({});
    } else {
      results.push({ error: 'unknown action' });
    }
  } catch (e) {
    results.push({ error: String(e && e.message ? e.message : e) });
  }
}
console.log(JSON.stringify(results));
ws.close();
process.exit(0);
