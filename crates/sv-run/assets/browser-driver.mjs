// Drives the headless Chromium next to it, for `sv run`. Node's standard library only.
//
// It shares Chromium's network (`--network container:<browser>`), so it reaches the DevTools port
// on 127.0.0.1 and the app by its name on the fenced network, and nothing else. The DevTools port
// listens on 127.0.0.1 alone, so the app cannot reach it (`browser_args` in docker.rs). It reads one job
// from the environment and prints one line of JSON: the result of each action, in order.
//
// SV_JOB = base64 of {"app": "http://localhost:8080", "actions": [...]}
// Actions:
//   {"goto": "/path"}                     -> {"status": 200, "path": "/where/it/ended"}
//   {"fill": "/path", "text": "..."}      -> {"status", "found": bool, "after": {"status", "path"}}
//   {"eval": "expression"}                -> {"value": ...}
//   {"act": "expression"}                 -> {"found": bool, "after": {"status", "path"}}
//       runs an expression that does something in the page, such as clicking, and answers
//       whether it found what to do; when it did, waits for wherever that leads.
//   {"wait": 500}                         -> {}
//   {"cookies": [{"name", "value", "path", "secure", "httpOnly", "sameSite"}]}
//                                         -> {"refused": [{"name", "why"}]}
//       sets them for the app, with the attributes given, and answers which the browser would not
//       keep and why. A browser refuses a `__Host-` cookie that is not `Secure`, for one.
//   {"outside": true}                     -> {"requests": [{"url", "method", "type", "page", "body", "headers"}]}
//       every request the tab tried to send to a host other than the app's, since the job began.
//       The fence stops each one leaving; the browser records it before it tries.

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

// Each cookie set for the app's address, with its attributes, and the browser's answer read: an
// error, or `success: false` from an older browser, is a cookie it did not keep.
async function setCookies(cookies) {
  const refused = [];
  for (const cookie of cookies || []) {
    const { name, value, path, secure, httpOnly, sameSite } = cookie;
    const params = { name, value, url: job.app, path: path || '/', secure: !!secure, httpOnly: !!httpOnly };
    if (sameSite) params.sameSite = sameSite;
    const r = await page('Network.setCookie', params);
    if (r.error || r.result?.success === false) {
      refused.push({ name, why: String(r.error?.message || 'refused').slice(0, 200) });
    }
  }
  return refused;
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

// Requests to any host but the app's, in the order the tab tried them. Capped, so a page that
// sends without end cannot fill the output; each field is cut short for the same reason.
const APP_HOST = new URL(job.app).host;
const OUTSIDE_MAX = 200;
const outside = [];
const bodyOf = (request) => {
  if (typeof request.postData === 'string') return request.postData;
  if (Array.isArray(request.postDataEntries)) {
    return request.postDataEntries
      .map((e) => (e.bytes ? Buffer.from(e.bytes, 'base64').toString('utf8') : ''))
      .join('');
  }
  return '';
};
listeners.add((d) => {
  if (d.sessionId !== sessionId || d.method !== 'Network.requestWillBeSent') return;
  const request = d.params.request;
  let url;
  try {
    url = new URL(request.url);
  } catch {
    return;
  }
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) || url.host === APP_HOST) return;
  if (outside.length >= OUTSIDE_MAX) return;
  let page = '';
  try {
    page = new URL(d.params.documentURL).pathname;
  } catch {}
  outside.push({
    url: request.url.slice(0, 8192),
    method: request.method,
    type: d.params.type || '',
    page,
    body: bodyOf(request).slice(0, 65536),
    headers: Object.entries(request.headers || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n')
      .slice(0, 8192),
  });
});

async function settle() {
  const until = Date.now() + LOAD_MS;
  while (!loaded && Date.now() < until) await sleep(50);
  await sleep(300);
}

// Every expression runs in a world of the driver's own beside the page's: the same page and the
// same storage, with none of the page's scripts. In the page's own world, the app could redefine
// what the driver reads with, such as `localStorage` or `Object.keys`, and hide what it keeps from
// the sign-out check (deep review S11). Made afresh each time, since a navigation ends it; when it
// cannot be made, the action fails rather than reading through the page's world.
async function evaluate(params) {
  const tree = await page('Page.getFrameTree');
  const frameId = tree.result?.frameTree?.frame?.id;
  const world = await page('Page.createIsolatedWorld', { frameId, worldName: 'sv-driver' });
  const contextId = world.result?.executionContextId;
  if (!contextId) throw new Error('the driver could not make a world of its own in the page');
  return page('Runtime.evaluate', { ...params, contextId });
}

async function where() {
  const r = await evaluate({ expression: 'location.pathname + location.search', returnByValue: true });
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
      const r = await evaluate({ expression: FILL(action.text), returnByValue: true });
      const found = r.result?.result?.value === true;
      if (found) await settle();
      results.push({ ...opened, found, after: { status, path: await where() } });
    } else if ('act' in action) {
      loaded = false;
      status = 0;
      const r = await evaluate({ expression: action.act, returnByValue: true });
      const found = r.result?.result?.value === true;
      if (found) await settle();
      results.push({ found, after: { status, path: await where() } });
    } else if ('eval' in action) {
      const r = await evaluate({ expression: action.eval, returnByValue: true, awaitPromise: true });
      results.push({ value: r.result?.result?.value ?? null });
    } else if ('cookies' in action) {
      results.push({ refused: await setCookies(action.cookies) });
    } else if ('outside' in action) {
      results.push({ requests: outside });
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
