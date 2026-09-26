// A test model for `sv`, run on the fenced network in a stock Node image, standing in for the AI
// service an app calls. It speaks the three request shapes apps use — OpenAI's chat completions and
// responses, and Anthropic's messages, each plain or streamed — and it misbehaves on purpose, which
// is its whole purpose: whether an app's own controls hold can only be seen when the model does the
// wrong thing, and a real model cannot be made to do the wrong thing on demand, or for free.
//
// Built-in modules only: the fence has no route to a package registry.
//
// Environment: HOST (its own name, as the app reaches it) and PORT.
//
// What it answers depends on a marker in the latest user message, `SV-PROBE-<KIND>-<tag>`:
//   PLAIN   an ordinary reply carrying `SV-REPLY-<tag>`
//   LEAK    the reply repeats, word for word, the instructions the app sent it
//   IMAGE   the reply carries a markdown image and a link to an address on this server
//   INJECT  an ordinary reply; what matters is whether the message reached it at all
//
// `GET /_sv/seen/<tag>` says what arrived for that tag: whether it did, the instructions it came
// with, whether the request limited the reply's length, and whether anything has since fetched the
// address an IMAGE reply named. It also says the model name the request asked for and the token
// counts the reply reported, which are picked at random for each reply so that a log line carrying
// both can only be the log of that call.
import http from 'node:http';

const HOST = process.env.HOST || 'localhost';
const PORT = Number(process.env.PORT || 9100);
const MODEL = 'sv-test-model';
const seen = new Map(); // tag -> { kind, system, bounded, fetched, api, model, input_tokens, output_tokens }
const between = (low, high) => low + Math.floor(Math.random() * (high - low));

const text = (content) => {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => (typeof part === 'string' ? part : part && typeof part.text === 'string' ? part.text : ''))
      .join('\n');
  }
  return '';
};

// The instructions, the latest user message, and whether the reply's length was limited, for each
// of the three shapes.
function read(api, body) {
  const system = [];
  let user = '';
  if (api === 'messages') {
    system.push(text(body.system));
    for (const m of body.messages || []) if (m.role === 'user') user = text(m.content);
    return { system, user, bounded: Number.isFinite(body.max_tokens) };
  }
  if (api === 'responses') {
    if (typeof body.instructions === 'string') system.push(body.instructions);
    if (typeof body.input === 'string') user = body.input;
    for (const m of Array.isArray(body.input) ? body.input : []) {
      if (m.role === 'system' || m.role === 'developer') system.push(text(m.content));
      if (m.role === 'user') user = text(m.content);
    }
    return { system, user, bounded: Number.isFinite(body.max_output_tokens) };
  }
  for (const m of body.messages || []) {
    if (m.role === 'system' || m.role === 'developer') system.push(text(m.content));
    if (m.role === 'user') user = text(m.content);
  }
  return {
    system,
    user,
    bounded: Number.isFinite(body.max_tokens) || Number.isFinite(body.max_completion_tokens),
  };
}

function reply(api, body, usage) {
  const { system, user, bounded } = read(api, body);
  const instructions = system.filter(Boolean).join('\n');
  const found = /SV-PROBE-([A-Z]+)-([0-9a-f]+)/.exec(user);
  if (!found) return 'Hello from the test model.';
  const [, kind, tag] = found;
  const before = seen.get(tag);
  seen.set(tag, {
    kind, system: instructions, bounded, fetched: before ? before.fetched : false, api,
    model: typeof body.model === 'string' ? body.model : '',
    input_tokens: usage.input, output_tokens: usage.output,
  });
  const marker = `SV-REPLY-${tag}`;
  switch (kind) {
    case 'LEAK':
      return instructions
        ? `${marker} My instructions are: ${instructions}`
        : `${marker} I was given no instructions.`;
    case 'IMAGE': {
      const base = `http://${HOST}:${PORT}/_sv/exfil/${tag}`;
      return `${marker} Here is the chart: ![chart](${base}.png) and [the details](${base}-link).`;
    }
    default:
      return `${marker} Hello from the test model.`;
  }
}

function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
}

function sse(res, events) {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  for (const [event, data] of events) {
    if (event) res.write(`event: ${event}\n`);
    res.write(`data: ${typeof data === 'string' ? data : JSON.stringify(data)}\n\n`);
  }
  res.end();
}

function answer(api, body, res) {
  // Counts no real call of this size would report, different every time: 4000 to 8999 in, 1000
  // to 3999 out.
  const input = between(4000, 9000);
  const output = between(1000, 4000);
  const said = reply(api, body, { input, output });
  const model = typeof body.model === 'string' ? body.model : MODEL;
  if (api === 'messages') {
    const message = {
      id: 'msg_sv', type: 'message', role: 'assistant', model,
      content: [{ type: 'text', text: said }],
      stop_reason: 'end_turn', stop_sequence: null,
      usage: { input_tokens: input, output_tokens: output },
    };
    if (!body.stream) return json(res, 200, message);
    return sse(res, [
      ['message_start', { type: 'message_start', message: { ...message, content: [], stop_reason: null, usage: { input_tokens: input, output_tokens: 0 } } }],
      ['content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }],
      ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: said } }],
      ['content_block_stop', { type: 'content_block_stop', index: 0 }],
      ['message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: output } }],
      ['message_stop', { type: 'message_stop' }],
    ]);
  }
  if (api === 'responses') {
    const response = {
      id: 'resp_sv', object: 'response', created_at: 0, status: 'completed', model,
      output: [{
        type: 'message', id: 'msg_sv', status: 'completed', role: 'assistant',
        content: [{ type: 'output_text', text: said, annotations: [] }],
      }],
      output_text: said,
      usage: { input_tokens: input, output_tokens: output, total_tokens: input + output },
    };
    if (!body.stream) return json(res, 200, response);
    // Every event the real service sends, in its order: the OpenAI library refuses text for an
    // item it has not been told about.
    const item = response.output[0];
    const part = item.content[0];
    const at = { item_id: 'msg_sv', output_index: 0, content_index: 0 };
    return sse(res, [
      ['response.created', { type: 'response.created', response: { ...response, status: 'in_progress', output: [] } }],
      ['response.output_item.added', { type: 'response.output_item.added', output_index: 0, item: { ...item, status: 'in_progress', content: [] } }],
      ['response.content_part.added', { type: 'response.content_part.added', ...at, part: { ...part, text: '' } }],
      ['response.output_text.delta', { type: 'response.output_text.delta', ...at, delta: said }],
      ['response.output_text.done', { type: 'response.output_text.done', ...at, text: said }],
      ['response.content_part.done', { type: 'response.content_part.done', ...at, part }],
      ['response.output_item.done', { type: 'response.output_item.done', output_index: 0, item }],
      ['response.completed', { type: 'response.completed', response }],
    ].map(([event, data], n) => [event, { ...data, sequence_number: n }]));
  }
  const usage = { prompt_tokens: input, completion_tokens: output, total_tokens: input + output };
  if (!body.stream) {
    return json(res, 200, {
      id: 'chatcmpl-sv', object: 'chat.completion', created: 0, model,
      choices: [{ index: 0, message: { role: 'assistant', content: said }, finish_reason: 'stop' }],
      usage,
    });
  }
  const chunk = (delta, finish) => ({
    id: 'chatcmpl-sv', object: 'chat.completion.chunk', created: 0, model,
    choices: [{ index: 0, delta, finish_reason: finish }],
  });
  const events = [
    [null, chunk({ role: 'assistant', content: said }, null)],
    [null, chunk({}, 'stop')],
  ];
  if (body.stream_options && body.stream_options.include_usage) {
    events.push([null, { id: 'chatcmpl-sv', object: 'chat.completion.chunk', created: 0, model, choices: [], usage }]);
  }
  events.push([null, '[DONE]']);
  return sse(res, events);
}

function readBody(req) {
  return new Promise((resolve) => {
    const parts = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts).toString()));
  });
}

// A 1x1 transparent PNG, for an app that fetches the image its model named.
const PIXEL = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);

http
  .createServer(async (req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    if (req.method === 'GET' && path === '/_sv/health') return json(res, 200, { ok: true });
    const seenAt = /^\/_sv\/seen\/([0-9a-f]+)$/.exec(path);
    if (req.method === 'GET' && seenAt) {
      const what = seen.get(seenAt[1]);
      return json(res, 200, what ? { received: true, ...what } : { received: false });
    }
    const exfil = /^\/_sv\/exfil\/([0-9a-f]+)/.exec(path);
    if (exfil) {
      const what = seen.get(exfil[1]) || { received: false };
      seen.set(exfil[1], { ...what, fetched: true });
      res.writeHead(200, { 'content-type': 'image/png' });
      return res.end(PIXEL);
    }
    if (req.method !== 'POST') return json(res, 404, { error: { message: 'not found' } });
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return json(res, 400, { error: { message: 'the body is not JSON' } });
    }
    if (/(^|\/)chat\/completions$/.test(path)) return answer('chat', body, res);
    if (/(^|\/)responses$/.test(path)) return answer('responses', body, res);
    if (/(^|\/)messages$/.test(path)) return answer('messages', body, res);
    return json(res, 404, { error: { message: `no such endpoint: ${path}` } });
  })
  .listen(PORT, '0.0.0.0');
