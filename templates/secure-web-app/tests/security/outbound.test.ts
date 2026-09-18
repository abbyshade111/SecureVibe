/** Outbound HTTP, trust zones and email hygiene (TPL-OUTBOUND-01, TPL-TRUSTZONES-01, TPL-EMAIL-01, AS-01). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { connect } from 'node:net';
import { networkInterfaces, tmpdir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { CookieJar, generateEnv, moduleUrl, runSnippet, startApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';

interface Hit {
  method: string;
  url: string;
}

/** A local origin server recording every request it receives. */
function recordingServer(behaviour: (url: string, res: import('node:http').ServerResponse) => void): Promise<{ server: Server; port: number; hits: Hit[] }> {
  const hits: Hit[] = [];
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      hits.push({ method: req.method ?? '', url: req.url ?? '' });
      behaviour(req.url ?? '', res);
    });
    server.once('error', (err) => reject(new Error(`local origin server could not listen: ${String(err)}`)));
    server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as { port: number }).port, hits }));
  });
}

/** Runs outboundFetch(url) in a child process with the given allow-list and reports the outcome. */
async function callOutbound(url: string, allowedHosts: string, extra: Record<string, string> = {}): Promise<{ ok: boolean; status?: number; error?: string; ms: number }> {
  const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-outbound-'));
  try {
    const code = `
      import { outboundFetch } from ${JSON.stringify(moduleUrl('src/lib/http-client.ts'))};
      const started = Date.now();
      try {
        const res = await outboundFetch(${JSON.stringify(url)}, { method: 'GET' });
        let text = '';
        try { text = await res.text(); } catch (e) { text = 'BODY_ERROR:' + String(e); }
        console.log(JSON.stringify({ ok: true, status: res.status, ms: Date.now() - started, bodyLength: text.length, bodyError: text.startsWith('BODY_ERROR:') ? text : undefined }));
      } catch (e) {
        console.log(JSON.stringify({ ok: false, error: String(e && (e.message || e)), ms: Date.now() - started }));
      }
    `;
    const result = await runSnippet(code, { ...generateEnv(dataDir), OUTBOUND_ALLOWED_HOSTS: allowedHosts, ...extra }, 45_000);
    const line = result.stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1);
    if (!line) throw new Error(`outbound snippet produced no result (exit ${result.code}):\n${result.stderr}`);
    return JSON.parse(line) as { ok: boolean; status?: number; error?: string; ms: number };
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
}

describe('outbound', () => {
  let origin: { server: Server; port: number; hits: Hit[] };
  let other: { server: Server; port: number; hits: Hit[] };

  before(async () => {
    origin = await recordingServer((url, res) => {
      if (url.startsWith('/redirect')) {
        res.writeHead(302, { Location: `http://127.0.0.1:${other.port}/landed` });
        res.end();
      } else if (url.startsWith('/fail')) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('boom');
      } else if (url.startsWith('/slow')) {
        // never answers
      } else if (url.startsWith('/huge')) {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end(Buffer.alloc(3 * 1024 * 1024, 65));
      } else {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('hello');
      }
    });
    other = await recordingServer((_url, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('landed');
    });
  });
  after(() => {
    origin?.server.close();
    other?.server.close();
  });

  test('V13.2.4 outbound requests are only allowed to hosts on the OUTBOUND_ALLOWED_HOSTS allow-list', async () => {
    const allowed = await callOutbound(`http://127.0.0.1:${origin.port}/ok`, `127.0.0.1:${origin.port}`);
    assert.equal(allowed.ok, true, `allow-listed host must be reachable: ${allowed.error}`);
    assert.equal(allowed.status, 200);
    assert.equal(origin.hits.filter((h) => h.url === '/ok').length, 1);

    const blocked = await callOutbound(`http://127.0.0.1:${other.port}/blocked`, `127.0.0.1:${origin.port}`);
    assert.equal(blocked.ok, false, 'a host that is not allow-listed must be rejected');
    assert.equal(other.hits.filter((h) => h.url === '/blocked').length, 0, 'the blocked request must never leave the app');

    const denyAll = await callOutbound(`http://127.0.0.1:${origin.port}/deny-all`, '');
    assert.equal(denyAll.ok, false, 'an empty allow-list must deny every outbound request');
    assert.equal(origin.hits.filter((h) => h.url === '/deny-all').length, 0);

    const wrongPort = await callOutbound(`http://127.0.0.1:${other.port}/wrong-port`, `127.0.0.1:${origin.port}`);
    assert.equal(wrongPort.ok, false, 'the allow-list must match the port as well as the host');
  });

  test('V15.3.2 redirects from external services are not followed automatically', async () => {
    const res = await callOutbound(`http://127.0.0.1:${origin.port}/redirect`, `127.0.0.1:${origin.port},127.0.0.1:${other.port}`);
    if (res.ok) {
      assert.equal(res.status, 302, 'the redirect must be returned to the caller, not followed');
    } else {
      assert.match(res.error ?? '', /redirect/i, 'if redirects are refused the error must say so');
    }
    assert.equal(other.hits.filter((h) => h.url === '/landed').length, 0, 'the redirect target must not be requested');
  });

  test('V16.5.2 failing external services trip a circuit breaker and the app degrades instead of hanging', async () => {
    const allow = `127.0.0.1:${origin.port}`;
    const before = origin.hits.filter((h) => h.url.startsWith('/fail')).length;
    const attempts = 12;
    const code = `
      import { outboundFetch } from ${JSON.stringify(moduleUrl('src/lib/http-client.ts'))};
      const outcomes = [];
      for (let i = 0; i < ${attempts}; i++) {
        try { const r = await outboundFetch(${JSON.stringify(`http://127.0.0.1:${origin.port}/fail`)}, { method: 'GET' }); await r.text().catch(() => ''); outcomes.push('status:' + r.status); }
        catch (e) { outcomes.push('error:' + String(e && (e.message || e))); }
      }
      console.log(JSON.stringify(outcomes));
    `;
    const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-outbound-'));
    let outcomes: string[];
    try {
      const result = await runSnippet(code, { ...generateEnv(dataDir), OUTBOUND_ALLOWED_HOSTS: allow }, 60_000);
      const line = result.stdout.trim().split('\n').filter((l) => l.startsWith('[')).at(-1);
      assert.ok(line, `breaker snippet produced no output (exit ${result.code}): ${result.stderr}`);
      outcomes = JSON.parse(line) as string[];
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
    const reached = origin.hits.filter((h) => h.url.startsWith('/fail')).length - before;
    assert.ok(reached < attempts, `after repeated failures the breaker must open: all ${attempts} attempts reached the failing service`);
    assert.ok(outcomes.length === attempts, 'every attempt must resolve or reject (never hang)');
    const shortCircuited = outcomes.slice(reached).filter((o) => o.startsWith('error:'));
    assert.ok(shortCircuited.length >= 1, `calls after the breaker opened must fail fast: ${outcomes.join(', ')}`);
  });

  test('V13.2.5 outbound calls have a bounded timeout and a response size cap', async () => {
    const slow = await callOutbound(`http://127.0.0.1:${origin.port}/slow`, `127.0.0.1:${origin.port}`);
    assert.equal(slow.ok, false, 'a service that never answers must time out');
    assert.ok(slow.ms < 20_000, `timeout must be about 10 s (took ${slow.ms} ms)`);
    const huge = await callOutbound(`http://127.0.0.1:${origin.port}/huge`, `127.0.0.1:${origin.port}`);
    const capped = !huge.ok || (huge as { bodyLength?: number; bodyError?: string }).bodyError !== undefined || ((huge as { bodyLength?: number }).bodyLength ?? 0) <= 1024 * 1024;
    assert.ok(capped, 'responses larger than 1 MB must be rejected or truncated');
  });

  test('AS-01 trust zones: the app listens on loopback only unless BIND_LAN=1, and egress is deny-by-default', async (t) => {
    const app = await startApp();
    try {
      const health = await app.fetch(paths.healthz);
      await health.text();
      assert.equal(health.status, 200);
      const lanAddress = Object.values(networkInterfaces())
        .flat()
        .find((i) => i && !i.internal && i.family === 'IPv4')?.address;
      if (!lanAddress) return t.skip('no non-loopback IPv4 interface available to probe');
      const reachable = await new Promise<boolean>((resolve) => {
        const socket = connect(app.port, lanAddress);
        socket.setTimeout(3_000, () => {
          socket.destroy();
          resolve(false);
        });
        socket.on('connect', () => {
          socket.destroy();
          resolve(true);
        });
        socket.on('error', () => resolve(false));
      });
      assert.equal(reachable, false, `the app must not be reachable on the LAN address ${lanAddress} by default`);
      assert.equal(app.env.OUTBOUND_ALLOWED_HOSTS, '', 'the default egress allow-list is empty (deny all)');
    } finally {
      await app.stop();
    }
  });

  test('V1.3.11 user-controlled text cannot inject headers into outgoing mail', async (t) => {
    const app = await startApp();
    try {
      if (!(await app.featureEnabled('email'))) return t.skip('feature "email" is not enabled');
      const jar = await app.login(users.member);
      const injected = 'Eve\r\nBcc: attacker@evil.example\r\nSubject: injected';
      const profile = await app.submitForm(paths.profile, { [fields.name]: injected }, jar);
      await profile.text();
      const before = app.outbox().length;
      const reset = await app.submitForm(paths.forgotPassword, { [fields.email]: users.member }, new CookieJar());
      await reset.text();
      const mails = await app.waitForOutbox(before + 1);
      assert.ok(mails.length > before, 'a mail must be written to the outbox');
      const mail = mails[mails.length - 1]!.text;
      const headerBlock = mail.split(/\r?\n\r?\n/)[0] ?? '';
      assert.doesNotMatch(headerBlock, /^bcc:\s*attacker@evil\.example/im, 'an injected Bcc header must not appear');
      assert.equal((headerBlock.match(/^subject:/gim) ?? []).length, 1, 'exactly one Subject header');
      assert.equal((headerBlock.match(/^to:/gim) ?? []).length, 1, 'exactly one To header');
      for (const line of headerBlock.split(/\r?\n/)) assert.doesNotMatch(line, /[\r\n]/, 'header lines must not contain bare CR/LF');
    } finally {
      await app.stop();
    }
  });
});
