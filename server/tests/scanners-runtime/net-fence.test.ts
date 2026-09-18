/**
 * The network fence: a generated app can listen and be reached on loopback, and cannot reach anything else.
 * The real check runs a node script behind the fence; where no fence is available it is skipped and says so.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { detectNetworkFence, SEATBELT_LOOPBACK_PROFILE } from '../../src/pipeline/net-fence.js';
import { realPathFor, runNode } from '../../src/pipeline/process.js';

describe('seatbelt profile', () => {
  it('denies every network path but loopback and unix sockets', () => {
    expect(SEATBELT_LOOPBACK_PROFILE).toContain('(deny network*)');
    expect(SEATBELT_LOOPBACK_PROFILE).toContain('(allow network-outbound (remote ip "localhost:*"))');
    expect(SEATBELT_LOOPBACK_PROFILE).toContain('(allow network-bind (local ip "localhost:*"))');
    expect(SEATBELT_LOOPBACK_PROFILE).not.toContain('allow network-outbound (remote ip "*');
  });
});

describe('a node process behind the fence', () => {
  const dir = realPathFor(mkdtempSync(join(tmpdir(), 'securevibe-fence-')));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  const script = `
    const http = require('node:http');
    const net = require('node:net');
    const out = {};
    const server = http.createServer((req, res) => res.end('hello'));
    server.listen(0, '127.0.0.1', async () => {
      const port = server.address().port;
      try {
        const r = await fetch('http://127.0.0.1:' + port + '/');
        out.loopback = await r.text();
      } catch (e) { out.loopback = 'ERR ' + e.message; }
      out.outside = await new Promise((resolve) => {
        const s = net.connect({ host: '1.1.1.1', port: 443 });
        const t = setTimeout(() => { s.destroy(); resolve('timeout'); }, 4000);
        s.on('connect', () => { clearTimeout(t); s.destroy(); resolve('connected'); });
        s.on('error', (e) => { clearTimeout(t); resolve('ERR ' + (e.code || e.message)); });
      });
      server.close();
      console.log(JSON.stringify(out));
    });
  `;
  const file = join(dir, 'probe.cjs');
  writeFileSync(file, script);

  it('can serve and be reached on loopback but cannot reach the internet', async () => {
    const fence = detectNetworkFence();
    if (fence.kind === 'none') {
      console.log('no network fence on this computer; skipped');
      return;
    }
    const result = await runNode([file], { cwd: dir, projectDir: dir, timeoutMs: 30_000, permission: { read: [dir], write: [dir] } });
    expect(result.sandboxMode).toBe('node-permission-model+loopback-only');
    const line = result.stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1);
    expect(line, `${result.stdout}\n${result.stderr}`).toBeDefined();
    const out = JSON.parse(line!) as { loopback: string; outside: string };
    expect(out.loopback).toBe('hello');
    expect(out.outside).not.toBe('connected');
  });

  it('is skipped for a child that must reach outside hosts, and the mode says so', async () => {
    const result = await runNode(['-e', 'process.exit(0)'], { cwd: dir, projectDir: dir, timeoutMs: 30_000, permission: { read: [dir], write: [dir], network: 'any' } });
    expect(result.sandboxMode).toBe('node-permission-model');
  });
});
