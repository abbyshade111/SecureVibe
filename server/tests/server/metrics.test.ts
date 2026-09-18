import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { computeMetrics } from '../../src/api/metrics.js';
import { loadConfig } from '../../src/config.js';
import { readSecurityEvents, securityEventStream } from '../../src/security/event-log.js';
import { ProjectStore } from '../../src/store/index.js';
import { habitTracker } from '../fixtures/design/profiles.js';

const NOW = new Date('2026-09-17T12:00:00.000Z');

describe('security event log', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'securevibe-events-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('keeps only named events, only safe fields, readable by the owner only', () => {
    const file = join(dir, 'logs', 'security-events.jsonl');
    const stream = securityEventStream(file);
    stream.write(`${JSON.stringify({ level: 30, time: NOW.toISOString(), msg: 'plain line' })}\n`);
    stream.write(
      `${JSON.stringify({ level: 40, time: NOW.toISOString(), event: 'csrf.rejected', status: 403, method: 'POST', path: '/api/projects', ip: '127.0.0.1', token: 'secret-value', cookie: 'c=1' })}\n`,
    );
    const events = readSecurityEvents(file, 0);
    expect(events).toEqual([{ ts: NOW.toISOString(), event: 'csrf.rejected', level: 40, status: 403, method: 'POST', path: '/api/projects' }]);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readSecurityEvents(file, NOW.getTime() + 1)).toEqual([]);
  });
});

describe('dashboard metrics', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'securevibe-metrics-'));
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  it('counts AI spending per purpose, app and build, ignoring test calls and old entries', () => {
    const config = loadConfig({ ...process.env, SECUREVIBE_HOME: home });
    const store = new ProjectStore(config.paths.home);
    const project = store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const runId = 'r_20260917100000_aaaaaa';
    store.writeRunSync({
      id: runId,
      projectId: project.id,
      mode: 'full',
      startedAt: '2026-09-17T10:00:00.000Z',
      finishedAt: '2026-09-17T10:06:00.000Z',
      status: 'succeeded',
      stages: [],
      spendingCapUsd: 5,
      findings: [],
      coverage: [],
      artifacts: [],
      fixRounds: 0,
      incomplete: false,
    } as never);
    const line = (o: Record<string, unknown>) => JSON.stringify({ provider: 'anthropic', servedModel: 'claude-opus-5', inputTokens: 100, cacheRead: 300, cacheWrite: 0, outputTokens: 10, ...o });
    writeFileSync(
      config.paths.auditLogFile,
      [
        line({ ts: '2026-09-17T10:01:00.000Z', projectId: project.id, runId, purpose: 'generate', costUsd: 2 }),
        line({ ts: '2026-09-17T10:03:00.000Z', projectId: project.id, runId, purpose: 'ai-review', costUsd: 1.5 }),
        line({ ts: '2026-09-17T10:04:00.000Z', projectId: project.id, runId, purpose: 'ai-review', costUsd: 0, error: 'billing' }),
        line({ ts: '2026-09-17T10:05:00.000Z', projectId: 'p1', purpose: 'generate', costUsd: 9, provider: 'scripted' }),
        line({ ts: '2026-07-01T10:00:00.000Z', projectId: project.id, purpose: 'generate', costUsd: 50 }),
        'not json',
      ].join('\n'),
    );

    const m = computeMetrics({ config, store }, 7, NOW);
    expect(m.ai.totalUsd).toBe(3.5);
    expect(m.ai.calls).toBe(3);
    expect(m.ai.failedCalls).toBe(1);
    expect(m.ai.cacheShare).toBe(0.75);
    expect(m.ai.byPurpose.map((p) => [p.key, p.usd])).toEqual([
      ['generate', 2],
      ['ai-review', 1.5],
    ]);
    expect(m.ai.byApp).toEqual([{ key: project.id, label: 'Habits', count: 3, usd: 3.5 }]);
    expect(m.ai.byDay).toHaveLength(7);
    expect(m.ai.byDay.at(-1)).toEqual({ day: '2026-09-17', usd: 3.5, calls: 3 });
    expect(m.builds.total).toBe(1);
    expect(m.builds.recent[0]).toMatchObject({ appName: 'Habits', usd: 3.5, minutes: 6, spendingCapUsd: 5 });
    expect(m.builds.averageUsd).toBe(3.5);
    expect(m.security.recordingSince).toBeNull();
  });
});
