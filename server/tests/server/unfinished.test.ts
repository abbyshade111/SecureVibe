/**
 * "Things you still need to finish": what SecureVibe cannot do for an owner, read from facts.
 *
 * The field has existed, and been rendered by the Results page, and been hardcoded empty. Meanwhile an owner was
 * told her app "only talks to the outside services you named (weather service, maps)" — describing the safety of
 * two connections that were never built, because she had never been asked for their addresses. Nothing anywhere
 * told her they were missing.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('what only the owner can finish', () => {
  let harness: TestHarness;
  let projectId: string;
  let headers: Record<string, string>;

  beforeEach(async () => {
    harness = await buildHarness();
    const profile = {
      ...habitTracker,
      capabilities: {
        ...habitTracker.capabilities,
        email: true,
        externalApis: [
          { name: 'Weather service', purpose: 'show the forecast', sendsPersonalData: false, host: '', credentials: 'not-sure' as const },
          { name: 'Maps', purpose: 'show where a run went', sendsPersonalData: false, host: 'api.maps.example', credentials: 'not-yet' as const },
        ],
      },
    };
    projectId = harness.store.create({ name: 'Fitness', mode: 'guided', profile }).id;
    const appDir = harness.store.paths(projectId).appDir;
    mkdirSync(appDir, { recursive: true });
    writeFileSync(join(appDir, '.env'), 'PORT=3000\nSMTP_URL=\n');
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken, Origin: 'http://127.0.0.1:4173' };
  });
  afterEach(() => harness?.cleanup());

  it('names an outside service with no address, and says the app does not call it', async () => {
    const res = await request(harness.server).get(`/api/projects/${projectId}/app/run-instructions`).set(headers);
    expect(res.status).toBe(200);
    const weather = (res.body.unfinished as string[]).find((u) => u.startsWith('Weather service'));
    expect(weather, `nothing said the weather service is unconnected: ${JSON.stringify(res.body.unfinished)}`).toBeDefined();
    expect(weather).toMatch(/does not call it/i);
    expect(weather).toMatch(/no web address/i);
  });

  it('distinguishes "no address" from "no key yet", because they need different things from the owner', async () => {
    const res = await request(harness.server).get(`/api/projects/${projectId}/app/run-instructions`).set(headers);
    const maps = (res.body.unfinished as string[]).find((u) => u.startsWith('Maps'));
    expect(maps).toMatch(/api\.maps\.example/);
    expect(maps).toMatch(/needs an account and key/i);
  });

  it('says email will send nothing when it is switched on with no mail service', async () => {
    const res = await request(harness.server).get(`/api/projects/${projectId}/app/run-instructions`).set(headers);
    expect((res.body.unfinished as string[]).some((u) => /mail service/i.test(u) && /nothing is sent/i.test(u))).toBe(true);
  });
});
