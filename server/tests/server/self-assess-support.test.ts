import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { NOT_APPLICABLE_TO_SECUREVIBE, selfRoutes, type ExpressLayer } from '../../src/cli/self-assess-support.js';
import { ALL_PROBES } from '../../src/scanners/dast/probes/index.js';
import { buildHarness, type TestHarness } from './helpers.js';

describe('self-assessment support', () => {
  let harness: TestHarness;
  beforeAll(async () => {
    harness = await buildHarness();
  });
  afterAll(() => harness?.cleanup());

  it("lists SecureVibe's own routes with the right audience", () => {
    const { routes } = selfRoutes(harness.app as unknown as { router?: { stack?: ExpressLayer[] } });
    const find = (method: string, path: string) => routes.find((r) => r.method === method && r.path === path);
    expect(find('GET', '/auth/token')?.auth).toBe('public');
    expect(find('GET', '/healthz')?.auth).toBe('public');
    expect(find('POST', '/auth/logout')?.auth).toBe('user');
    expect(find('GET', '/api/projects')).toMatchObject({ auth: 'user', kind: 'api' });
    expect(find('GET', '/api/projects/:id')?.params).toEqual(['id']);
    expect(routes.some((r) => r.path.includes('*'))).toBe(false);
  });

  it('only names probes that exist', () => {
    const ids = new Set(ALL_PROBES.map((p) => p.id));
    for (const id of Object.keys(NOT_APPLICABLE_TO_SECUREVIBE)) expect(ids.has(id), id).toBe(true);
  });
});
