/** The build plan: what Claude proposes is tidied into checkable facts, and the coverage check measures the result. */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { planBuild } from '../../src/llm/flows/plan.js';
import { planCoverage } from '../../src/pipeline/plan-coverage.js';
import { NullProvider } from '../../src/llm/null.js';
import { ScriptedProvider } from '../../src/llm/scripted.js';
import { FIXTURE_DIR, makeDesign } from './helpers.js';

describe('build plan', () => {
  it('keeps only page paths and record names that could exist, and numbers the features', async () => {
    const provider = new ScriptedProvider({ dir: FIXTURE_DIR, scenario: 'plan' });
    const { plan } = await planBuild(provider, { design: makeDesign(), records: [{ name: 'note', label: 'Note' }] }, { projectId: 'p1' });
    expect(plan).toBeDefined();
    expect(plan!.features.map((f) => f.id)).toEqual(['PF-01', 'PF-02', 'PF-03']);
    expect(plan!.features[0]).toMatchObject({ pages: ['/research', '/research/new', '/research/:id'], records: ['research_topics'], wanted: true });
    // Malformed entries are dropped; the feature itself stays for the owner to see.
    expect(plan!.features[2]).toMatchObject({ pages: [], records: [] });
    expect(plan!.estimatedSteps).toBe(24);
    expect(plan!.designHash).toBe(makeDesign().profileHash);
  });

  it('is simply absent without AI', async () => {
    const { plan, failure } = await planBuild(new NullProvider('none'), { design: makeDesign(), records: [] });
    expect(plan).toBeUndefined();
    expect(failure).toBeUndefined();
  });
});

describe('plan coverage', () => {
  it('measures each feature against the route list, record types and tests', () => {
    const appDir = mkdtempSync(join(tmpdir(), 'securevibe-plan-'));
    try {
      mkdirSync(appDir, { recursive: true });
      writeFileSync(
        join(appDir, 'routes.manifest.json'),
        JSON.stringify([
          { method: 'GET', path: '/research', entity: 'research_topics', kind: 'page' },
          { method: 'GET', path: '/research/:topicId', entity: 'research_topics', kind: 'page' },
          { method: 'GET', path: '/ai', entity: null, kind: 'page' },
        ]),
      );
      const plan = {
        createdAt: 'now',
        designHash: 'h',
        summary: '',
        features: [
          { id: 'PF-01', title: 'Keep research topics', whatItDoes: '', pages: ['/research', '/research/new', '/research/:id'], records: ['research_topics'], tests: ['RS-01 denies anonymous visitors', 'RS-02 rejects invalid input'], wanted: true },
          { id: 'PF-02', title: 'Ask the assistant', whatItDoes: '', pages: ['/ai'], records: [], tests: [], wanted: true },
          { id: 'PF-03', title: 'Export', whatItDoes: '', pages: ['/export'], records: ['exports'], tests: [], wanted: true },
          { id: 'PF-04', title: 'Left out', whatItDoes: '', pages: ['/x'], records: [], tests: [], wanted: false },
        ],
      };
      const tests = [
        { name: 'research > RS-01 denies anonymous visitors', ok: true },
        { name: 'research > RS-02 rejects invalid input', ok: false },
      ];
      const coverage = planCoverage(plan, appDir, tests);
      expect(coverage.map((c) => c.status)).toEqual(['partly', 'built', 'not-built', 'left-out']);
      expect(coverage[0]!.evidence).toBe('2 of 3 pages exist; 1 of 1 record types exist; 2 of 2 tests exist (1 passing).');
      expect(coverage[1]!.evidence).toBe('1 of 1 pages exist.');
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  });
});
