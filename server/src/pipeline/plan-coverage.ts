/**
 * After the build: was each planned feature actually built? Checked against facts, not the model's own report —
 * the app's route list (pages), the registered record types, and the names of the tests that ran.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PipelineRun } from '@shared/pipeline.js';
import type { BuildPlan } from '@shared/project.js';

export type PlanCoverage = NonNullable<PipelineRun['planCoverage']>;

interface RouteLike {
  path?: string;
  entity?: string | null;
  kind?: string;
}

function readRoutes(appDir: string): RouteLike[] {
  const file = join(appDir, 'routes.manifest.json');
  if (!existsSync(file)) return [];
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    return Array.isArray(parsed) ? (parsed as RouteLike[]) : [];
  } catch {
    return [];
  }
}

const norm = (s: string) => s.trim().toLowerCase().replace(/[\s-]+/g, '_');

/** A planned page "/research/:id" matches a route "/research/:topicId"; parameter names do not matter. */
function pageMatches(planned: string, route: string): boolean {
  const shape = (p: string) => p.toLowerCase().replace(/\/+$/, '').replace(/:[^/]+/g, ':x');
  return shape(planned) === shape(route);
}

export function planCoverage(plan: BuildPlan, appDir: string, tests: { name: string; ok: boolean }[]): PlanCoverage {
  const routes = readRoutes(appDir);
  const pagePaths = routes.filter((r) => typeof r.path === 'string').map((r) => r.path!);
  const entities = new Set(routes.map((r) => (typeof r.entity === 'string' ? norm(r.entity) : '')).filter(Boolean));
  const testNames = tests.map((t) => ({ name: t.name.toLowerCase(), ok: t.ok }));

  return plan.features.map((f) => {
    if (!f.wanted) return { featureId: f.id, title: f.title, status: 'left-out' as const, evidence: 'Left out of the build at your request.' };

    const pagesFound = f.pages.filter((p) => pagePaths.some((r) => pageMatches(p, r)));
    const recordsFound = f.records.filter((r) => entities.has(norm(r)));
    // A planned test counts as present when a test with that name, or at least its id ("RS-01"), ran.
    const matches = (t: string, n: { name: string; ok: boolean }): boolean => {
      const id = t.toLowerCase().split(' ')[0] ?? '';
      return n.name.includes(t.toLowerCase()) || (id.length >= 4 && n.name.includes(id));
    };
    const testsFound = f.tests.filter((t) => testNames.some((n) => matches(t, n)));
    const testsPassing = f.tests.filter((t) => testNames.some((n) => n.ok && matches(t, n)));

    const checks: { planned: number; found: number }[] = [
      { planned: f.pages.length, found: pagesFound.length },
      { planned: f.records.length, found: recordsFound.length },
      { planned: f.tests.length, found: testsFound.length },
    ].filter((c) => c.planned > 0);
    const planned = checks.reduce((n, c) => n + c.planned, 0);
    const found = checks.reduce((n, c) => n + c.found, 0);

    const parts: string[] = [];
    if (f.pages.length) parts.push(`${pagesFound.length} of ${f.pages.length} pages exist`);
    if (f.records.length) parts.push(`${recordsFound.length} of ${f.records.length} record types exist`);
    if (f.tests.length) parts.push(`${testsFound.length} of ${f.tests.length} tests exist (${testsPassing.length} passing)`);
    const evidence = parts.length ? `${parts.join('; ')}.` : 'The plan named nothing that can be checked for this feature.';

    // "Built" has to mean something was shown to work, not that files turned up where the plan said they would.
    // A feature whose pages and records all exist still only reads 'built' when a test the plan named passed on
    // it; with no passing test it is 'files in place', which an owner reads as weaker without needing it
    // explained. The case that prompted this: a charts feature marked built, with three of its planned test
    // names passing, in an app where nothing draws anything — the tests asserted the page answered and carried a
    // heading.
    const everythingFound = planned > 0 && found === planned;
    const provedByATest = f.tests.length > 0 && testsPassing.length > 0;
    const status =
      planned === 0 ? 'partly' : everythingFound ? (provedByATest ? 'built' : 'files-in-place') : found === 0 ? 'not-built' : 'partly';
    return { featureId: f.id, title: f.title, status, evidence };
  });
}
