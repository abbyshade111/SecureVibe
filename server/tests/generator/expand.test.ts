/**
 * The CRUD expander is the path that makes a build without AI still useful, so this test runs it against a real
 * copy of the template and type-checks the result: generated code that does not compile is worse than none.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../../src/config.js';
import { deriveDesign, loadFrameworks, loadKnowledge } from '../../src/integration.js';
import { expandEntities } from '../../src/generator/expand.js';
import { clinicBookings, habitTracker, teamInventory } from '../fixtures/design/profiles.js';

const templateDir = join(REPO_ROOT, 'templates', 'secure-web-app');
const templateExists = existsSync(join(templateDir, 'src', 'features', 'index.ts'));

function copyTemplate(): string {
  const dir = mkdtempSync(join(tmpdir(), 'securevibe-expand-'));
  const appDir = join(dir, 'app');
  cpSync(templateDir, appDir, { recursive: true, dereference: true, filter: (src) => !src.includes('node_modules') && !src.includes(`${appDir}/data`) });
  return appDir;
}

describe.skipIf(!templateExists)('generator/expand against the real template', () => {
  it('writes a complete feature for every record type the person described', async () => {
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(habitTracker, { knowledge, frameworks });

      const result = await expandEntities({ appDir, design, profile: habitTracker, runId: 'r_20260101000000_aaaaaa' });

      expect(result.entities).toHaveLength(1);
      const habit = result.entities[0]!;
      expect(habit.name).toBe('habit');
      expect(habit.table).toBe('habits');
      expect(habit.routeBase).toBe('/habits');

      for (const rel of ['src/features/habit/schema.ts', 'src/features/habit/repo.ts', 'src/features/habit/index.ts', 'src/views/habit/list.ejs', 'src/views/habit/show.ejs', 'src/views/habit/form.ejs', 'tests/features/habit.test.ts', 'src/db/migrations/100_habits.sql']) {
        expect(existsSync(join(appDir, rel)), `${rel} must exist`).toBe(true);
      }

      // Every route is registered, and the feature is mounted in the marked spot.
      const features = readFileSync(join(appDir, 'src', 'features', 'index.ts'), 'utf8');
      expect(features).toContain("await import('./habit/index.ts')");
      const routes = JSON.parse(readFileSync(join(appDir, 'routes.manifest.json'), 'utf8')) as { method: string; path: string; auth: string }[];
      expect(routes.some((r) => r.method === 'GET' && r.path === '/habits')).toBe(true);
      expect(routes.some((r) => r.method === 'DELETE' && r.path === '/api/habits/:id')).toBe(true);
      // Deny by default: no generated route may be public unless the entity was marked public-read.
      expect(routes.filter((r) => r.path.startsWith('/habits') || r.path.startsWith('/api/habits')).every((r) => r.auth !== 'public')).toBe(true);
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  });

  it('leaves out a file field when the uploads feature is off, and says why', async () => {
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(teamInventory, { knowledge, frameworks });
      const result = await expandEntities({ appDir, design, profile: teamInventory, runId: 'r_20260101000000_bbbbbb' });

      const item = result.entities.find((e) => e.name === 'item');
      expect(item).toBeDefined();
      if (design.buildSpec.features.uploads) {
        expect(item!.droppedFields).toHaveLength(0);
      } else {
        expect(item!.droppedFields.some((d) => d.name === 'photo')).toBe(true);
        expect(result.warnings.join(' ')).toMatch(/uploads/i);
      }
      // Money is stored as whole cents so totals never drift.
      const migration = readFileSync(join(appDir, 'src', 'db', 'migrations', '100_items.sql'), 'utf8');
      expect(migration).toMatch(/cost INTEGER/);
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  });

  it('produces code that compiles, with owner checks on records that belong to one person', async () => {
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(clinicBookings, { knowledge, frameworks });
      const result = await expandEntities({ appDir, design, profile: clinicBookings, runId: 'r_20260101000000_cccccc' });
      expect(result.entities.length).toBeGreaterThan(0);

      const ownerScoped = clinicBookings.app.entities.filter((e) => e.access === 'owner-only').map((e) => e.name);
      for (const name of ownerScoped) {
        const routes = readFileSync(join(appDir, 'src', 'features', name, 'index.ts'), 'utf8');
        expect(routes, `${name} must enforce ownership`).toContain('owner: OWNER');
      }

      // Sensitive fields are encrypted at rest.
      for (const entity of clinicBookings.app.entities) {
        if (!entity.fields.some((f) => f.sensitive)) continue;
        const repo = readFileSync(join(appDir, 'src', 'features', entity.name, 'repo.ts'), 'utf8');
        expect(repo, `${entity.name} must encrypt its sensitive fields`).toContain('encryptField(');
        expect(repo).toContain('registerEncryptedColumn(');
      }

      // The real proof: the expanded application still type-checks.
      cpSync(join(templateDir, 'node_modules'), join(appDir, 'node_modules'), { recursive: true, dereference: false });
      const tsc = join(appDir, 'node_modules', '.bin', 'tsc');
      const out = execFileSync(tsc, ['-p', join(appDir, 'tsconfig.json')], { cwd: appDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      expect(out.trim()).toBe('');
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  }, 300_000);
});
