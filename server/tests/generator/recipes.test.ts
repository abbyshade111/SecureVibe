/**
 * The recipe library against a real copy of the template. Recipes are the path that makes a build without AI
 * useful at all, so this runs them for real and type-checks the result: generated code that does not compile is
 * worse than none. `recipes-contract.test.ts` covers the library's rules; this covers what it actually produces.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../../src/config.js';
import { deriveDesign, loadFrameworks, loadKnowledge } from '../../src/integration.js';
import { TemplateManifestSchema } from '@shared/knowledge.js';
import { applyRecipes } from '../../src/generator/recipes/apply.js';
import { clinicBookings, habitTracker, teamInventory } from '../fixtures/design/profiles.js';

const templateDir = join(REPO_ROOT, 'templates', 'secure-web-app');
const manifest = TemplateManifestSchema.parse(JSON.parse(readFileSync(join(templateDir, 'securevibe.manifest.json'), 'utf8')));
const templateExists = existsSync(join(templateDir, 'src', 'features', 'index.ts'));

function copyTemplate(): string {
  const dir = mkdtempSync(join(tmpdir(), 'securevibe-expand-'));
  const appDir = join(dir, 'app');
  cpSync(templateDir, appDir, { recursive: true, dereference: true, filter: (src) => !src.includes('node_modules') && !src.includes(`${appDir}/data`) });
  return appDir;
}

describe.skipIf(!templateExists)('the recipe library against the real template', () => {
  it('writes a complete feature for every record type the person described', async () => {
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(habitTracker, { knowledge, frameworks });

      const result = await applyRecipes({ appDir, manifest, design, profile: habitTracker, runId: 'r_20260101000000_aaaaaa' });

      expect(result.applications).toHaveLength(1);
      const habit = result.applications[0]!;
      expect(habit.recipeId).toBe('record-type');
      expect(habit.recipeVersion).toBe('1');
      expect(habit.instance).toBe('habit');
      // The application names the files it wrote, which is how a later build or the version diff knows their source.
      expect(habit.files).toContain('src/features/habit/repo.ts');
      expect(habit.files).toContain('tests/features/habit.test.ts');
      // And it says, in the owner's language, what the app gained.
      expect(habit.description.toLowerCase()).toContain('habit');

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

      // The requirement mapping is only worth anything if the named tests are in the emitted file: this is the
      // chain from "the recipe claims V8.2.2" to "a test that says V8.2.2 ran and passed".
      const testFile = readFileSync(join(appDir, 'tests', 'features', 'habit.test.ts'), 'utf8');
      expect(habit.requirements.length).toBeGreaterThan(0);
      for (const requirement of habit.requirements) {
        expect(requirement.test.startsWith(requirement.id), `${requirement.test} must start with ${requirement.id}`).toBe(true);
        expect(testFile, `the test named in the mapping for ${requirement.id} must exist`).toContain(`test('${requirement.test}'`);
      }
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
      const result = await applyRecipes({ appDir, manifest, design, profile: teamInventory, runId: 'r_20260101000000_bbbbbb' });

      const item = result.applications.find((a) => a.instance === 'item');
      expect(item).toBeDefined();
      if (design.buildSpec.features.uploads) {
        expect(item!.notes).toHaveLength(0);
      } else {
        expect(item!.notes.some((n) => n.includes('photo'))).toBe(true);
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
      const result = await applyRecipes({ appDir, manifest, design, profile: clinicBookings, runId: 'r_20260101000000_cccccc' });
      expect(result.applications.length).toBeGreaterThan(0);

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
