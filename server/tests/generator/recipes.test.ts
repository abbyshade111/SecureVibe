/**
 * The recipe library against a real copy of the template. Recipes are the path that makes a build without AI
 * useful at all, so this runs them for real and type-checks the result: generated code that does not compile is
 * worse than none. `recipes-contract.test.ts` covers the library's rules; this covers what it actually produces.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../../src/config.js';
import { deriveDesign, loadFrameworks, loadKnowledge } from '../../src/integration.js';
import { TemplateManifestSchema } from '@shared/knowledge.js';
import { applyRecipes } from '../../src/generator/recipes/apply.js';
import { manifestFeatureFlags } from '../../src/generator/scaffold.js';
import { runSast } from '../../src/scanners/sast/index.js';
import { makeScanContext } from '../scanners-static/helpers.js';
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

      // Two recipes apply: the record type itself, and a report over it (habits have a choice field to count by).
      expect(result.applications.map((a) => a.recipeId)).toEqual(['record-type', 'record-summary']);
      const habit = result.applications[0]!;
      expect(habit.recipeId).toBe('record-type');
      expect(habit.recipeVersion).toBe('3');
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

      // The report is its own page, away from the record's own paths, because /habits/:id would match "summary".
      const report = result.applications[1]!;
      expect(report.instance).toBe('habit-report');
      for (const rel of ['src/features/habit-report/index.ts', 'src/views/habit-report/index.ejs', 'tests/features/habit-report.test.ts']) {
        expect(existsSync(join(appDir, rel)), `${rel} must exist`).toBe(true);
      }
      const reportRoutes = routes.filter((r) => r.path === '/reports/habits');
      expect(reportRoutes).toHaveLength(1);
      expect(reportRoutes[0]!.method).toBe('GET');
      expect(reportRoutes[0]!.auth).not.toBe('public');
      expect(readFileSync(join(appDir, 'src', 'views', 'habit', 'list.ejs'), 'utf8')).toContain('href="/reports/habits"');
      // It reads and nothing else: no write of any kind reaches the table.
      const reportSource = readFileSync(join(appDir, 'src', 'features', 'habit-report', 'index.ts'), 'utf8');
      expect(reportSource).not.toMatch(/\b(INSERT|UPDATE|DELETE|ALTER|DROP)\b/);
      expect(reportSource).toMatch(/COUNT\(\*\)/);
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  });

  it('gives a record type with a file field its own attachment page, and keeps the column out of the record\u2019s own interface', async () => {
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(teamInventory, { knowledge, frameworks });
      expect(design.buildSpec.features.uploads, 'this design asks for file uploads').toBe(true);
      const result = await applyRecipes({ appDir, manifest, design, profile: teamInventory, runId: 'r_20260101000000_bbbbbb' });

      const item = result.applications.find((a) => a.recipeId === 'record-type' && a.instance === 'item');
      const files = result.applications.find((a) => a.recipeId === 'record-attachment' && a.instance === 'item-files');
      expect(item, 'the record type itself').toBeDefined();
      expect(files, 'its attachment feature').toBeDefined();
      // The file field is handled by the attachment recipe, so it is not reported as left out.
      expect(item!.notes).toEqual([]);

      // The record's own schema has no photo field: the column can only be written by attaching a file.
      const schema = readFileSync(join(appDir, 'src', 'features', 'item', 'schema.ts'), 'utf8');
      expect(schema).not.toMatch(/photo/);
      const itemMigration = readFileSync(join(appDir, 'src', 'db', 'migrations', '100_items.sql'), 'utf8');
      expect(itemMigration).not.toMatch(/photo/);
      // Money is stored as whole cents so totals never drift.
      expect(itemMigration).toMatch(/cost INTEGER/);

      // The attachment recipe adds the column, the routes, the page and its tests.
      const added = files!.files.find((f) => f.endsWith('_items_files.sql'))!;
      expect(readFileSync(join(appDir, added), 'utf8')).toMatch(/ALTER TABLE items ADD COLUMN photo TEXT;/);
      for (const rel of ['src/features/item-files/index.ts', 'src/views/item-files/index.ejs', 'tests/features/item-files.test.ts']) {
        expect(existsSync(join(appDir, rel)), `${rel} must exist`).toBe(true);
      }
      // Uploading goes through the template's own module, never through code the recipe wrote (SC-12).
      const routesSource = readFileSync(join(appDir, 'src', 'features', 'item-files', 'index.ts'), 'utf8');
      expect(routesSource).toContain("import { receiveUpload } from '../uploads/index.ts'");
      expect(routesSource, 'a recipe never parses a multipart body itself').not.toMatch(/from 'busboy'|require\('busboy'\)/);

      const features = readFileSync(join(appDir, 'src', 'features', 'index.ts'), 'utf8');
      expect(features).toContain("await import('./item-files/index.ts')");
      const routes = JSON.parse(readFileSync(join(appDir, 'routes.manifest.json'), 'utf8')) as { method: string; path: string; auth: string; csrf: boolean }[];
      const attach = routes.find((r) => r.path === '/items/:id/files/photo' && r.method === 'POST');
      expect(attach, 'the attach route must be in the manifest').toBeDefined();
      // The uploads module checks the Origin and the form token itself, because the body cannot be parsed first.
      expect(attach!.csrf).toBe(false);
      expect(attach!.auth).not.toBe('public');
      expect(routes.some((r) => r.path === '/items/:id/files/photo/remove' && r.csrf === true)).toBe(true);
      expect(routes.some((r) => r.path === '/items/:id/files' && r.method === 'GET')).toBe(true);
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  });

  it('leaves a file field out, and says why, when the uploads feature is off', async () => {
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      // The design engine turns the uploads feature on whenever any record has a file field, so this is the
      // defensive path rather than one a wizard answer can reach: the feature is forced off under a design that
      // still describes a file.
      const derived = deriveDesign(teamInventory, { knowledge, frameworks });
      const design = { ...derived, buildSpec: { ...derived.buildSpec, features: { ...derived.buildSpec.features, uploads: false } } };
      const result = await applyRecipes({ appDir, manifest, design, profile: teamInventory, runId: 'r_20260101000000_bbbb02' });

      expect(result.applications.some((a) => a.recipeId === 'record-attachment'), 'no attachment feature without uploads').toBe(false);
      const item = result.applications.find((a) => a.instance === 'item')!;
      expect(item.notes.some((n) => n.includes('photo'))).toBe(true);
      expect(result.warnings.join(' ')).toMatch(/uploads/i);
      expect(existsSync(join(appDir, 'src', 'features', 'item-files')), 'nothing may be written for it').toBe(false);
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  });

  it('produces code that compiles, attachments and all', async () => {
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(teamInventory, { knowledge, frameworks });
      const result = await applyRecipes({ appDir, manifest, design, profile: teamInventory, runId: 'r_20260101000000_bbbb03' });
      expect(result.applications.some((a) => a.recipeId === 'record-attachment')).toBe(true);

      cpSync(join(templateDir, 'node_modules'), join(appDir, 'node_modules'), { recursive: true, dereference: false });
      const tsc = join(appDir, 'node_modules', '.bin', 'tsc');
      const out = execFileSync(tsc, ['-p', join(appDir, 'tsconfig.json')], { cwd: appDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      expect(out.trim()).toBe('');
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  }, 300_000);

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

  it('writes nothing the static scan objects to', async () => {
    // The evaluation harness would catch this too, but only after a twenty-minute build of four apps. Running the
    // real rules over what the recipes just wrote turns that into a few seconds, and it is how the recipes are held
    // to the conventions the scan enforces on generated code — a query assembled at runtime, most of all.
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(teamInventory, { knowledge, frameworks });
      const result = await applyRecipes({ appDir, manifest, design, profile: teamInventory, runId: 'r_20260101000000_sast01' });
      const written = new Set(result.applications.flatMap((a) => a.files));
      expect(written.size).toBeGreaterThan(0);

      const scan = await runSast(makeScanContext(appDir, { manifest, buildSpec: design.buildSpec }));
      const ours = scan.findings.filter((f) => f.location?.file !== undefined && written.has(f.location.file));
      const serious = ours.filter((f) => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium');
      expect(serious.map((f) => `${f.ruleId} ${f.location?.file}:${f.location?.line ?? 0} — ${f.title}`)).toEqual([]);
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  }, 120_000);

  it('compiles when the features a design left out have been removed', async () => {
    // A copy of the template has every optional file in it; a real build deletes the files of every feature the
    // design switched off. Code that reaches one of those files still compiles here and fails in the app — which is
    // what happened: a test-mode helper imported src/lib/scheduler.ts, and every app without a scheduler stopped
    // compiling. This removes the same paths the scaffold removes before it checks.
    const appDir = copyTemplate();
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      // team-inventory has no scheduler, no email, no AI and no public interface: a good stress case.
      const design = deriveDesign(teamInventory, { knowledge, frameworks });
      const flags = manifestFeatureFlags(design.buildSpec, teamInventory);
      expect(flags.scheduler, 'this design must have the scheduler off for the test to mean anything').toBe(false);
      const removed: string[] = [];
      for (const feature of manifest.features) {
        if (flags[feature.id] !== false) continue;
        for (const rel of feature.paths) {
          if (!existsSync(join(appDir, rel))) continue;
          rmSync(join(appDir, rel), { recursive: true, force: true });
          removed.push(rel);
        }
      }
      expect(removed.length, 'some feature files must have been removed').toBeGreaterThan(0);
      writeFileSync(join(appDir, 'securevibe.features.json'), `${JSON.stringify(flags, null, 2)}\n`);

      await applyRecipes({ appDir, manifest, design, profile: teamInventory, runId: 'r_20260101000000_ff0001' });

      cpSync(join(templateDir, 'node_modules'), join(appDir, 'node_modules'), { recursive: true, dereference: false });
      const tsc = join(appDir, 'node_modules', '.bin', 'tsc');
      let out = '';
      try {
        execFileSync(tsc, ['-p', join(appDir, 'tsconfig.json')], { cwd: appDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (err) {
        out = String((err as { stdout?: string }).stdout ?? '');
      }
      expect(out.trim(), `removed: ${removed.join(', ')}`).toBe('');
    } finally {
      rmSync(appDir, { recursive: true, force: true });
    }
  }, 300_000);
});
