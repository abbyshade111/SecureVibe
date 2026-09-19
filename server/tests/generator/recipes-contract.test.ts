/**
 * The recipe library's own contract (server/src/generator/recipes/types.ts). These checks are what stop a recipe
 * from becoming a code generator that merely claims to be secure:
 *
 *  - a recipe may only write where the generation agent may write (the template manifest's `writablePaths`);
 *  - every requirement a recipe claims must name a test the recipe actually emits, and that test's name must
 *    start with the requirement id, because that is how `compliance/evidence.ts` turns a test result into
 *    evidence — a claim with no test behind it would be a green tick from nothing;
 *  - every requirement id must exist in the framework data;
 *  - identities are unique and stable, and the files a recipe emits carry the provenance header.
 *
 * It runs against every golden profile, so a new recipe is held to all of them, and it needs no ports, no
 * template copy and no model call.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TemplateManifestSchema } from '@shared/knowledge.js';
import { REPO_ROOT } from '../../src/config.js';
import { testMatchesRequirement } from '../../src/compliance/evidence.js';
import { matchesRequirement, testBody } from '../../src/compliance/test-name-match.js';
import { deriveDesign, loadFrameworks, loadKnowledge } from '../../src/integration.js';
import { contentSha256File, matchesAnyGlob, sha256 } from '../../src/generator/files.js';
import { matchesAny } from '../../src/llm/tools.js';
import { applyRecipes } from '../../src/generator/recipes/apply.js';
import { RECIPES } from '../../src/generator/recipes/registry.js';
import type { AnyRecipe, RecipeContext } from '../../src/generator/recipes/types.js';
import { allProfiles } from '../fixtures/design/profiles.js';

const manifest = TemplateManifestSchema.parse(JSON.parse(readFileSync(join(REPO_ROOT, 'templates', 'secure-web-app', 'securevibe.manifest.json'), 'utf8')));
const frameworks = loadFrameworks();
const knowledge = loadKnowledge();

function contextFor(profileName: string): RecipeContext {
  const profile = allProfiles.find((p) => p.name === profileName)!.profile;
  const design = deriveDesign(profile, { knowledge, frameworks });
  let migration = 100;
  return { design, profile, features: design.buildSpec.features, runId: 'r_20260101000000_contract', nextMigrationNumber: () => migration++ };
}

describe('the recipe library holds to its contract', () => {
  it('gives every recipe a unique, stable identity and plain-language copy', () => {
    const ids = RECIPES.map((r) => r.id);
    expect(new Set(ids).size, 'recipe ids must be unique').toBe(ids.length);
    for (const recipe of RECIPES) {
      expect(recipe.id, `${recipe.id} must be a lower-case, hyphenated id`).toMatch(/^[a-z][a-z0-9-]*$/);
      expect(recipe.version, `${recipe.id} must carry a version`).toMatch(/^\d+$/);
      // The owner reads these, so they must be sentences rather than identifiers.
      expect(recipe.title.length, `${recipe.id} needs a title`).toBeGreaterThan(8);
      expect(recipe.summary.length, `${recipe.id} needs a plain-language summary`).toBeGreaterThan(30);
      expect(recipe.title).not.toMatch(/[_{}<>]/);
      expect(recipe.summary).not.toMatch(/[_{}<>]/);
    }
  });

  it('holds recipes to the same fence as the generation agent', () => {
    // The recipe runner uses the generator's glob matcher and the agent's write tool uses its own. If the two
    // disagree about a path in the manifest, one of them is enforcing a fence nobody wrote down.
    const paths = [
      'src/features/booking/index.ts',
      'src/features/index.ts',
      'src/views/booking/list.ejs',
      'src/db/migrations/100_bookings.sql',
      'src/db/migrations/012_users.sql',
      'tests/features/booking.test.ts',
      'tests/security/authz.test.ts',
      'routes.manifest.json',
      'src/security/authz.ts',
      'src/app.ts',
      'package.json',
      '.env',
      'src/features/ai/prompt.ts',
      'src/features/ai/index.ts',
    ];
    for (const list of [manifest.writablePaths, manifest.protectedPaths]) {
      for (const path of paths) {
        expect(matchesAnyGlob(path, list), `the two matchers disagree about ${path}`).toBe(matchesAny(path, list));
      }
    }
    // And the fence really does let a recipe's migration through, which is what SC-16 promises.
    expect(matchesAnyGlob('src/db/migrations/100_bookings.sql', manifest.writablePaths)).toBe(true);
    expect(matchesAnyGlob('src/db/migrations/012_users.sql', manifest.writablePaths), 'the template\u2019s own migrations stay out of reach').toBe(false);
  });

  for (const { name } of allProfiles) {
    describe(`against the ${name} design`, () => {
      // A fresh context per check, so the migration numbers a recipe is handed are the same every time.
      const fresh = (): RecipeContext => contextFor(name);

      it('only writes files the generation agent is also allowed to write', () => {
        const ctx = fresh();
        for (const recipe of RECIPES) {
          for (const instance of recipe.plan(ctx)) {
            for (const file of recipe.emit(instance, ctx).files) {
              expect(matchesAnyGlob(file.path, manifest.writablePaths), `${recipe.id}/${instance.id} wrote ${file.path}, which is not in the template's writable paths`).toBe(true);
            }
          }
        }
      });

      it('never has two recipes write the same file or claim the same migration number', () => {
        const ctx = fresh();
        const owners = new Map<string, string>();
        const clashes: string[] = [];
        for (const recipe of RECIPES) {
          for (const instance of recipe.plan(ctx)) {
            for (const file of recipe.emit(instance, ctx).files) {
              const owner = `${recipe.id}/${instance.id}`;
              const already = owners.get(file.path);
              if (already !== undefined) clashes.push(`${file.path}: ${already} and ${owner}`);
              else owners.set(file.path, owner);
            }
          }
        }
        expect(clashes, 'two recipes must never write the same path').toEqual([]);
      });

      it('proves every requirement it claims with a test it actually emits', () => {
        const ctx = fresh();
        let claims = 0;
        for (const recipe of RECIPES) {
          for (const instance of recipe.plan(ctx)) {
            const emission = recipe.emit(instance, ctx);
            const testSources = emission.files.filter((f) => f.path.startsWith('tests/')).map((f) => f.contents);
            for (const requirement of emission.requirements) {
              claims += 1;
              // The id must be real.
              expect(frameworks.getRequirement(requirement.id), `${recipe.id} claims ${requirement.id}, which is not a known requirement`).toBeDefined();
              // The compliance engine credits a test to a requirement by the test's own name; if the id is not at
              // the front of the name the claim would produce no evidence at all.
              expect(testMatchesRequirement(requirement.test, requirement.id), `the test name "${requirement.test}" must start with ${requirement.id} or it will never be credited`).toBe(true);
              // And the test has to exist in what the recipe wrote.
              const emitted = testSources.some((src) => src.includes(`test('${requirement.test}'`));
              expect(emitted, `${recipe.id}/${instance.id} claims ${requirement.id} but emits no test named "${requirement.test}"`).toBe(true);
              expect(requirement.proves.length, `${requirement.id} needs a plain-language sentence saying what the test shows`).toBeGreaterThan(20);
              // The name is emitted inside a single-quoted literal, so a quote or backslash in it would produce a
              // generated test file that does not parse.
              expect(requirement.test, 'a test name cannot contain a quote or a backslash').not.toMatch(/['\\]/);
            }
          }
        }
        expect(claims, 'the library must evidence something').toBeGreaterThan(0);
      });

      it('names its tests so the test-name screen recognises them', () => {
        // A test whose name says nothing its requirement says produces a finding on every build and puts a person
        // in front of a comparison that was never worth their time. The recipes own their names, so they carry the
        // cost of getting them right: each name restates the requirement in the plain words the reports use. This
        // runs the screen exactly as pipeline/stages/unit-tests.ts runs it, id stripped off the front and all.
        const ctx = fresh();
        const unsupported: string[] = [];
        for (const recipe of RECIPES) {
          for (const instance of recipe.plan(ctx)) {
            const emission = recipe.emit(instance, ctx);
            const sources = emission.files
              .filter((f) => f.path.startsWith('tests/'))
              .map((f) => f.contents)
              .join('\n');
            for (const requirement of emission.requirements) {
              const description = frameworks.getRequirement(requirement.id)?.description;
              const plain = knowledge.requirementsPlain[requirement.id]?.plain;
              const text = `${requirement.test.slice(requirement.id.length)}\n${testBody(sources, requirement.test)}`;
              const verdict = matchesRequirement(text, description ? { description, ...(plain ? { plain } : {}) } : undefined);
              if (verdict.match === 'unsupported') unsupported.push(`${recipe.id}/${instance.id} ${requirement.id}: ${requirement.test}`);
            }
          }
        }
        expect(unsupported, 'every recipe test name must share vocabulary with the requirement it cites').toEqual([]);
      });

      it('writes plain-language descriptions and a provenance header on every code file', () => {
        const ctx = fresh();
        for (const recipe of RECIPES) {
          for (const instance of recipe.plan(ctx)) {
            const emission = recipe.emit(instance, ctx);
            expect(emission.description.length, `${recipe.id}/${instance.id} needs a description for the owner`).toBeGreaterThan(40);
            expect(emission.description, 'descriptions are for a reader who is not a programmer').not.toMatch(/[{}<>]|\bDTO\b|\bCRUD\b/);
            for (const file of emission.files) {
              if (!/\.(ts|sql)$/.test(file.path)) continue;
              expect(file.contents.startsWith(`// Generated by SecureVibe (recipe ${recipe.id})`) || file.contents.startsWith(`-- Generated by SecureVibe (recipe ${recipe.id})`), `${file.path} must start with the recipe's provenance header`).toBe(true);
            }
          }
        }
      });
    });
  }

  it('hashes a recipe file the same across runs once the run id is out of the way', () => {
    // A rebuild needs to tell "this file is byte-for-byte what the earlier check read" from "this file was merely
    // written again". Only the provenance header differs between two builds of an unchanged file, so `sha256`
    // cannot answer that and `contentSha256` can.
    const dir = mkdtempSync(join(tmpdir(), 'securevibe-recipe-hash-'));
    try {
      const recipe = RECIPES.find((r) => r.id === 'record-type')!;
      const written: string[] = [];
      for (const runId of ['r_20260101000000_first', 'r_20260202000000_second']) {
        const ctx = { ...contextFor('clinicBookings'), runId };
        const instance = recipe.plan(ctx)[0]!;
        const file = recipe.emit(instance, ctx).files.find((f) => f.path.endsWith('repo.ts'))!;
        const path = join(dir, `${runId}.ts`);
        writeFileSync(path, file.contents, 'utf8');
        written.push(path);
      }
      const [first, second] = written as [string, string];
      expect(readFileSync(first, 'utf8')).not.toEqual(readFileSync(second, 'utf8'));
      expect(sha256(readFileSync(first))).not.toEqual(sha256(readFileSync(second)));
      expect(contentSha256File(first)).toEqual(contentSha256File(second));
      // And it still notices a real change.
      writeFileSync(second, `${readFileSync(second, 'utf8')}\n// an edit\n`, 'utf8');
      expect(contentSha256File(first)).not.toEqual(contentSha256File(second));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses to write a recipe that strays outside the files the agent may change', async () => {
    // The fence is the point: a recipe is not trusted more than the generation agent is. A recipe that tries to
    // reach a protected file is stopped whole, so an app is never left with half a feature.
    const rogue: AnyRecipe = {
      id: 'rogue-for-test',
      version: '1',
      title: 'A step that tries to reach a protected file',
      summary: 'Only used by this test: it tries to write somewhere it is not allowed to, and must be refused.',
      plan: () => [{ id: 'rogue', label: 'Rogue' }],
      emit: () => ({
        description: 'This step should never manage to write anything at all, in any application.',
        files: [
          { path: 'src/features/rogue/index.ts', contents: '// Generated by SecureVibe (recipe rogue-for-test) — run r\n' },
          { path: 'src/security/authz.ts', contents: '// nope\n' },
        ],
        routes: [],
        requirements: [],
        notes: [],
      }),
    };
    const appDir = mkdtempSync(join(tmpdir(), 'securevibe-recipe-fence-'));
    RECIPES.push(rogue);
    try {
      const ctx = contextFor('habitTracker');
      const result = await applyRecipes({ appDir, manifest, design: ctx.design, profile: ctx.profile, runId: 'r_20260101000000_fence', only: ['rogue-for-test'] });
      expect(result.applications, 'nothing may be recorded for a refused recipe').toEqual([]);
      expect(existsSync(join(appDir, 'src', 'security', 'authz.ts')), 'the protected file must not be written').toBe(false);
      expect(existsSync(join(appDir, 'src', 'features', 'rogue', 'index.ts')), 'the allowed file must not be written either: the recipe is refused whole').toBe(false);
      expect(result.warnings.join(' ')).toMatch(/outside the files it is allowed to change/);
    } finally {
      RECIPES.splice(RECIPES.indexOf(rogue), 1);
      rmSync(appDir, { recursive: true, force: true });
    }
  });
});
