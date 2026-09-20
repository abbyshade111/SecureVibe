/**
 * The spec a record type is queried through, held to the engine's own rules and to one rule the engine cannot know.
 *
 * `assertUsableSpec` in the template runs on every request, not once at build time, so a spec this emitter can
 * produce and the engine refuses is not a build error — it is an app that throws on every list. That is worth
 * catching here, in our suite, rather than from somebody's running app. So the emitter's output for every fixture
 * profile goes through the template's own checker, imported rather than copied: a copy is a thing that goes stale
 * and then agrees with us.
 *
 * And one rule the checker cannot enforce, because the word does not exist in the spec. The engine refuses a
 * *scrambled* column that claims to be searchable or sortable, but "sensitive" lives in the person's answers, not in
 * the query spec, so a sensitive-but-unencrypted column marked filterable would sail through. Our rule — a field
 * marked sensitive may be neither searched, sorted nor filtered, because a filter is a question whose answer reveals
 * the value to somebody who may not read it — is enforced only by the emitter, so it is asserted only here.
 */
import { describe, expect, it } from 'vitest';
import { assertUsableSpec, type QuerySpec } from '../../../templates/secure-web-app/src/db/query.ts';
import { DEFAULT_PAGE_SIZE } from '../../../templates/secure-web-app/src/db/limits.ts';
import { planEntity } from '../../src/generator/recipes/record-type/fields.js';
import { queryPlanOf } from '../../src/generator/recipes/record-type/query.js';
import { allProfiles } from '../fixtures/design/profiles.js';

/** The spec as the emitted module will hold it, built from the same plan the emitter builds it from. */
function specFor(entity: Parameters<typeof planEntity>[0], uploads: boolean): { spec: QuerySpec; plan: ReturnType<typeof planEntity> } {
  const plan = planEntity(entity, { uploads });
  const query = queryPlanOf(plan);
  const spec: QuerySpec = {
    table: plan.table,
    columns: query.columns.map((c) => ({
      column: c.column,
      label: c.label,
      kind: c.kind,
      ...(c.searchable ? { searchable: true } : {}),
      ...(c.sortable ? { sortable: true } : {}),
      ...(c.filterable ? { filterable: true } : {}),
      ...(c.encrypted ? { encrypted: true } : {}),
      ...(c.choices.length > 0 ? { choices: c.choices } : {}),
    })),
    defaultSort: query.defaultSort,
    pageSize: DEFAULT_PAGE_SIZE,
  };
  return { spec, plan };
}

describe('the query spec a record type is listed through', () => {
  for (const { name, profile } of allProfiles) {
    const entities = (profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
    for (const entity of entities) {
      it(`${name}/${entity.name}: is a spec the template's own engine accepts`, () => {
        const { spec } = specFor(entity, true);
        // Throws on a scrambled column claiming to be searchable, a number claiming to be searchable, a duplicate,
        // a name that is not a plain identifier, or a default sort that is not a listed column.
        expect(() => assertUsableSpec(spec)).not.toThrow();
      });

      it(`${name}/${entity.name}: never lets a sensitive field be searched, sorted or narrowed down by`, () => {
        const { spec, plan } = specFor(entity, true);
        const sensitive = new Set(plan.fields.filter((f) => f.field.sensitive).map((f) => f.column));
        const offered = spec.columns.filter((c) => sensitive.has(c.column) && (c.searchable || c.sortable || c.filterable));
        expect(
          offered.map((c) => c.column),
          'a field the person marked sensitive must not be answerable through the list',
        ).toEqual([]);
      });

      it(`${name}/${entity.name}: lists every column the row has, so no field vanishes from the page`, () => {
        const { spec, plan } = specFor(entity, true);
        // The engine selects the columns the spec names plus the row's own four, so a column left out is a field
        // that silently stops appearing — the kind of bug that survives a long time because nothing fails.
        expect(spec.columns.map((c) => c.column).sort()).toEqual(plan.fields.map((f) => f.column).sort());
      });
    }
  }
});
