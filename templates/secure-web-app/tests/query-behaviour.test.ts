/**
 * How the list-query builder behaves, as opposed to what it is evidence for.
 *
 * Deliberately no requirement id on these test names, and so deliberately not in `tests/security/`. Each of
 * these checks something the builder genuinely does — and none of them checks the requirement it would have to
 * be named after to live next door. Escaping a search wildcard is about the search finding the right rows, not
 * about SQL injection. A sort menu agreeing with the builder is internal consistency. Refusing to sort by the
 * owner column keeps one person's activity from being inferred from a shared list, which is a real thing to
 * want and is not the direct-object-reference problem V8.2.2 describes.
 *
 * They were in `tests/security/query.test.ts` until SecureVibe's own test-name-match checker flagged eight of
 * them across all five golden apps. It was right: a test named after a requirement it does not check quietly
 * credits the wrong control, and credit is the whole point of the naming rule. They run exactly as before and
 * claim nothing.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { assertUsableSpec, buildListQuery, likePattern, sortableColumns } from '../src/db/query.ts';
import { spec, mine, everyone, clauses } from './helpers/query-spec.ts';

describe('list query behaviour', () => {
  test('search wildcards are escaped, so looking for a per-cent sign does not match everything', () => {
    assert.equal(likePattern('100%'), '%100\\%%');
    assert.equal(likePattern('a_b'), '%a\\_b%');
    assert.equal(likePattern('back\\slash'), '%back\\\\slash%');
    const built = buildListQuery(spec, mine, { search: '%' });
    assert.match(built.sql, /LIKE \? ESCAPE '\\'/, 'the LIKE must declare its escape character');
    assert.ok(built.params.includes('%\\%%'), 'the wildcard should have been escaped before binding');
  });

  test('a field stored scrambled can be neither searched nor sorted, and saying otherwise is refused', () => {
    // Not an access-control test: the database holds ciphertext, so comparing it would compare the scrambling.
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'secret_note', label: 'Private note', kind: 'text', encrypted: true, searchable: true }] }), /scrambled/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'secret_note', label: 'Private note', kind: 'text', encrypted: true, sortable: true }] }), /scrambled/);
    const built = buildListQuery(spec, mine, { search: 'anything' });
    assert.doesNotMatch(clauses(built.sql), /secret_note/, 'a scrambled column must not be part of a search');
  });

  test('a spec that could only behave surprisingly is refused rather than written', () => {
    assert.throws(() => assertUsableSpec({ ...spec, columns: [spec.columns[0]!, spec.columns[0]!] }), /listed twice/);
    assert.throws(() => assertUsableSpec({ ...spec, defaultSort: { column: 'nope', direction: 'asc' } }), /default sort/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'amount', label: 'Amount', kind: 'number', searchable: true }] }), /would not mean anything/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'status', label: 'Status', kind: 'choice', filterable: true }] }), /no choices/);
  });

  test('a shared list is never ordered by who added the records', () => {
    // Ordering a shared list by owner both groups it by person and, read twice a minute apart, says something
    // about how much each person is adding. Nobody asked for either to be published.
    const built = buildListQuery(spec, everyone, { sort: 'owner_id' });
    assert.doesNotMatch(clauses(built.sql), /ORDER BY owner_id/);
    assert.match(built.sql, /ORDER BY updated_at DESC/);
    assert.match(built.applied.ignored.join(' '), /cannot be sorted by "owner_id"/);
    // It is still selected, because a page has to know whose row it is showing.
    assert.match(built.sql, /^SELECT [^]*owner_id[^]*FROM/);
  });

  test('a filter is checked against what the field actually is, and an impossible one is dropped', () => {
    const bad = buildListQuery(spec, mine, { filters: { status: 'deleted', amount: 'lots', done: 'perhaps', nonsense: 'x' } });
    assert.deepEqual(bad.applied.filters, [], 'none of those filters should have been applied');
    assert.equal(bad.applied.ignored.length, 4, `expected four explanations, got ${JSON.stringify(bad.applied.ignored)}`);
    assert.ok(bad.applied.ignored.every((line) => line.endsWith('.')), 'each explanation should read as a sentence');
    const good = buildListQuery(spec, mine, { filters: { status: 'open', done: 'yes' } });
    assert.deepEqual(
      good.applied.filters.map((f) => `${f.column}=${f.value}`).sort(),
      ['done=yes', 'status=open'],
      'both filters should have been applied, with the values the person will see on the page',
    );
    assert.equal(good.applied.ignored.length, 0);
    assert.ok(good.params.includes(1), 'a yes should be bound as 1');
  });

  test('what was ignored is reported rather than quietly dropped', () => {
    const built = buildListQuery(spec, mine, { sort: 'nope', direction: 'sideways' });
    assert.equal(built.applied.ignored.length, 2);
    assert.match(built.applied.ignored.join(' '), /cannot be sorted by "nope"/);
    assert.equal(built.applied.sort, 'updated_at');
    assert.equal(built.applied.sortLabel, 'when it was last changed');
    const far = buildListQuery(spec, mine, { page: 99_999_999 });
    assert.match(far.applied.ignored.join(' '), /never more than 10000 pages/);
    const many = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`f${i}`, 'x']));
    assert.match(buildListQuery(spec, mine, { filters: many }).applied.ignored.join(' '), /Only the first 20/);
  });

  test('the sort menu offers only columns the builder would accept', () => {
    for (const { column } of sortableColumns(spec)) {
      const built = buildListQuery(spec, mine, { sort: column });
      assert.equal(built.applied.sort, column, `the menu offers "${column}" but the builder refused it`);
      assert.equal(built.applied.ignored.length, 0);
    }
  });
});
