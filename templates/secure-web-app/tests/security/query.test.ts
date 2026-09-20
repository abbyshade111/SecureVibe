/**
 * The list-query builder (TPL-QUERY-01). These are unit tests on the SQL that comes out, deliberately, because
 * the property worth proving is not "the list looked right on screen" — a list that leaks another person's
 * records looks perfectly right on screen. It is "the ownership clause is in the statement, and nothing a
 * visitor typed is in the statement". Both are things you can only see by reading the SQL.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { assertUsableSpec, buildListQuery, likePattern, sortableColumns, type QuerySpec } from '../../src/db/query.ts';

const spec: QuerySpec = {
  table: 'notes',
  columns: [
    { column: 'title', label: 'Title', kind: 'text', searchable: true, sortable: true },
    { column: 'body', label: 'Notes', kind: 'text', searchable: true },
    { column: 'amount', label: 'Amount', kind: 'number', sortable: true, filterable: true },
    { column: 'done', label: 'Finished', kind: 'boolean', filterable: true },
    { column: 'status', label: 'Status', kind: 'choice', filterable: true, choices: ['open', 'closed'] },
    { column: 'secret_note', label: 'Private note', kind: 'text', encrypted: true },
  ],
  defaultSort: { column: 'updated_at', direction: 'desc' },
  pageSize: 20,
};

/** Everything after the table name: the clauses a request can influence, without the column list it cannot. */
function clauses(sql: string): string {
  return sql.slice(sql.indexOf(' FROM '));
}

const mine = { kind: 'owner', ownerId: 'user-1' } as const;
const everyone = { kind: 'everyone', because: 'this list is public to read' } as const;

describe('list queries', () => {
  test('V8.2.2 a query for one person always carries the ownership check, whatever else was asked for', () => {
    const requests = [
      {},
      { search: 'anything' },
      { sort: 'amount', direction: 'asc' },
      { page: 7 },
      { filters: { status: 'open' } },
      { search: 'x', sort: 'title', direction: 'desc', page: 3, filters: { done: 'yes', amount: '5' } },
    ];
    for (const req of requests) {
      const built = buildListQuery(spec, mine, req);
      assert.match(built.sql, /WHERE owner_id = \?/, `owner check missing for ${JSON.stringify(req)}`);
      assert.match(built.countSql, /WHERE owner_id = \?/, `owner check missing from the count for ${JSON.stringify(req)}`);
      assert.equal(built.params[0], 'user-1', 'the owner must be the first bound value');
      assert.equal(built.countParams[0], 'user-1');
    }
  });

  test('V8.2.2 reading everyone\u2019s records is a sentence somebody wrote, not a scope left off', () => {
    const built = buildListQuery(spec, everyone, {});
    assert.doesNotMatch(clauses(built.sql), /WHERE/, 'an everyone query should not be scoped at all');
    // The type system stops this at build time; this is the runtime half of the same fence.
    assert.throws(() => buildListQuery(spec, undefined as never, {}), /needs a scope/);
    assert.throws(() => buildListQuery(spec, { kind: 'all' } as never, {}), /needs a scope/);
  });

  test('V1.2.4 a sort column that is not on the allow-list never reaches the SQL', () => {
    const attempts = ['id; DROP TABLE notes', 'body', '(SELECT 1)', 'title--', 'secret_note', 'owner_id, 1'];
    for (const sort of attempts) {
      const built = buildListQuery(spec, mine, { sort });
      assert.match(built.sql, /ORDER BY updated_at DESC, id ASC/, `"${sort}" changed the sort`);
      assert.doesNotMatch(clauses(built.sql), /DROP|SELECT 1|--/, `"${sort}" reached the SQL`);
    }
    // A column the spec does allow is used, so the allow-list is doing the work rather than a blanket refusal.
    assert.match(buildListQuery(spec, mine, { sort: 'amount', direction: 'asc' }).sql, /ORDER BY amount ASC/);
  });

  test('V1.2.4 the sort direction can only ever be one of two words', () => {
    for (const direction of ['asc); DROP TABLE notes --', 'ASC, owner_id', 'sideways', '']) {
      const built = buildListQuery(spec, mine, { sort: 'amount', direction });
      assert.match(built.sql, /ORDER BY amount (ASC|DESC), id ASC LIMIT \? OFFSET \?$/, `"${direction}" got through`);
    }
    assert.match(buildListQuery(spec, mine, { sort: 'amount', direction: 'ASC' }).sql, /amount ASC/, 'capitals are still a direction');
  });

  test('V1.2.4 everything a person typed is a bound value and none of it is in the statement', () => {
    const nasty = "' OR 1=1 --";
    const built = buildListQuery(spec, mine, { search: nasty, filters: { status: 'open', amount: '42' } });
    assert.ok(!built.sql.includes(nasty), 'a typed value reached the SQL text');
    assert.doesNotMatch(built.sql, /OR 1=1|--/, 'a typed value reached the SQL text');
    // The only quotation marks in a built statement belong to the LIKE escape clause, which we wrote ourselves.
    assert.deepEqual(built.sql.match(/'[^']*'/g), ["'\\'", "'\\'"], 'the only quoted text should be the two ESCAPE clauses');
    assert.ok(built.params.some((p) => typeof p === 'string' && p.includes(nasty)), 'the search should be a bound parameter');
    assert.ok(built.params.includes(42), 'the number filter should be a bound parameter');
    assert.ok(built.params.includes('open'), 'the choice filter should be a bound parameter');
  });

  test('V1.2.4 search wildcards are escaped, so looking for a per-cent sign does not match everything', () => {
    assert.equal(likePattern('100%'), '%100\\%%');
    assert.equal(likePattern('a_b'), '%a\\_b%');
    assert.equal(likePattern('back\\slash'), '%back\\\\slash%');
    const built = buildListQuery(spec, mine, { search: '%' });
    assert.match(built.sql, /LIKE \? ESCAPE '\\'/, 'the LIKE must declare its escape character');
    assert.ok(built.params.includes('%\\%%'), 'the wildcard should have been escaped before binding');
  });

  test('V1.2.4 a field stored scrambled can be neither searched nor sorted, and saying otherwise is refused', () => {
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'secret_note', label: 'Private note', kind: 'text', encrypted: true, searchable: true }] }), /scrambled/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'secret_note', label: 'Private note', kind: 'text', encrypted: true, sortable: true }] }), /scrambled/);
    // And an encrypted column is not silently searched by a search that names no column.
    const built = buildListQuery(spec, mine, { search: 'anything' });
    assert.doesNotMatch(clauses(built.sql), /secret_note/, 'a scrambled column must not be part of a search');
  });

  test('V1.2.4 a spec that could only behave surprisingly is refused rather than written', () => {
    assert.throws(() => assertUsableSpec({ ...spec, table: 'notes; DROP TABLE users' }), /plain identifier/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'a b', label: 'A', kind: 'text' }] }), /plain identifier/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [spec.columns[0]!, spec.columns[0]!] }), /listed twice/);
    assert.throws(() => assertUsableSpec({ ...spec, defaultSort: { column: 'nope', direction: 'asc' } }), /default sort/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'amount', label: 'Amount', kind: 'number', searchable: true }] }), /would not mean anything/);
  });

  test('V8.2.2 the statement names the columns it wants, so a later migration cannot widen every list', () => {
    const built = buildListQuery(spec, mine, {});
    assert.doesNotMatch(built.sql, /SELECT \*/, 'a list should never ask for every column');
    const selected = /^SELECT (.+?) FROM/.exec(built.sql)?.[1]?.split(', ') ?? [];
    assert.deepEqual(
      [...selected].sort(),
      ['amount', 'created_at', 'done', 'id', 'owner_id', 'secret_note', 'status', 'title', 'updated_at', 'body'].sort(),
      'every column of the row, and nothing that is not a column of the row',
    );
    // The point of naming them: a column that arrives later is not selected until the spec says so.
    const widened = buildListQuery({ ...spec, columns: [...spec.columns, { column: 'added_later', label: 'Added later', kind: 'text' }] }, mine, {});
    assert.match(widened.sql, /added_later/);
    assert.doesNotMatch(built.sql, /added_later/);
  });

  test('V8.2.2 a list can never be ordered by who added the rows', () => {
    const built = buildListQuery(spec, everyone, { sort: 'owner_id' });
    assert.doesNotMatch(clauses(built.sql), /ORDER BY owner_id/, 'sorting by owner groups a shared list by person');
    assert.match(built.sql, /ORDER BY updated_at DESC/);
    assert.match(built.applied.ignored.join(' '), /cannot be sorted by "owner_id"/);
    // It is still selected, because a page has to know whose row it is showing.
    assert.match(built.sql, /^SELECT [^]*owner_id[^]*FROM/);
  });

  test('V2.4.1 a request cannot page past the end of the world, or send an unbounded pile of filters', () => {
    const far = buildListQuery(spec, mine, { page: 99_999_999 });
    assert.equal(far.applied.page, 10_000, 'the page number should have been capped');
    assert.equal(far.params.at(-1), (10_000 - 1) * 20, 'the offset follows the capped page');
    assert.match(far.applied.ignored.join(' '), /never more than 10000 pages/);

    const many = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`f${i}`, 'x']));
    const piled = buildListQuery(spec, mine, { filters: many });
    assert.equal(piled.applied.filters.length, 0, 'none of those are real columns');
    assert.ok(piled.applied.ignored.length <= 21, `expected the filters to be capped, got ${piled.applied.ignored.length} explanations`);
    assert.match(piled.applied.ignored.join(' '), /Only the first 20/);
  });

  test('V2.4.1 every list query is bounded and a page size cannot be raised past the cap', () => {
    const built = buildListQuery(spec, mine, { page: 3 });
    assert.match(built.sql, /LIMIT \? OFFSET \?$/);
    assert.equal(built.applied.pageSize, 20);
    assert.equal(built.applied.offset, 40);
    const huge = buildListQuery({ ...spec, pageSize: 10_000 }, mine, {});
    assert.ok(huge.applied.pageSize <= 200, `the page size should have been clamped, got ${huge.applied.pageSize}`);
    for (const page of [0, -5, Number.NaN, undefined]) {
      assert.equal(buildListQuery(spec, mine, { page }).applied.page, 1, `page ${String(page)} should fall back to the first page`);
    }
  });

  test('V1.2.4 a filter is checked against what the field actually is, and an impossible one is dropped', () => {
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

  test('V1.2.4 what was ignored is reported rather than quietly dropped', () => {
    const built = buildListQuery(spec, mine, { sort: 'nope', direction: 'sideways' });
    assert.equal(built.applied.ignored.length, 2);
    assert.match(built.applied.ignored.join(' '), /cannot be sorted by "nope"/);
    assert.equal(built.applied.sort, 'updated_at');
    assert.equal(built.applied.sortLabel, 'when it was last changed');
  });

  test('V1.2.4 the sort menu offers only columns the builder would accept', () => {
    for (const { column } of sortableColumns(spec)) {
      const built = buildListQuery(spec, mine, { sort: column });
      assert.equal(built.applied.sort, column, `the menu offers "${column}" but the builder refused it`);
      assert.equal(built.applied.ignored.length, 0);
    }
  });
});
