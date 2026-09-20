/**
 * The list-query builder, where it is evidence for a requirement (TPL-QUERY-01).
 *
 * These are unit tests on the SQL that comes out, deliberately, because the property worth proving is not "the
 * list looked right on screen" — a list that leaks another person's records looks perfectly right on screen. It
 * is "the ownership clause is in the statement, and nothing a visitor typed is in the statement". Both are
 * things you can only see by reading the SQL.
 *
 * Only tests that really are evidence for the requirement they name live here. The builder's other behaviour —
 * how it escapes a search, what it refuses to be configured as, what it reports back to the page — is tested in
 * `tests/query-behaviour.test.ts`, with no requirement id, because a test that names a requirement it does not
 * check credits the wrong control. Eight of these tests used to be in this file and were moved out for exactly
 * that reason, after SecureVibe's own test-name-match checker flagged them.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { buildListQuery, assertUsableSpec } from '../../src/db/query.ts';
import { spec, mine, everyone, clauses } from '../helpers/query-spec.ts';

describe('list queries', () => {
  test('V8.2.2 a query for one person restricts it to that person’s own records, whatever else was asked for', () => {
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

  test('V8.2.2 access to other people’s records cannot be obtained by leaving the scope off', () => {
    // There is no unscoped default. Reading everyone's records is a named choice carrying its own reason.
    assert.throws(() => buildListQuery(spec, undefined as never, {}), /needs a scope/);
    assert.throws(() => buildListQuery(spec, { kind: 'all' } as never, {}), /needs a scope/);
    const built = buildListQuery(spec, everyone, {});
    assert.doesNotMatch(clauses(built.sql), /WHERE/, 'the explicit everyone scope is the only way to read them all');
  });

  test('V8.2.2 a query returns only the data items it declares, so a column added later is not exposed by default', () => {
    const built = buildListQuery(spec, mine, {});
    assert.doesNotMatch(built.sql, /SELECT \*/, 'a list should never ask for every column');
    const selected = /^SELECT (.+?) FROM/.exec(built.sql)?.[1]?.split(', ') ?? [];
    assert.deepEqual(
      [...selected].sort(),
      ['amount', 'body', 'created_at', 'done', 'id', 'owner_id', 'secret_note', 'status', 'title', 'updated_at'],
      'every column of the row, and nothing that is not a column of the row',
    );
    const widened = buildListQuery({ ...spec, columns: [...spec.columns, { column: 'added_later', label: 'Added later', kind: 'text' }] }, mine, {});
    assert.match(widened.sql, /added_later/, 'a column is returned once the spec declares it');
    assert.doesNotMatch(built.sql, /added_later/, 'and not before');
  });

  test('V1.2.4 every value from a request is a bound parameter, so a database query cannot be injected into', () => {
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

  test('V1.2.4 SQL injection through the sort column is prevented: an unlisted column never reaches the query', () => {
    // The sort column is one of only two things that cannot be a bound parameter, so it is the injection route.
    const attempts = ['id; DROP TABLE notes', 'body', '(SELECT 1)', 'title--', 'secret_note', 'owner_id, 1'];
    for (const sort of attempts) {
      const built = buildListQuery(spec, mine, { sort });
      assert.match(built.sql, /ORDER BY updated_at DESC, id ASC/, `"${sort}" changed the sort`);
      assert.doesNotMatch(clauses(built.sql), /DROP|SELECT 1|--/, `"${sort}" reached the SQL`);
    }
    assert.match(buildListQuery(spec, mine, { sort: 'amount', direction: 'asc' }).sql, /ORDER BY amount ASC/, 'a listed column is still honoured');
  });

  test('V1.2.4 SQL injection through the sort direction is prevented: only ASC or DESC reach the query', () => {
    // The other value that cannot be bound.
    for (const direction of ['asc); DROP TABLE notes --', 'ASC, owner_id', 'sideways', '']) {
      const built = buildListQuery(spec, mine, { sort: 'amount', direction });
      assert.match(built.sql, /ORDER BY amount (ASC|DESC), id ASC LIMIT \? OFFSET \?$/, `"${direction}" got through`);
    }
    assert.match(buildListQuery(spec, mine, { sort: 'amount', direction: 'ASC' }).sql, /amount ASC/, 'capitals are still a direction');
  });

  test('V1.2.4 a table or column name that is not a plain identifier is refused before any query is built', () => {
    // The names of tables and columns are the only parts of the statement written as text rather than bound, so
    // this is what stands between a badly built spec and an injected query.
    assert.throws(() => assertUsableSpec({ ...spec, table: 'notes; DROP TABLE users' }), /plain identifier/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'a b', label: 'A', kind: 'text' }] }), /plain identifier/);
    assert.throws(() => assertUsableSpec({ ...spec, columns: [{ column: 'x)--', label: 'A', kind: 'text' }] }), /plain identifier/);
  });

  test('V2.4.1 every list query is bounded, so no request can draw out the whole table', () => {
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

  test('V2.4.1 the work one request can demand is capped: no runaway page number, no unbounded pile of filters', () => {
    const far = buildListQuery(spec, mine, { page: 99_999_999 });
    assert.equal(far.applied.page, 10_000, 'the page number should have been capped');
    assert.equal(far.params.at(-1), (10_000 - 1) * 20, 'the offset follows the capped page');

    const many = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`f${i}`, 'x']));
    const piled = buildListQuery(spec, mine, { filters: many });
    assert.equal(piled.applied.filters.length, 0, 'none of those are real columns');
    assert.ok(piled.applied.ignored.length <= 21, `expected the filters to be capped, got ${piled.applied.ignored.length} explanations`);
  });
});
