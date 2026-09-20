/**
 * Building the SELECT behind a list page: search, filter, sort and paginate, settled once.
 *
 * Every list in every generated app wants the same four things, and writing them fresh per feature is where the
 * expensive mistake lives. Not the sort order — a missing ownership clause. A list that forgets `owner_id = ?`
 * hands one person's records to another, looks completely normal on screen, and passes any test that only counts
 * rows. So the shape of this module is chosen to make that omission impossible rather than merely discouraged:
 *
 *  - **The scope is an argument, not an option.** `buildListQuery` cannot be called without one. The unscoped
 *    case is spelled `{ kind: 'everyone', because: '…' }`, so choosing it means writing down why, in the code,
 *    where a reader and a reviewer both see it. `grep "kind: 'everyone'"` lists every unscoped read in an app.
 *  - **Nothing from a request ever reaches the SQL text.** Values are bound parameters. The two things that
 *    cannot be bound — the column a person sorts by, and the direction — are looked up in the spec's own
 *    allow-list and used only if they are found there, and the name is checked against a plain-identifier
 *    pattern a second time on the way in to the string. An unknown column is not an error and not a guess: it
 *    is ignored, reported in `applied.ignored`, and the default sort is used.
 *  - **Every query is bounded.** There is no way to ask for all the rows.
 *
 * `columns` lists **every** column the row has, not only the ones a person may act on — the flags say what may
 * be done with each. That is what lets the statement name its columns instead of asking for `*`, so a column
 * added by a later migration is not silently selected by every list from the moment it exists.
 *
 * Three honest limits, all of which the app tells the person about rather than hiding:
 *  - A field stored scrambled cannot be searched or sorted, because the database holds ciphertext and comparing
 *    it would compare the scrambling. Declaring one searchable is a programming mistake, and `assertUsableSpec`
 *    refuses the spec instead of quietly returning nothing.
 *  - Search is a plain "contains" match, case-insensitive for ASCII. It is not a ranked search engine, and it
 *    does not stem, spell-correct or understand phrases.
 *  - A filter on a `date` column matches that exact day. It is the one kind where the behaviour is not obvious
 *    from the type, so it is written down here: there are no ranges, no "on or after", no "this month". A range
 *    filter is the obvious next thing to want and this deliberately does not pretend to do it.
 */
import { clampLimit } from './limits.ts';
import type { SqlParam } from './index.ts';

/** A column name we are willing to write into SQL. Deliberately narrower than SQLite allows. */
const PLAIN_IDENTIFIER = /^[a-z][a-z0-9_]{0,62}$/;

/** Longer than this and a search term is a denial-of-service attempt rather than a question. */
const MAX_SEARCH_LENGTH = 200;

/**
 * The furthest a person may page into a list. Without it `?page=99999999` becomes a nine-digit OFFSET and the
 * database walks the whole table to find nothing. Routes will validate the number too; this is here because the
 * module's only real argument is that it does not depend on a caller remembering something.
 */
const MAX_PAGE = 10_000;

/** How many filters one request may carry, for the same reason: each one is another clause to evaluate. */
const MAX_FILTERS = 20;

export type SortDirection = 'asc' | 'desc';

export type ColumnKind = 'text' | 'number' | 'date' | 'boolean' | 'choice';

/** One column a list may be searched, filtered or sorted by. Built from the design, never from a request. */
export interface QueryColumn {
  column: string;
  /** What the person calls this field; used in the plain-language report of what was applied. */
  label: string;
  kind: ColumnKind;
  searchable?: boolean;
  sortable?: boolean;
  filterable?: boolean;
  /** Stored scrambled. Such a column can be neither searched nor sorted; saying otherwise is refused. */
  encrypted?: boolean;
  /** For `choice` columns: the only values a filter may ask for. */
  choices?: string[];
}

export interface QuerySpec {
  table: string;
  columns: QueryColumn[];
  defaultSort: { column: string; direction: SortDirection };
  /** How many rows one page holds. Clamped by `clampLimit`, so a spec cannot ask for an unbounded page. */
  pageSize: number;
}

/**
 * Whose records this query may return.
 *
 * `everyone` is not a default and never will be. It carries a `because` so that an unscoped read is a sentence
 * somebody wrote on purpose — "the list is public to read" — rather than a scope that was left off.
 */
export type QueryScope = { kind: 'owner'; ownerId: string } | { kind: 'everyone'; because: string };

/** What a person asked for, straight off the query string and entirely untrusted. */
export interface ListRequest {
  search?: string | undefined;
  sort?: string | undefined;
  direction?: string | undefined;
  page?: number | undefined;
  filters?: Record<string, string | undefined> | undefined;
}

/** What was actually done, for the page to show and for the person to correct. */
export interface AppliedQuery {
  search: string;
  sort: string;
  sortLabel: string;
  direction: SortDirection;
  page: number;
  pageSize: number;
  offset: number;
  filters: { column: string; label: string; value: string }[];
  /** Plain language, one line per thing asked for and not done, and why. */
  ignored: string[];
}

export interface BuiltQuery {
  sql: string;
  params: SqlParam[];
  countSql: string;
  countParams: SqlParam[];
  applied: AppliedQuery;
}

function isPlainIdentifier(name: string): boolean {
  return PLAIN_IDENTIFIER.test(name);
}

/**
 * Refuses a spec that could only ever behave surprisingly. Called by `buildListQuery` on every call: the cost is
 * a few regular-expression tests, and the alternative is a searchable encrypted column silently matching nothing.
 */
export function assertUsableSpec(spec: QuerySpec): void {
  if (!isPlainIdentifier(spec.table)) throw new Error(`Table name "${spec.table}" is not a plain identifier.`);
  const seen = new Set<string>();
  for (const col of spec.columns) {
    if (!isPlainIdentifier(col.column)) throw new Error(`Column name "${col.column}" is not a plain identifier.`);
    if (seen.has(col.column)) throw new Error(`Column "${col.column}" is listed twice.`);
    seen.add(col.column);
    if (col.encrypted && (col.searchable || col.sortable)) {
      throw new Error(`Column "${col.column}" is stored scrambled, so it cannot be searched or sorted.`);
    }
    if (col.searchable && col.kind !== 'text' && col.kind !== 'choice') {
      throw new Error(`Column "${col.column}" is a ${col.kind}, so a "contains" search would not mean anything.`);
    }
    if (col.kind === 'choice' && col.filterable && (col.choices ?? []).length === 0) {
      throw new Error(`Column "${col.column}" can be filtered but lists no choices to filter by.`);
    }
  }
  if (!seen.has(spec.defaultSort.column) && !isAlwaysSortable(spec.defaultSort.column)) {
    throw new Error(`The default sort column "${spec.defaultSort.column}" is not one of the listed columns.`);
  }
}

/** Columns every table in this template has. Always selected, so a list always knows whose row it is holding. */
const ROW_COLUMNS = ['id', 'owner_id', 'created_at', 'updated_at'] as const;

/**
 * The always-present columns a list may be sorted by. `owner_id` is deliberately not one of them: on a shared
 * list, sorting by it groups and orders the rows by who added them, which publishes a small fact about other
 * people that nobody asked to publish. It stays selectable and is never an ordering.
 */
const ALWAYS_SORTABLE = new Set(['id', 'created_at', 'updated_at']);
const OWN_COLUMN_LABELS: Record<string, string> = {
  created_at: 'when it was added',
  updated_at: 'when it was last changed',
  id: 'its reference',
  owner_id: 'who added it',
};

function isAlwaysSortable(name: string): boolean {
  return ALWAYS_SORTABLE.has(name);
}

/** The columns the statement names. Every column of the row, each one already checked as a plain identifier. */
function selectList(spec: QuerySpec): string {
  const names = [...ROW_COLUMNS, ...spec.columns.map((c) => c.column)];
  return [...new Set(names)].join(', ');
}

/** Escapes the wildcards, so searching for "100%" looks for "100%" and not for everything. */
export function likePattern(term: string): string {
  return `%${term.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
}

function labelFor(spec: QuerySpec, column: string): string {
  return spec.columns.find((c) => c.column === column)?.label ?? OWN_COLUMN_LABELS[column] ?? column;
}

/** The column to sort by: the requested one if the spec allows it, the default otherwise. */
function resolveSort(spec: QuerySpec, req: ListRequest, ignored: string[]): { column: string; direction: SortDirection } {
  let column = spec.defaultSort.column;
  const asked = (req.sort ?? '').trim();
  if (asked !== '') {
    const match = spec.columns.find((c) => c.column === asked && c.sortable === true);
    if (match) column = match.column;
    else if (isAlwaysSortable(asked)) column = asked;
    else ignored.push(`This list cannot be sorted by "${asked}", so it is sorted by ${labelFor(spec, column)} instead.`);
  }
  // Checked again here rather than trusted from the spec: this is the only value that is not a bound parameter.
  if (!isPlainIdentifier(column)) throw new Error(`Refusing to sort by "${column}".`);

  let direction: SortDirection = spec.defaultSort.direction;
  const askedDirection = (req.direction ?? '').trim().toLowerCase();
  if (askedDirection === 'asc' || askedDirection === 'desc') direction = askedDirection;
  else if (askedDirection !== '') ignored.push(`"${askedDirection}" is not an order, so ${direction === 'asc' ? 'smallest first' : 'newest first'} was used.`);
  return { column, direction };
}

/** One filter, checked against its column's kind. A value that does not fit is ignored and said so. */
function resolveFilter(col: QueryColumn, raw: string): { value: SqlValueForFilter; shown: string } | { problem: string } {
  const value = raw.trim();
  if (value === '') return { problem: '' };
  switch (col.kind) {
    case 'boolean': {
      const yes = ['yes', 'true', '1', 'on'].includes(value.toLowerCase());
      const no = ['no', 'false', '0', 'off'].includes(value.toLowerCase());
      if (!yes && !no) return { problem: `"${value}" is not a yes or a no, so the ${col.label} filter was ignored.` };
      return { value: yes ? 1 : 0, shown: yes ? 'yes' : 'no' };
    }
    case 'number': {
      const n = Number(value);
      if (!Number.isFinite(n)) return { problem: `"${value}" is not a number, so the ${col.label} filter was ignored.` };
      return { value: n, shown: value };
    }
    case 'choice': {
      const choices = col.choices ?? [];
      if (!choices.includes(value)) return { problem: `"${value}" is not one of the ${col.label} choices, so that filter was ignored.` };
      return { value, shown: value };
    }
    default:
      return { value, shown: value };
  }
}

type SqlValueForFilter = string | number;

/**
 * Builds the two statements a list page needs — the page of rows, and the total the pager counts against — from
 * a spec the app controls and a request it does not.
 *
 * `scope` has no default on purpose. See the note at the top of this file.
 */
export function buildListQuery(spec: QuerySpec, scope: QueryScope, req: ListRequest = {}): BuiltQuery {
  assertUsableSpec(spec);
  if (scope === undefined || (scope.kind !== 'owner' && scope.kind !== 'everyone')) {
    throw new Error('A list query needs a scope: either one person’s records, or everyone’s with a reason.');
  }

  const ignored: string[] = [];
  const where: string[] = [];
  const params: SqlParam[] = [];

  // First and never conditional on anything a request said.
  if (scope.kind === 'owner') {
    where.push('owner_id = ?');
    params.push(scope.ownerId);
  }

  let search = (req.search ?? '').trim();
  if (search.length > MAX_SEARCH_LENGTH) {
    ignored.push(`The search was longer than ${MAX_SEARCH_LENGTH} letters, so only the first ${MAX_SEARCH_LENGTH} were used.`);
    search = search.slice(0, MAX_SEARCH_LENGTH);
  }
  if (search !== '') {
    const searchable = spec.columns.filter((c) => c.searchable === true && c.encrypted !== true);
    if (searchable.length === 0) {
      ignored.push('None of the fields on this list can be searched, so the search was ignored.');
      search = '';
    } else {
      where.push(`(${searchable.map((c) => `${c.column} LIKE ? ESCAPE '\\'`).join(' OR ')})`);
      for (const _ of searchable) params.push(likePattern(search));
    }
  }

  const appliedFilters: AppliedQuery['filters'] = [];
  const askedFilters = Object.entries(req.filters ?? {});
  if (askedFilters.length > MAX_FILTERS) {
    ignored.push(`Only the first ${MAX_FILTERS} ways of narrowing the list down were used; the rest were ignored.`);
  }
  for (const [name, raw] of askedFilters.slice(0, MAX_FILTERS)) {
    if (raw === undefined) continue;
    const col = spec.columns.find((c) => c.column === name && c.filterable === true);
    if (!col) {
      if (raw.trim() !== '') ignored.push(`This list cannot be narrowed down by "${name}", so that was ignored.`);
      continue;
    }
    if (col.encrypted) {
      ignored.push(`${col.label} is scrambled in the database, so it cannot be used to narrow the list down.`);
      continue;
    }
    const resolved = resolveFilter(col, raw);
    if ('problem' in resolved) {
      if (resolved.problem !== '') ignored.push(resolved.problem);
      continue;
    }
    where.push(`${col.column} = ?`);
    params.push(resolved.value);
    appliedFilters.push({ column: col.column, label: col.label, value: resolved.shown });
  }

  const { column: sortColumn, direction } = resolveSort(spec, req, ignored);
  const pageSize = clampLimit(spec.pageSize);
  const asked = Math.max(1, Number.isFinite(req.page) ? Math.floor(req.page as number) : 1);
  const page = Math.min(asked, MAX_PAGE);
  if (asked > MAX_PAGE) ignored.push(`There are never more than ${MAX_PAGE} pages, so the last one was shown instead.`);
  const offset = (page - 1) * pageSize;

  const whereSql = where.length > 0 ? ` WHERE ${where.join(' AND ')}` : '';
  // `id` breaks ties so that two rows with the same sort value never swap places between pages.
  const orderSql = ` ORDER BY ${sortColumn} ${direction === 'asc' ? 'ASC' : 'DESC'}, id ASC`;

  return {
    sql: `SELECT ${selectList(spec)} FROM ${spec.table}${whereSql}${orderSql} LIMIT ? OFFSET ?`,
    params: [...params, pageSize, offset],
    countSql: `SELECT COUNT(*) AS n FROM ${spec.table}${whereSql}`,
    countParams: [...params],
    applied: {
      search,
      sort: sortColumn,
      sortLabel: labelFor(spec, sortColumn),
      direction,
      page,
      pageSize,
      offset,
      filters: appliedFilters,
      ignored,
    },
  };
}

/** The columns of a spec a search box should mention, so the page can say what it looks in. */
export function searchableLabels(spec: QuerySpec): string[] {
  return spec.columns.filter((c) => c.searchable === true && c.encrypted !== true).map((c) => c.label);
}

/** The columns a person may sort by, for a sort menu, with the always-present ones last. */
export function sortableColumns(spec: QuerySpec): { column: string; label: string }[] {
  const own = ['updated_at', 'created_at'].map((column) => ({ column, label: OWN_COLUMN_LABELS[column] as string }));
  return [...spec.columns.filter((c) => c.sortable === true).map((c) => ({ column: c.column, label: c.label })), ...own];
}
