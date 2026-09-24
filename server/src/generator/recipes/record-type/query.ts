/**
 * Turning one record type into the spec its list page is queried through.
 *
 * The template owns the engine (`src/db/query.ts`): it applies a spec, binds every value a person typed, looks the
 * sort column up in the spec's own allow-list, and bounds every page. This file decides what that spec *says* for
 * one record type, which is the half the answers decide.
 *
 * The thing this exists to prevent is not a wrong sort order. A list that forgets `owner_id = ?` hands one
 * person's records to another, looks entirely normal on screen, and passes any test that counts rows. Before this,
 * each record type emitted two list functions — one scoped, one not — and *every call site chose between them*:
 *
 *     req.user?.isAdmin ? listAllBookings(...) : listBookingsForOwner(...)
 *
 * twice per record type, once on the page route and once on the JSON route. Add search to that and the fastest way
 * to make it work is to copy the wrong branch. So the scope is now decided once, here, from the record type's own
 * `access` answer, and no call site chooses anything.
 *
 * Three rules about which fields may be searched, sorted and filtered, and one reason behind all three:
 *
 *  - **A scrambled field can be neither searched nor sorted.** The database holds ciphertext, so a "contains"
 *    match would compare the scrambling and a sort would order by it. The engine refuses a spec that claims
 *    otherwise rather than quietly matching nothing.
 *  - **A field the person marked sensitive is left out of all three**, even where it is not scrambled. Filtering
 *    is a question with a yes or no answer: someone who may not read a field can still learn its value by asking
 *    which records have it. The report and chart pages leave sensitive fields alone for the same reason.
 *  - **Every column is listed all the same**, with the flags saying what may be done with it. The engine selects
 *    the columns the spec names, so a field left out of the spec is a field that silently vanishes from the page.
 */
import type { EntityPlan, FieldPlan } from './fields.js';
import { commentText } from '../js-literal.js';

/** The kinds the template's query engine understands. */
export type ColumnKind = 'text' | 'number' | 'date' | 'boolean' | 'choice';

export interface SpecColumn {
  column: string;
  /** The name the field is exposed under in a form or a JSON body, which is not the column name. */
  prop: string;
  label: string;
  kind: ColumnKind;
  searchable: boolean;
  sortable: boolean;
  filterable: boolean;
  encrypted: boolean;
  /** For a choice column, the only values a filter may ask for. */
  choices: string[];
}

export interface QueryPlan {
  /** Every field column on the row. The engine adds id, owner_id, created_at and updated_at itself. */
  columns: SpecColumn[];
  searchable: SpecColumn[];
  sortable: SpecColumn[];
  filterable: SpecColumn[];
  defaultSort: { column: string; direction: 'asc' | 'desc' };
  /**
   * Why an unscoped read is allowed, in the owner's words, written from the `access` answer. The engine makes an
   * unscoped read spell out its reason so that `grep "kind: 'everyone'"` finds every one of them in an app.
   */
  everyoneBecause: string;
}

function kindOf(field: FieldPlan): ColumnKind {
  switch (field.control) {
    case 'number':
    case 'money':
      return 'number';
    case 'date':
    case 'datetime-local':
      return 'date';
    case 'checkbox':
      return 'boolean';
    case 'select':
      return 'choice';
    default:
      return 'text';
  }
}

function columnFor(field: FieldPlan): SpecColumn {
  const kind = kindOf(field);
  const choices = (field.field.choices ?? []).filter((c) => c.trim() !== '');
  // Scrambled or sensitive: listed so the page can still show it, but nothing may be asked of it.
  const usable = !field.encrypted && !field.field.sensitive;
  return {
    column: field.column,
    prop: field.prop,
    label: field.field.label,
    kind,
    searchable: usable && kind === 'text',
    // Ordering by a yes/no answer tells a reader nothing they cannot see, so it is left off the menu.
    sortable: usable && kind !== 'boolean',
    filterable: usable && (kind === 'boolean' || (kind === 'choice' && choices.length > 0)),
    encrypted: field.encrypted,
    choices,
  };
}

/** Why this record type's list may be read without a per-person scope, in plain language. */
function everyoneBecause(plan: EntityPlan): string {
  const plural = (plan.entity.pluralLabel ?? `${plan.entity.label}s`).toLowerCase();
  if (plan.adminOnly) return `only administrators can reach this list, and they may read every ${plural.replace(/s$/, '')}`;
  if (plan.publicRead) return `the person who described this app said these ${plural} are public to read`;
  if (plan.ownerScoped) return `an administrator may read every ${plural}, which the ownership check allows them anyway`;
  return `the person who described this app said these ${plural} are shared with everyone who has signed in`;
}

export function queryPlanOf(plan: EntityPlan): QueryPlan {
  const columns = plan.fields.map(columnFor);
  return {
    columns,
    searchable: columns.filter((c) => c.searchable),
    sortable: columns.filter((c) => c.sortable),
    filterable: columns.filter((c) => c.filterable),
    // The same order the list has always had, so an upgrade does not silently reshuffle somebody's page.
    defaultSort: { column: 'updated_at', direction: 'desc' },
    everyoneBecause: everyoneBecause(plan),
  };
}

/** The spec literal, written into the record type's own repository module. */
export function emitSpecLiteral(plan: EntityPlan, query: QueryPlan): string {
  const lines = query.columns.map((c) => {
    const parts = [
      `column: ${JSON.stringify(c.column)}`,
      `label: ${JSON.stringify(c.label)}`,
      `kind: ${JSON.stringify(c.kind)}`,
      ...(c.searchable ? ['searchable: true'] : []),
      ...(c.sortable ? ['sortable: true'] : []),
      ...(c.filterable ? ['filterable: true'] : []),
      ...(c.encrypted ? ['encrypted: true'] : []),
      ...(c.kind === 'choice' && c.choices.length > 0 ? [`choices: ${JSON.stringify(c.choices)}`] : []),
    ];
    return `    { ${parts.join(', ')} },`;
  });
  return `/**
 * What a list of ${commentText((plan.entity.pluralLabel ?? `${plan.entity.label}s`).toLowerCase())} may be searched, sorted and narrowed down by.
 *
 * Settled when this app was built, from the fields the person described. Nothing here is read from a request: the
 * engine looks the sort column up in this list and binds every value, so a name that is not here cannot reach the
 * query at all. Every column is listed even when nothing may be asked of it, because the statement selects the
 * columns this names.
 */
export const QUERY_SPEC: QuerySpec = {
  table: TABLE,
  columns: [
${lines.join('\n')}
  ],
  defaultSort: { column: ${JSON.stringify(query.defaultSort.column)}, direction: ${JSON.stringify(query.defaultSort.direction)} },
  pageSize: DEFAULT_PAGE_SIZE,
};`;
}

/**
 * The one place this record type decides whose records a list returns.
 *
 * Emitted per record type rather than passed in by whoever is calling, because a scope that travels as an argument
 * is a scope a call site can get wrong, and getting it wrong is invisible on screen.
 */
export function emitScopeFunction(plan: EntityPlan, query: QueryPlan): string {
  const plural = (plan.entity.pluralLabel ?? `${plan.entity.label}s`).toLowerCase();
  const body = plan.ownerScoped
    ? `  // These ${plural} belong to the person who added them. An administrator may already read every record, so
  // for them the list is unscoped — and says why, as the engine requires of any unscoped read.
  if (user && !user.isAdmin) return { kind: 'owner', ownerId: user.id };
  return { kind: 'everyone', because: ${JSON.stringify(query.everyoneBecause)} };`
    : `  return { kind: 'everyone', because: ${JSON.stringify(query.everyoneBecause)} };`;
  return `/**
 * Whose ${commentText(plural)} a list may return, decided here and nowhere else.
 *
 * Every route that lists ${commentText(plural)} calls this. It takes no argument it could be given wrongly beyond the signed-in
 * person, and it has no default: the engine will not build a query without a scope.
 */
export function ${plan.camelName}Scope(user: { id: string; isAdmin: boolean } | undefined): QueryScope {
${body}
}`;
}
