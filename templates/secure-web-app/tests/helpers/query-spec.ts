/** One fixture spec, shared by the two query test files so they cannot drift apart. */
import type { QuerySpec } from '../../src/db/query.ts';

export const spec: QuerySpec = {
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

export const mine = { kind: 'owner', ownerId: 'user-1' } as const;
export const everyone = { kind: 'everyone', because: 'this list is public to read' } as const;

/** Everything after the table name: the clauses a request can influence, without the column list it cannot. */
export function clauses(sql: string): string {
  return sql.slice(sql.indexOf(' FROM '));
}
