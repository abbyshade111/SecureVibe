/**
 * Reference data module for the "notes" example. Generated features copy this shape:
 *  - every query goes through the db helpers with parameters and a LIMIT on lists,
 *  - creation checks the per-user quota inside a transaction,
 *  - updates use optimistic concurrency (the caller sends the updated_at it last saw),
 *  - DTOs (public / owner / admin) are the only things returned to pages and the API,
 *  - the entity is registered so owner checks, exports, deletion and test seeding work.
 */
import { randomUUID } from 'node:crypto';
import { all, get, nowIso, run, withTransaction } from '../../db/index.ts';
import { pick } from '../../lib/dto.ts';
import { registerEntity } from '../../security/authz.ts';

export const NOTE_QUOTA_PER_USER = 200;

export interface NoteRow {
  id: string;
  owner_id: string;
  title: string;
  body: string;
  status: 'draft' | 'published' | 'archived';
  published_at: string | null;
  publish_note: string | null;
  created_at: string;
  updated_at: string;
}

export interface NoteInput {
  title: string;
  body: string;
}

export function getNote(id: string): NoteRow | undefined {
  return get<NoteRow>('SELECT * FROM notes WHERE id = ?', [id]);
}

export function listNotesForOwner(ownerId: string, limit: number, offset: number): NoteRow[] {
  return all<NoteRow>('SELECT * FROM notes WHERE owner_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?', [ownerId, limit, offset]);
}

export function listAllNotes(limit: number, offset: number): NoteRow[] {
  return all<NoteRow>('SELECT * FROM notes ORDER BY updated_at DESC LIMIT ? OFFSET ?', [limit, offset]);
}

export function countNotesForOwner(ownerId: string): number {
  return get<{ n: number }>('SELECT COUNT(*) AS n FROM notes WHERE owner_id = ?', [ownerId])?.n ?? 0;
}

export type CreateResult = { ok: true; note: NoteRow } | { ok: false; reason: 'quota' | 'duplicate' };

/** Quota check and insert happen in one transaction so two parallel requests cannot both slip under the limit. */
export function createNote(ownerId: string, input: NoteInput): CreateResult {
  return withTransaction<CreateResult>(() => {
    if (countNotesForOwner(ownerId) >= NOTE_QUOTA_PER_USER) return { ok: false, reason: 'quota' };
    if (get('SELECT 1 FROM notes WHERE owner_id = ? AND title = ?', [ownerId, input.title])) return { ok: false, reason: 'duplicate' };
    const id = randomUUID();
    const now = nowIso();
    run('INSERT INTO notes (id, owner_id, title, body, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [id, ownerId, input.title, input.body, 'draft', now, now]);
    const note = getNote(id);
    if (!note) throw new Error('Note was not created.');
    return { ok: true, note };
  });
}

export type UpdateResult = { ok: true; note: NoteRow } | { ok: false; reason: 'conflict' | 'not-found' | 'duplicate' };

/** Optimistic concurrency: the row is only updated when its updated_at still equals what the caller last saw. */
export function updateNote(id: string, input: Partial<NoteInput>, expectedUpdatedAt: string): UpdateResult {
  return withTransaction<UpdateResult>(() => {
    const current = getNote(id);
    if (!current) return { ok: false, reason: 'not-found' };
    if (current.updated_at !== expectedUpdatedAt) return { ok: false, reason: 'conflict' };
    const title = input.title ?? current.title;
    const body = input.body ?? current.body;
    if (title !== current.title && get('SELECT 1 FROM notes WHERE owner_id = ? AND title = ? AND id <> ?', [current.owner_id, title, id])) {
      return { ok: false, reason: 'duplicate' };
    }
    const now = nowIso();
    const result = run('UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ? AND updated_at = ?', [title, body, now, id, expectedUpdatedAt]);
    if (result.changes !== 1) return { ok: false, reason: 'conflict' };
    const note = getNote(id);
    if (!note) return { ok: false, reason: 'not-found' };
    return { ok: true, note };
  });
}

export function deleteNote(id: string): boolean {
  return run('DELETE FROM notes WHERE id = ?', [id]).changes === 1;
}

export function publishNote(id: string, publishNote: string | null): NoteRow | undefined {
  const now = nowIso();
  run("UPDATE notes SET status = 'published', published_at = ?, publish_note = ?, updated_at = ? WHERE id = ?", [now, publishNote, now, id]);
  return getNote(id);
}

/** Seen by other signed-in users (for example in a shared list). */
export function toPublicDto(row: NoteRow): { id: string; title: string; status: string; publishedAt: string | null } {
  return { id: row.id, title: row.title, status: row.status, publishedAt: row.published_at };
}

/** Seen by the owner. */
export function toOwnerDto(row: NoteRow): {
  id: string;
  title: string;
  body: string;
  status: string;
  publishedAt: string | null;
  publishNote: string | null;
  createdAt: string;
  updatedAt: string;
} {
  const p = pick(row, ['id', 'title', 'body', 'status']);
  return { ...p, publishedAt: row.published_at, publishNote: row.publish_note, createdAt: row.created_at, updatedAt: row.updated_at };
}

/** Seen by administrators (adds the owner id). */
export function toAdminDto(row: NoteRow): ReturnType<typeof toOwnerDto> & { ownerId: string } {
  return { ...toOwnerDto(row), ownerId: row.owner_id };
}

export function registerNotesEntity(): void {
  registerEntity({
    name: 'note',
    table: 'notes',
    ownerField: 'owner_id',
    label: 'Note',
    sensitiveFields: [],
    seed: (ownerId) => {
      createNote(ownerId, { title: 'Sample note', body: 'This record was created by test mode.' });
    },
    sampleId: (ownerId) => get<{ id: string }>('SELECT id FROM notes WHERE owner_id = ? ORDER BY created_at ASC LIMIT 1', [ownerId])?.id,
    exportForUser: (userId) => listNotesForOwner(userId, 1000, 0).map(toOwnerDto),
    deleteForUser: (userId) => {
      run('DELETE FROM notes WHERE owner_id = ?', [userId]);
    },
  });
}
