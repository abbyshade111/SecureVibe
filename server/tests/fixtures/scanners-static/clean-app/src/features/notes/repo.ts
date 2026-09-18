// Clean fixture: parameterized queries and multi-row writes inside a transaction (CONTRACTS §1 convention).
import { get, run, withTransaction } from '../../db/index.js';
import type { NoteRow } from './dto.js';

export function createNoteWithAudit(title: string, ownerId: string): void {
  withTransaction(() => {
    run('INSERT INTO notes (title, owner_id) VALUES (?, ?)', [title, ownerId]);
    run('INSERT INTO audit_log (action) VALUES (?)', ['note.created']);
  });
}

export function findNoteById(id: string): NoteRow | undefined {
  return get('SELECT * FROM notes WHERE id = ?', [id]) as NoteRow | undefined;
}
