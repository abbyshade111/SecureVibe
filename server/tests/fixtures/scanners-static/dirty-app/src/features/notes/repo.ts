// Fixture: SQL built from a template string, and two writes outside a transaction (CONTRACTS §3).
import { get, run } from '../../db/index.js';

export function findByTitle(title: string): unknown {
  return get(`SELECT * FROM notes WHERE title = '${title}'`);
}

export function createTwo(a: string, b: string): void {
  run('INSERT INTO notes (title) VALUES (?)', [a]);
  run('INSERT INTO notes (title) VALUES (?)', [b]);
}
