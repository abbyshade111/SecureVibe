// Clean fixture: a DTO function, so a raw db row never reaches the client (CONTRACTS §1 convention).
export interface NoteRow {
  id: string;
  title: string;
  owner_id: string;
  body: string;
}

export function toPublicDto(row: NoteRow): { id: string; title: string; body: string } {
  return { id: row.id, title: row.title, body: row.body };
}
