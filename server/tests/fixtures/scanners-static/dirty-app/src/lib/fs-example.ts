// Fixture: file paths and file access built from request data (CONTRACTS §3).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function loadUserFile(req: { params: { filename: string } }): Buffer {
  const filePath = join('/data/uploads', req.params.filename);
  return readFileSync(filePath);
}

export function downloadFile(req: { params: { file: string } }): Buffer {
  return readFileSync(req.params.file);
}
