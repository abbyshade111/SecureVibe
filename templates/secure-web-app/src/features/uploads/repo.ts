/**
 * Storage, type checking and data access for uploaded files (contract §1.10). Every query goes through the db
 * helpers with parameters; the per-user quota is checked and the row inserted inside one transaction so two
 * uploads racing each other can never both slip under the limit.
 */
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { config } from '../../config.ts';
import { all, get, nowIso, run, withTransaction } from '../../db/index.ts';
import { pick } from '../../lib/dto.ts';
import { registerEntity } from '../../security/authz.ts';

export interface UploadRow {
  id: string;
  owner_id: string;
  original_name: string;
  mime: string;
  size: number;
  sha256: string;
  created_at: string;
}

/** The recognized file types: sniffed magic bytes, the extensions that may carry them, and their exact byte tests. */
export type AllowedMime = 'image/png' | 'image/jpeg' | 'image/gif' | 'image/webp' | 'application/pdf';

const EXTENSIONS_FOR_TYPE: Record<AllowedMime, string[]> = {
  'image/png': ['png'],
  'image/jpeg': ['jpg', 'jpeg'],
  'image/gif': ['gif'],
  'image/webp': ['webp'],
  'application/pdf': ['pdf'],
};

/** Types that are refused outright, whatever the declared type or file content says (contract §1.10, V1.3.4). */
const ALWAYS_REFUSED_EXTENSIONS = new Set(['svg', 'svgz', 'html', 'htm', 'xhtml', 'xml', 'zip']);

/** Matches the first bytes of a stream against a small, fixed magic-byte table. Returns undefined when nothing matches. */
export function sniffMagicBytes(head: Buffer): AllowedMime | undefined {
  if (head.length >= 8 && head.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return 'image/jpeg';
  if (head.length >= 6) {
    const sig = head.subarray(0, 6).toString('latin1');
    if (sig === 'GIF87a' || sig === 'GIF89a') return 'image/gif';
  }
  if (head.length >= 12 && head.subarray(0, 4).toString('latin1') === 'RIFF' && head.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  if (head.length >= 5 && head.subarray(0, 5).toString('latin1') === '%PDF-') return 'application/pdf';
  return undefined;
}

export function extensionOf(filename: string): string {
  const dot = filename.lastIndexOf('.');
  if (dot < 0 || dot === filename.length - 1) return '';
  return filename.slice(dot + 1).toLowerCase();
}

export interface TypeCheck {
  ok: boolean;
  mime?: AllowedMime;
  reason?: string;
}

/**
 * The full check (contract §1.10, TPL-UPLOAD-02): sniffed magic bytes must be on the configured allow-list, the
 * file's extension must be one that type normally uses, and the declared Content-Type must agree — otherwise 415.
 * A handful of extensions are refused outright before any of that, because they can carry active content.
 */
export function checkFileType(opts: { sniffed: AllowedMime | undefined; declaredType: string; extension: string }): TypeCheck {
  if (ALWAYS_REFUSED_EXTENSIONS.has(opts.extension)) return { ok: false, reason: 'refused-file-type' };
  if (!opts.sniffed) return { ok: false, reason: 'unrecognised-file-content' };
  const allowList = config.UPLOAD_ALLOWED_TYPES.split(',').map((t) => t.trim().toLowerCase());
  if (!allowList.includes(opts.sniffed)) return { ok: false, reason: 'file-type-not-allowed' };
  const validExtensions = EXTENSIONS_FOR_TYPE[opts.sniffed];
  if (!validExtensions.includes(opts.extension)) return { ok: false, reason: 'extension-does-not-match-content' };
  const declared = opts.declaredType.split(';')[0]?.trim().toLowerCase() ?? '';
  if (declared && declared !== opts.sniffed) return { ok: false, reason: 'declared-type-does-not-match-content' };
  return { ok: true, mime: opts.sniffed };
}

/** Strips any directory components and control characters, collapses runs of dots, and caps the length. */
export function sanitiseOriginalName(raw: string): string {
  const last = raw.split(/[\\/]+/).pop() ?? raw;
  // eslint-disable-next-line no-control-regex
  const noControl = last.replace(/[\x00-\x1f\x7f]+/g, '');
  const noDotRuns = noControl.replace(/\.{2,}/g, '.');
  const trimmed = noDotRuns.trim().slice(0, 120);
  return trimmed.length > 0 ? trimmed : 'file';
}

export function uploadsDir(): string {
  const dir = resolve(config.dataDir, 'uploads');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function tempUploadPath(token: string): string {
  return resolve(uploadsDir(), `.tmp-${token}`);
}

export function storedUploadPath(id: string): string {
  return resolve(uploadsDir(), id);
}

/** Moves a fully-received, validated temp file into place with owner-only permissions. */
export function commitTempFile(tempPath: string, id: string): void {
  const dest = storedUploadPath(id);
  renameSync(tempPath, dest);
  chmodSync(dest, 0o600);
}

/** Deletes a file if it exists (a temp upload that failed validation, or a stored one being removed). Never throws. */
export function safeUnlink(path: string): void {
  try {
    if (existsSync(path)) unlinkSync(path);
  } catch {
    // Best effort: a failed cleanup must not turn into a second error on top of the original rejection.
  }
}

export function getUpload(id: string): UploadRow | undefined {
  return get<UploadRow>('SELECT * FROM uploads WHERE id = ?', [id]);
}

function usageForOwner(ownerId: string): { count: number; bytes: number } {
  const row = get<{ n: number; bytes: number | null }>('SELECT COUNT(*) AS n, SUM(size) AS bytes FROM uploads WHERE owner_id = ?', [ownerId]);
  return { count: row?.n ?? 0, bytes: row?.bytes ?? 0 };
}

export interface NewUpload {
  ownerId: string;
  originalName: string;
  mime: AllowedMime;
  size: number;
  sha256: string;
}

export type RecordResult = { ok: true; row: UploadRow } | { ok: false; reason: 'quota-bytes' };

/** Checks the per-user byte quota and inserts the row in one transaction (contract §1.10, TPL-UPLOAD-05). */
export function recordUpload(id: string, input: NewUpload): RecordResult {
  return withTransaction<RecordResult>(() => {
    const usage = usageForOwner(input.ownerId);
    if (usage.bytes + input.size > config.UPLOAD_USER_QUOTA_BYTES) return { ok: false, reason: 'quota-bytes' };
    const now = nowIso();
    run('INSERT INTO uploads (id, owner_id, original_name, mime, size, sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [
      id,
      input.ownerId,
      input.originalName,
      input.mime,
      input.size,
      input.sha256,
      now,
    ]);
    const row = getUpload(id);
    if (!row) throw new Error('Upload row was not created.');
    return { ok: true, row };
  });
}

export function deleteUpload(id: string): void {
  const row = getUpload(id);
  run('DELETE FROM uploads WHERE id = ?', [id]);
  if (row) safeUnlink(storedUploadPath(row.id));
}

export function listUploadsForOwner(ownerId: string, limit: number, offset: number): UploadRow[] {
  return all<UploadRow>('SELECT * FROM uploads WHERE owner_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?', [ownerId, limit, offset]);
}

export function toOwnerDto(row: UploadRow): { id: string; originalName: string; mime: string; size: number; createdAt: string } {
  return { ...pick(row, ['id', 'mime', 'size']), originalName: row.original_name, createdAt: row.created_at };
}

export function registerUploadsEntity(): void {
  registerEntity({
    name: 'upload',
    table: 'uploads',
    ownerField: 'owner_id',
    label: 'Upload',
    sensitiveFields: ['original_name'],
    // Test mode needs one real file per seeded user so the ownership and download probes have something to fetch.
    seed: (ownerId) => {
      const id = randomUUID();
      // The smallest valid PNG: an 1×1 transparent pixel, so the sniffed type matches the stored one.
      const png = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
        'base64',
      );
      const path = storedUploadPath(id);
      writeFileSync(path, png, { mode: 0o600 });
      const result = recordUpload(id, {
        ownerId,
        originalName: 'sample.png',
        mime: 'image/png',
        size: png.length,
        sha256: createHash('sha256').update(png).digest('hex'),
      });
      if (!result.ok) safeUnlink(path);
    },
    sampleId: (ownerId) => get<{ id: string }>('SELECT id FROM uploads WHERE owner_id = ? ORDER BY created_at ASC LIMIT 1', [ownerId])?.id,
    exportForUser: (userId) => listUploadsForOwner(userId, 1000, 0).map(toOwnerDto),
    deleteForUser: (userId) => {
      for (const row of listUploadsForOwner(userId, 100000, 0)) safeUnlink(storedUploadPath(row.id));
      run('DELETE FROM uploads WHERE owner_id = ?', [userId]);
    },
  });
}

/** Deletes uploads (row and file) created before `cutoffIso`. Used by the retention job. */
export function deleteUploadsCreatedBefore(cutoffIso: string): number {
  const old = all<UploadRow>('SELECT * FROM uploads WHERE created_at < ?', [cutoffIso]);
  for (const row of old) safeUnlink(storedUploadPath(row.id));
  return run('DELETE FROM uploads WHERE created_at < ?', [cutoffIso]).changes;
}

export const randomId = (): string => randomUUID();
