/**
 * Field-level encryption for sensitive columns: AES-256-GCM with versioned keys from FIELD_KEYS.
 * Stored format: `v<keyId>:<iv b64>:<tag b64>:<ciphertext b64>`. The table, column and row id are bound as
 * additional authenticated data (AAD), so a ciphertext copied into another row or column fails to decrypt.
 * Rotation: add a new key id to FIELD_KEYS, point ACTIVE_FIELD_KEY at it, run `npm run rotate-field-key`.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { config } from '../config.ts';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface EncryptedColumn {
  table: string;
  column: string;
  idColumn: string;
}

const encryptedColumns: EncryptedColumn[] = [{ table: 'users', column: 'totp_secret_enc', idColumn: 'id' }];

/** Feature modules call this for columns that hold sensitive data so `rotate-field-key` knows what to re-encrypt. */
export function registerEncryptedColumn(entry: EncryptedColumn): void {
  if (!/^[a-z_][a-z0-9_]*$/i.test(entry.table) || !/^[a-z_][a-z0-9_]*$/i.test(entry.column) || !/^[a-z_][a-z0-9_]*$/i.test(entry.idColumn)) {
    throw new Error('Encrypted column names must be plain identifiers.');
  }
  if (!encryptedColumns.some((c) => c.table === entry.table && c.column === entry.column)) encryptedColumns.push(entry);
}

export function listEncryptedColumns(): EncryptedColumn[] {
  return [...encryptedColumns];
}

export function aadFor(table: string, column: string, rowId: string | number): Buffer {
  return Buffer.from(`${table}.${column}.${rowId}`, 'utf8');
}

export function activeKeyId(): number {
  return config.ACTIVE_FIELD_KEY;
}

function keyFor(id: number): Buffer {
  const key = config.fieldKeys.get(id);
  if (!key) throw new Error(`Field encryption key ${id} is not present in FIELD_KEYS. Older data cannot be read without it.`);
  return key;
}

export function encryptField(plain: string, table: string, column: string, rowId: string | number, keyId: number = activeKeyId()): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, keyFor(keyId), iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aadFor(table, column, rowId));
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v${keyId}:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}

export function parseEncrypted(stored: string): { keyId: number; iv: Buffer; tag: Buffer; ct: Buffer } {
  const parts = stored.split(':');
  if (parts.length !== 4 || !parts[0] || !/^v\d+$/.test(parts[0])) throw new Error('Stored value is not in the expected encrypted format.');
  const parsed = {
    keyId: Number(parts[0].slice(1)),
    iv: Buffer.from(parts[1] ?? '', 'base64'),
    tag: Buffer.from(parts[2] ?? '', 'base64'),
    ct: Buffer.from(parts[3] ?? '', 'base64'),
  };
  if (parsed.iv.length !== IV_BYTES || parsed.tag.length !== TAG_BYTES) throw new Error('Stored value is not in the expected encrypted format.');
  return parsed;
}

export function decryptField(stored: string, table: string, column: string, rowId: string | number): string {
  const { keyId, iv, tag, ct } = parseEncrypted(stored);
  // Pinning the tag length stops a shortened (weaker) tag from being accepted.
  const decipher = createDecipheriv(ALGORITHM, keyFor(keyId), iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(aadFor(table, column, rowId));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** Re-encrypts a stored value under the active key when it was written with a different key. Returns undefined when unchanged. */
export function rotateField(stored: string, table: string, column: string, rowId: string | number): string | undefined {
  const { keyId } = parseEncrypted(stored);
  if (keyId === activeKeyId()) return undefined;
  const plain = decryptField(stored, table, column, rowId);
  return encryptField(plain, table, column, rowId);
}
