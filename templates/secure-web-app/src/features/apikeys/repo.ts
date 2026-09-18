/**
 * API keys for the optional public API (contract §1.12, TPL-APIKEY-01). Format `sk_<8 char prefix>_<32 bytes
 * base64url>`; only `HMAC-SHA256(TOKEN_HMAC_KEY, key)` and the lookup prefix are ever stored — the same keyed
 * hash already used for password reset tokens (`src/security/password.ts#hmacToken`).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { all, get, nowIso, run } from '../../db/index.ts';
import { pick } from '../../lib/dto.ts';
import { hmacToken } from '../../security/password.ts';
import { registerEntity } from '../../security/authz.ts';

export interface ApiKeyRow {
  id: string;
  prefix: string;
  hash: string;
  user_id: string;
  name: string | null;
  scopes: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

const PREFIX_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const PREFIX_LENGTH = 8;
const SECRET_BYTES = 32;
const MAX_PREFIX_ATTEMPTS = 20;

function randomPrefix(): string {
  const bytes = randomBytes(PREFIX_LENGTH);
  let out = '';
  for (let i = 0; i < PREFIX_LENGTH; i += 1) out += PREFIX_ALPHABET[bytes[i]! % PREFIX_ALPHABET.length];
  return out;
}

export interface ApiKeyFormat {
  prefix: string;
  secret: string;
}

const KEY_PATTERN = /^sk_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{43})$/;

/** Splits a presented `Authorization: Bearer` token into its prefix and secret, or undefined when malformed. */
export function parseApiKey(token: string): ApiKeyFormat | undefined {
  const m = KEY_PATTERN.exec(token.trim());
  if (!m) return undefined;
  return { prefix: m[1]!, secret: m[2]! };
}

export function findKeyByPrefix(prefix: string): ApiKeyRow | undefined {
  return get<ApiKeyRow>('SELECT * FROM api_keys WHERE prefix = ?', [prefix]);
}

export function hashApiKey(fullKey: string): string {
  return hmacToken(fullKey);
}

export interface CreatedKey {
  row: ApiKeyRow;
  fullKey: string;
}

/** Creates a new key for `userId`, retrying on the astronomically unlikely prefix collision. */
export function createApiKey(userId: string, label: string | null): CreatedKey {
  for (let attempt = 0; attempt < MAX_PREFIX_ATTEMPTS; attempt += 1) {
    const prefix = randomPrefix();
    if (findKeyByPrefix(prefix)) continue;
    const secret = randomBytes(SECRET_BYTES).toString('base64url');
    const fullKey = `sk_${prefix}_${secret}`;
    const id = randomUUID();
    const now = nowIso();
    run('INSERT INTO api_keys (id, prefix, hash, user_id, name, scopes, created_at, last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)', [
      id,
      prefix,
      hashApiKey(fullKey),
      userId,
      label,
      '[]',
      now,
    ]);
    const row = get<ApiKeyRow>('SELECT * FROM api_keys WHERE id = ?', [id]);
    if (!row) throw new Error('API key row was not created.');
    return { row, fullKey };
  }
  throw new Error('Could not generate a unique API key prefix.');
}

export function listKeysForUser(userId: string): ApiKeyRow[] {
  return all<ApiKeyRow>('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC', [userId]);
}

export function listAllKeys(limit: number, offset: number): ApiKeyRow[] {
  return all<ApiKeyRow>('SELECT * FROM api_keys ORDER BY created_at DESC LIMIT ? OFFSET ?', [limit, offset]);
}

export function getKey(id: string): ApiKeyRow | undefined {
  return get<ApiKeyRow>('SELECT * FROM api_keys WHERE id = ?', [id]);
}

export function revokeKey(id: string): void {
  run('UPDATE api_keys SET revoked_at = ? WHERE id = ?', [nowIso(), id]);
}

export function touchLastUsed(id: string): void {
  run('UPDATE api_keys SET last_used_at = ? WHERE id = ?', [nowIso(), id]);
}

export function toOwnerDto(row: ApiKeyRow): { id: string; prefix: string; name: string | null; createdAt: string; lastUsedAt: string | null; revoked: boolean } {
  return { ...pick(row, ['id', 'prefix', 'name']), createdAt: row.created_at, lastUsedAt: row.last_used_at, revoked: row.revoked_at !== null };
}

export function toAdminDto(row: ApiKeyRow): ReturnType<typeof toOwnerDto> & { userId: string } {
  return { ...toOwnerDto(row), userId: row.user_id };
}

export function registerApiKeysEntity(): void {
  registerEntity({
    name: 'apikey',
    table: 'api_keys',
    ownerField: 'user_id',
    label: 'API key',
    sampleId: (ownerId) => get<{ id: string }>('SELECT id FROM api_keys WHERE user_id = ? ORDER BY created_at ASC LIMIT 1', [ownerId])?.id,
    exportForUser: (userId) => listKeysForUser(userId).map(toOwnerDto),
    // The api_keys table already cascades on user deletion (ON DELETE CASCADE); nothing else to remove here.
  });
}
