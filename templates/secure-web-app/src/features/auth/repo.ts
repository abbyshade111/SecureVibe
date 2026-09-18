/**
 * User records: the only module that reads or writes the `users` table. Exposes DTOs for the three audiences
 * (public, the user themselves, administrators) so raw rows never reach a page or a JSON response.
 */
import { randomUUID } from 'node:crypto';
import { config } from '../../config.ts';
import { all, checkpoint, get, nowIso, run, withTransaction } from '../../db/index.ts';
import { asBool, pick } from '../../lib/dto.ts';

export interface UserRow {
  id: string;
  email: string;
  name: string | null;
  password_hash: string;
  role: string;
  status: 'active' | 'disabled' | 'deleted';
  must_change_password: number;
  bootstrap_expires_at: string | null;
  failed_logins: number;
  lock_until: string | null;
  last_login_at: string | null;
  totp_secret_enc: string | null;
  totp_confirmed: number;
  totp_used_steps: string;
  totp_created_at: string | null;
  totp_confirmed_at: string | null;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
}

/** What `req.user` carries: never the password hash. */
export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  role: string;
  isAdmin: boolean;
  mustChangePassword: boolean;
  mfaEnrolled: boolean;
  createdAt: string;
}

export function isAdminRole(role: string): boolean {
  return config.roles.some((r) => r.name === role && r.isAdmin);
}

export function roleNames(): string[] {
  return config.roles.map((r) => r.name);
}

export function findUserById(id: string): UserRow | undefined {
  return get<UserRow>('SELECT * FROM users WHERE id = ? AND status <> ?', [id, 'deleted']);
}

export function findUserByEmail(email: string): UserRow | undefined {
  return get<UserRow>('SELECT * FROM users WHERE email = ? AND status <> ?', [email.trim().toLowerCase(), 'deleted']);
}

export function mfaEnrolled(userId: string): boolean {
  return get<{ n: number }>('SELECT COUNT(*) AS n FROM users WHERE id = ? AND totp_confirmed = 1', [userId])?.n === 1;
}

export function toSessionUser(row: UserRow): SessionUser {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    isAdmin: isAdminRole(row.role),
    mustChangePassword: asBool(row.must_change_password),
    mfaEnrolled: row.totp_confirmed === 1,
    createdAt: row.created_at,
  };
}

export interface CreateUserInput {
  email: string;
  name?: string | null;
  passwordHash: string;
  role: string;
  mustChangePassword?: boolean;
  bootstrapExpiresAt?: string | null;
}

export function createUser(input: CreateUserInput): UserRow {
  const id = randomUUID();
  const now = nowIso();
  run(
    'INSERT INTO users (id, email, name, password_hash, role, status, must_change_password, bootstrap_expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [id, input.email.trim().toLowerCase(), input.name ?? null, input.passwordHash, input.role, 'active', input.mustChangePassword ? 1 : 0, input.bootstrapExpiresAt ?? null, now, now],
  );
  const row = findUserById(id);
  if (!row) throw new Error('User was not created.');
  return row;
}

export function countUsers(): number {
  return get<{ n: number }>('SELECT COUNT(*) AS n FROM users WHERE status <> ?', ['deleted'])?.n ?? 0;
}

export function countAdmins(): number {
  const adminRoles = config.roles.filter((r) => r.isAdmin).map((r) => r.name);
  const placeholders = adminRoles.map(() => '?').join(',');
  return get<{ n: number }>(`SELECT COUNT(*) AS n FROM users WHERE status = 'active' AND role IN (${placeholders})`, adminRoles)?.n ?? 0;
}

/** The oldest active administrator: who a SecureVibe app preview signs in as (see /preview-signin). */
export function firstAdmin(): UserRow | undefined {
  const adminRoles = config.roles.filter((r) => r.isAdmin).map((r) => r.name);
  const placeholders = adminRoles.map(() => '?').join(',');
  return get<UserRow>(`SELECT * FROM users WHERE status = 'active' AND role IN (${placeholders}) ORDER BY created_at ASC LIMIT 1`, adminRoles);
}

export function listUsers(limit: number, offset: number): UserRow[] {
  return all<UserRow>('SELECT * FROM users WHERE status <> ? ORDER BY created_at DESC LIMIT ? OFFSET ?', ['deleted', limit, offset]);
}

export function updatePassword(userId: string, passwordHash: string, clearMustChange = true): void {
  run('UPDATE users SET password_hash = ?, must_change_password = CASE WHEN ? THEN 0 ELSE must_change_password END, bootstrap_expires_at = NULL, failed_logins = 0, lock_until = NULL, updated_at = ? WHERE id = ?', [
    passwordHash,
    clearMustChange ? 1 : 0,
    nowIso(),
    userId,
  ]);
}

export function updateProfile(userId: string, fields: { name?: string | null; email?: string }): void {
  const now = nowIso();
  if (fields.email !== undefined) run('UPDATE users SET email = ?, updated_at = ? WHERE id = ?', [fields.email.trim().toLowerCase(), now, userId]);
  if (fields.name !== undefined) run('UPDATE users SET name = ?, updated_at = ? WHERE id = ?', [fields.name, now, userId]);
}

export function setStatus(userId: string, status: 'active' | 'disabled'): void {
  run('UPDATE users SET status = ?, updated_at = ? WHERE id = ?', [status, nowIso(), userId]);
}

export function setRole(userId: string, role: string): void {
  run('UPDATE users SET role = ?, updated_at = ? WHERE id = ?', [role, nowIso(), userId]);
}

export function recordLoginSuccess(userId: string): void {
  run('UPDATE users SET failed_logins = 0, lock_until = NULL, last_login_at = ?, updated_at = ? WHERE id = ?', [nowIso(), nowIso(), userId]);
}

export function recordLoginFailure(userId: string, lockUntil: string | null): void {
  run('UPDATE users SET failed_logins = failed_logins + 1, lock_until = COALESCE(?, lock_until), updated_at = ? WHERE id = ?', [lockUntil, nowIso(), userId]);
}

/**
 * Deletes an account while keeping the audit trail meaningful: the row is kept with a pseudonymous email and no
 * name, password or MFA data; related records (sessions, MFA, tokens) go with it.
 */
export function pseudonymiseAndDelete(userId: string): void {
  const now = nowIso();
  withTransaction(() => {
    run('DELETE FROM sessions WHERE user_id = ?', [userId]);
    run('DELETE FROM mfa_recovery_codes WHERE user_id = ?', [userId]);
    run('DELETE FROM password_resets WHERE user_id = ?', [userId]);
    run('DELETE FROM api_keys WHERE user_id = ?', [userId]);
    run('DELETE FROM idempotency_keys WHERE user_id = ?', [userId]);
    run(
      "UPDATE users SET email = ?, name = NULL, password_hash = 'deleted', status = 'deleted', totp_secret_enc = NULL, totp_confirmed = 0, totp_used_steps = '[]', totp_created_at = NULL, totp_confirmed_at = NULL, deleted_at = ?, updated_at = ? WHERE id = ?",
      [`deleted-${userId}@deleted.invalid`, now, now, userId],
    );
  });
  // Fold the write-ahead log into the database so no earlier copy of the personal data lingers on disk.
  checkpoint();
}

/** Visible to any signed-in user (for example as the author of a record). */
export function toPublicDto(row: UserRow): { id: string; name: string | null } {
  return pick(row, ['id', 'name']);
}

/** What a user sees about themselves. */
export function toOwnerDto(row: UserRow): {
  id: string;
  email: string;
  name: string | null;
  role: string;
  mfaEnrolled: boolean;
  /** True while the account still has to replace its one-time or reset password. */
  credentialUpdateRequired: boolean;
  createdAt: string;
  lastLoginAt: string | null;
} {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    mfaEnrolled: row.totp_confirmed === 1,
    credentialUpdateRequired: asBool(row.must_change_password),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

/** What administrators see in user management. */
export function toAdminDto(row: UserRow): ReturnType<typeof toOwnerDto> & {
  status: string;
  failedLogins: number;
  lockUntil: string | null;
  bootstrapExpiresAt: string | null;
  updatedAt: string;
} {
  return {
    ...toOwnerDto(row),
    status: row.status,
    failedLogins: row.failed_logins,
    lockUntil: row.lock_until,
    bootstrapExpiresAt: row.bootstrap_expires_at,
    updatedAt: row.updated_at,
  };
}
