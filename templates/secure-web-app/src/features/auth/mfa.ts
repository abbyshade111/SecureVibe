/**
 * One-time code (TOTP) storage. The seed lives on the user's row, encrypted with field encryption
 * (users.totp_secret_enc); recovery codes are stored hashed in mfa_recovery_codes and are single use.
 * Accepted 30-second steps are remembered on the row so a code can never be used twice.
 */
import { config } from '../../config.ts';
import { get, nowIso, run, withTransaction } from '../../db/index.ts';
import { decryptField, encryptField } from '../../db/field-crypto.ts';
import { logger } from '../../lib/logger.ts';
import {
  base32Encode,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  normaliseRecoveryCode,
  otpauthUrl,
  rememberUsedStep,
  verifyTotp,
} from '../../security/totp.ts';

export const TOTP_COLUMN = 'totp_secret_enc';

interface TotpRow {
  id: string;
  totp_secret_enc: string | null;
  totp_confirmed: number;
  totp_used_steps: string;
  totp_created_at: string | null;
}

function loadRow(userId: string): TotpRow | undefined {
  return get<TotpRow>('SELECT id, totp_secret_enc, totp_confirmed, totp_used_steps, totp_created_at FROM users WHERE id = ?', [userId]);
}

function secretFor(row: TotpRow): Buffer | undefined {
  if (!row.totp_secret_enc) return undefined;
  try {
    return Buffer.from(decryptField(row.totp_secret_enc, 'users', TOTP_COLUMN, row.id), 'base64');
  } catch (err) {
    // A seed that fails authentication (tampered, or written with a key that is no longer configured) must never verify.
    logger.error({ userId: row.id, err: (err as Error).message }, 'stored one-time code seed could not be decrypted');
    return undefined;
  }
}

function usedSteps(row: TotpRow): number[] {
  try {
    const parsed = JSON.parse(row.totp_used_steps) as unknown;
    return Array.isArray(parsed) ? parsed.filter((n): n is number => Number.isInteger(n)) : [];
  } catch {
    return [];
  }
}

export function isEnrolled(userId: string): boolean {
  return loadRow(userId)?.totp_confirmed === 1;
}

/** How long a pending (unconfirmed) enrolment secret stays valid while the user scans it and fetches the page again. */
export const ENROLMENT_SECRET_MINUTES = 30;

/**
 * Starts (or resumes) a pending enrolment and returns what the user needs to add it to their app. A pending
 * secret that is still fresh is shown again instead of being replaced, so reloading the page — or fetching it
 * once more for the form token — does not invalidate the key the user has just scanned. A confirmed account
 * never gets here, and the secret only becomes a second factor once a code from it has been verified.
 */
export function startEnrolment(userId: string, email: string): { base32: string; otpauth: string } {
  const existing = loadRow(userId);
  if (existing?.totp_confirmed === 1) throw new Error('One-time codes are already set up for this account.');
  const pending = existing ? pendingSecret(existing) : undefined;
  if (pending) return { base32: base32Encode(pending), otpauth: otpauthUrl(config.appName, email, pending) };
  const secret = generateTotpSecret();
  run("UPDATE users SET totp_secret_enc = ?, totp_confirmed = 0, totp_used_steps = '[]', totp_created_at = ?, totp_confirmed_at = NULL WHERE id = ?", [
    encryptField(secret.toString('base64'), 'users', TOTP_COLUMN, userId),
    nowIso(),
    userId,
  ]);
  return { base32: base32Encode(secret), otpauth: otpauthUrl(config.appName, email, secret) };
}

/** The unconfirmed secret of an enrolment that was started recently, or undefined when a fresh one is needed. */
function pendingSecret(row: TotpRow): Buffer | undefined {
  if (row.totp_confirmed === 1 || !row.totp_secret_enc) return undefined;
  const startedAt = row.totp_created_at ? new Date(row.totp_created_at).getTime() : Number.NaN;
  if (!Number.isFinite(startedAt) || Date.now() - startedAt > ENROLMENT_SECRET_MINUTES * 60_000) return undefined;
  return secretFor(row);
}

/** Confirms a pending enrolment with a code from the app; returns the recovery codes (shown once). */
export function confirmEnrolment(userId: string, code: string): { ok: true; recoveryCodes: string[] } | { ok: false; reason: string } {
  const row = loadRow(userId);
  if (!row || row.totp_confirmed === 1 || !row.totp_secret_enc) return { ok: false, reason: 'There is no one-time code setup in progress. Start again.' };
  const secret = secretFor(row);
  if (!secret) return { ok: false, reason: 'The setup could not be read. Start again.' };
  const result = verifyTotp(secret, code, []);
  if (!result.ok) return { ok: false, reason: 'That code is not correct. Check the time on your phone and try the newest code.' };
  const codes = generateRecoveryCodes();
  const now = nowIso();
  withTransaction(() => {
    run("UPDATE users SET totp_confirmed = 1, totp_confirmed_at = ?, totp_used_steps = '[]' WHERE id = ?", [now, userId]);
    run('DELETE FROM mfa_recovery_codes WHERE user_id = ?', [userId]);
    for (const c of codes) run('INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)', [userId, hashRecoveryCode(c), now]);
  });
  return { ok: true, recoveryCodes: codes };
}

/** Verifies a 6-digit code for a fully enrolled user and records the step so it cannot be reused. */
export function verifyUserCode(userId: string, code: string): { ok: boolean; reason?: string } {
  const row = loadRow(userId);
  if (!row || row.totp_confirmed !== 1) return { ok: false, reason: 'not-enrolled' };
  const secret = secretFor(row);
  if (!secret) return { ok: false, reason: 'unreadable' };
  const used = usedSteps(row);
  const result = verifyTotp(secret, code, used);
  if (!result.ok) return { ok: false, reason: result.reason };
  run('UPDATE users SET totp_used_steps = ? WHERE id = ?', [JSON.stringify(rememberUsedStep(used, result.step ?? 0)), userId]);
  return { ok: true };
}

/** Uses a recovery code (single use). */
export function consumeRecoveryCode(userId: string, code: string): boolean {
  const normalised = normaliseRecoveryCode(code);
  if (normalised.length !== 10) return false;
  const hash = hashRecoveryCode(normalised);
  const result = run('UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL', [nowIso(), userId, hash]);
  return result.changes === 1;
}

export function remainingRecoveryCodes(userId: string): number {
  return get<{ n: number }>('SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL', [userId])?.n ?? 0;
}

export function disableMfa(userId: string): void {
  withTransaction(() => {
    run("UPDATE users SET totp_secret_enc = NULL, totp_confirmed = 0, totp_used_steps = '[]', totp_created_at = NULL, totp_confirmed_at = NULL WHERE id = ?", [userId]);
    run('DELETE FROM mfa_recovery_codes WHERE user_id = ?', [userId]);
  });
}

/** Test mode: installs a known, already-confirmed seed (base64 of the raw bytes) for a seeded account. */
export function installConfirmedSeed(userId: string, secret: Buffer): void {
  const now = nowIso();
  run("UPDATE users SET totp_secret_enc = ?, totp_confirmed = 1, totp_used_steps = '[]', totp_created_at = ?, totp_confirmed_at = ? WHERE id = ?", [
    encryptField(secret.toString('base64'), 'users', TOTP_COLUMN, userId),
    now,
    now,
    userId,
  ]);
}
