/**
 * Sign-in, sign-out, registration (per registration mode), one-time code step, password reset and password change.
 * Every response to a failed sign-in looks the same, unknown accounts cost the same time as wrong passwords, and
 * repeated failures slow down and temporarily lock the account (never permanently).
 */
import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { Request, Response, Router } from 'express';
import { z } from 'zod';
import { config } from '../../config.ts';
import { get, nowIso, run, withTransaction } from '../../db/index.ts';
import { errors } from '../../lib/errors.ts';
import { renderPage } from '../../lib/views.ts';
import { PASSWORD_CHANGE_PATH } from '../../security/authz.ts';
import { emit } from '../../security/events.ts';
import { clearSiteData } from '../../security/headers.ts';
import {
  checkPasswordPolicy,
  createOpaqueToken,
  dummyVerify,
  hashEmailForLogs,
  hashPassword,
  hmacToken,
  verifyPassword,
} from '../../security/password.ts';
import { checkAccountLimit, checkClientLimit, clearAccount, recordAccountFailure, recordClientFailure } from '../../security/rate-limit.ts';
import { safeLocalPath, safeRedirect } from '../../security/redirect.ts';
import { defineRoute } from '../../security/routes.ts';
import { revokeAllForUser } from '../../security/session.ts';
import { schemas, type FieldErrors } from '../../security/validate.ts';
import { deliver } from './mail.ts';
import { consumeRecoveryCode, isEnrolled, verifyUserCode } from './mfa.ts';
import {
  createUser,
  findUserByEmail,
  findUserById,
  firstAdmin,
  recordLoginFailure,
  recordLoginSuccess,
  updatePassword,
  type UserRow,
} from './repo.ts';

export const RESET_TOKEN_MINUTES = 15;
export const INVITE_TOKEN_DAYS = 7;
const LOGIN_FAILED_MESSAGE = 'Email or password is incorrect.';

const LoginQuery = z.strictObject({ next: schemas.localPath.optional() });
const PreviewSigninQuery = z.strictObject({ t: z.string().min(32).max(200).optional() });
const LoginBody = z.strictObject({ email: schemas.email, password: schemas.password, next: schemas.localPath.optional() });
const MfaBody = z.strictObject({ code: z.string().trim().min(6).max(24) });
// The repeat-the-password fields are a typing aid: they are checked when present, never required, so a client
// that sends only the password is answered by the policy, not by a validation error.
const RegisterBody = z.strictObject({
  name: z.string().trim().max(80).optional(),
  email: schemas.email,
  password: schemas.password,
  passwordConfirm: schemas.password.optional(),
});
const ForgotBody = z.strictObject({ email: schemas.email });
const TokenParams = z.strictObject({ token: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/) });
const ResetBody = z.strictObject({ password: schemas.password, passwordConfirm: schemas.password.optional() });
const ChangePasswordBody = z.strictObject({
  currentPassword: schemas.password,
  newPassword: schemas.password,
  newPasswordConfirm: schemas.password.optional(),
  logoutEverywhere: schemas.bool.optional(),
});

function rerender(view: string, extra: (req: Request) => Record<string, unknown> = () => ({})) {
  return (req: Request, res: Response, fields: FieldErrors) => {
    renderPage(req, res, view, { errors: fields, values: safeValues(req), ...extra(req) }, 400);
  };
}

/** Only non-secret form values are echoed back into a re-rendered form. */
function safeValues(req: Request): Record<string, string> {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const out: Record<string, string> = {};
  for (const key of ['email', 'name', 'next']) {
    const v = body[key];
    if (typeof v === 'string') out[key] = v.slice(0, 254);
  }
  return out;
}

function pendingMfaUser(req: Request): UserRow | undefined {
  if (!req.session.userId || req.session.mfaVerified) return undefined;
  const user = findUserById(req.session.userId);
  return user && user.status === 'active' ? user : undefined;
}

function defaultRole(): string {
  const nonAdmin = config.roles.filter((r) => !r.isAdmin);
  return nonAdmin[nonAdmin.length - 1]?.name ?? config.adminRole;
}

function tooManyAttempts(req: Request, res: Response, view: string, retryAfterSeconds: number, bucket: 'login' | 'mfa' | 'reset', extra: Record<string, unknown> = {}): void {
  res.setHeader('Retry-After', String(retryAfterSeconds));
  emit('ratelimit.hit', { req, bucket });
  const minutes = Math.max(1, Math.ceil(retryAfterSeconds / 60));
  renderPage(req, res, view, { errors: { _: `Too many attempts. Please wait about ${minutes} minute${minutes === 1 ? '' : 's'} and try again.` }, values: safeValues(req), ...extra }, 429);
}

async function finishLogin(req: Request, res: Response, user: UserRow, factor: 'password' | 'password+totp', next: string | undefined): Promise<void> {
  req.session.rotate(user.id, true);
  recordLoginSuccess(user.id);
  emit('auth.login.success', { req, userId: user.id, factor });
  const target = safeLocalPath(next, undefined, '/');
  res.redirect(303, user.must_change_password === 1 ? PASSWORD_CHANGE_PATH : target);
}

export function createInviteOrResetToken(userId: string, kind: 'reset' | 'invite'): string {
  const token = createOpaqueToken(16);
  const ttlMs = kind === 'reset' ? RESET_TOKEN_MINUTES * 60_000 : INVITE_TOKEN_DAYS * 86_400_000;
  const now = Date.now();
  withTransaction(() => {
    run('UPDATE password_resets SET used_at = ? WHERE user_id = ? AND kind = ? AND used_at IS NULL', [nowIso(), userId, kind]);
    run('INSERT INTO password_resets (id, user_id, token_hash, kind, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)', [
      randomUUID(),
      userId,
      hmacToken(token),
      kind,
      new Date(now).toISOString(),
      new Date(now + ttlMs).toISOString(),
    ]);
  });
  return token;
}

interface ResetRow {
  id: string;
  user_id: string;
  kind: 'reset' | 'invite';
  expires_at: string;
  used_at: string | null;
}

function findLiveToken(token: string): ResetRow | undefined {
  const row = get<ResetRow>('SELECT id, user_id, kind, expires_at, used_at FROM password_resets WHERE token_hash = ?', [hmacToken(token)]);
  if (!row || row.used_at !== null || row.expires_at < nowIso()) return undefined;
  return row;
}

export function register(router: Router): void {
  defineRoute(router, { method: 'GET', path: '/', auth: 'public', summary: 'Home page' }, (req, res) => {
    renderPage(req, res, 'home', { title: config.appName });
  });

  defineRoute(router, { method: 'GET', path: '/login', auth: 'public', schema: { query: LoginQuery }, summary: 'Sign-in form' }, (req, res) => {
    if (req.user) return res.redirect(303, '/');
    renderPage(req, res, 'auth/login', { title: 'Sign in', values: { next: req.valid.query.next ?? '' } });
  });

  defineRoute(
    router,
    { method: 'POST', path: '/login', auth: 'public', rateLimit: 'login', schema: { body: LoginBody }, onInvalid: rerender('auth/login'), summary: 'Sign in with email and password' },
    async (req, res) => {
      const { email, password, next } = req.valid.body;
      const limit = checkAccountLimit('login', email);
      if (!limit.allowed) return tooManyAttempts(req, res, 'auth/login', limit.retryAfterSeconds, 'login');
      // The per-address budget counts failed attempts, so guessing from one client is capped without ever
      // locking out a shared address whose people all sign in successfully.
      const clientLimit = checkClientLimit('login', req);
      if (!clientLimit.allowed) return tooManyAttempts(req, res, 'auth/login', clientLimit.retryAfterSeconds, 'login');

      const user = findUserByEmail(email);
      const now = nowIso();
      let reason: string | undefined;
      if (!user) reason = 'unknown-account';
      else if (user.status !== 'active') reason = 'disabled';
      else if (user.lock_until && user.lock_until > now) reason = 'locked';
      else if (user.bootstrap_expires_at && user.bootstrap_expires_at < now && user.must_change_password === 1) reason = 'bootstrap-expired';

      let ok = false;
      if (reason) await dummyVerify(password);
      else if (user) {
        ok = await verifyPassword(password, user.password_hash);
        if (!ok) reason = 'wrong-password';
      }

      if (!ok || !user) {
        recordClientFailure('login', req);
        const lockSeconds = recordAccountFailure('login', email);
        if (user) recordLoginFailure(user.id, lockSeconds ? new Date(Date.now() + lockSeconds * 1000).toISOString() : null);
        emit('auth.login.failure', { req, userId: user?.id ?? null, reason, emailHash: hashEmailForLogs(email) });
        if (lockSeconds) emit('auth.lockout', { req, userId: user?.id ?? null, emailHash: hashEmailForLogs(email), seconds: lockSeconds });
        return renderPage(req, res, 'auth/login', { title: 'Sign in', errors: { _: LOGIN_FAILED_MESSAGE }, values: { email, next: next ?? '' } }, 400);
      }

      clearAccount('login', email);
      if (isEnrolled(user.id)) {
        req.session.rotate(user.id, false);
        if (next) req.session.set('next', next);
        return res.redirect(303, '/login/mfa');
      }
      await finishLogin(req, res, user, 'password', next);
    },
  );

  // SecureVibe's app preview: the link it shows signs the person in, so trying the app out needs no password.
  // Only ever active on a loopback-only, plain-http preview process (config.previewMode) with a 32+ character
  // one-time value in PREVIEW_SIGNIN_TOKEN; a real deployment has neither, and this route then behaves as if the
  // link were wrong.
  defineRoute(
    router,
    { method: 'GET', path: '/preview-signin', auth: 'public', rateLimit: 'login', schema: { query: PreviewSigninQuery }, summary: 'Sign in to a SecureVibe app preview' },
    async (req, res) => {
      if (req.user) return res.redirect(303, '/');
      const expected = config.PREVIEW_SIGNIN_TOKEN.trim();
      const presented = req.valid.query.t ?? '';
      const matches =
        config.previewMode &&
        presented.length === expected.length &&
        timingSafeEqual(Buffer.from(presented, 'utf8'), Buffer.from(expected, 'utf8'));
      const admin = matches ? firstAdmin() : undefined;
      if (!matches || !admin) {
        recordClientFailure('login', req);
        emit('auth.login.failure', { req, userId: null, reason: 'preview-link' });
        return renderPage(req, res, 'auth/login', { title: 'Sign in', errors: { _: LOGIN_FAILED_MESSAGE }, values: {} }, 400);
      }
      req.session.rotate(admin.id, true);
      recordLoginSuccess(admin.id);
      emit('auth.login.success', { req, userId: admin.id, factor: 'password' });
      res.redirect(303, '/');
    },
  );

  defineRoute(router, { method: 'GET', path: '/login/mfa', auth: 'public', summary: 'One-time code step of sign-in' }, (req, res) => {
    if (!pendingMfaUser(req)) return res.redirect(303, '/login');
    renderPage(req, res, 'auth/mfa', { title: 'Enter your one-time code' });
  });

  defineRoute(
    router,
    { method: 'POST', path: '/login/mfa', auth: 'public', rateLimit: 'mfa', schema: { body: MfaBody }, onInvalid: rerender('auth/mfa'), summary: 'Verify the one-time code' },
    async (req, res) => {
      const user = pendingMfaUser(req);
      if (!user) return res.redirect(303, '/login');
      const limit = checkAccountLimit('mfa', user.id);
      if (!limit.allowed) return tooManyAttempts(req, res, 'auth/mfa', limit.retryAfterSeconds, 'mfa');
      const code = req.valid.body.code;
      let verified = false;
      if (/^\d{3} ?\d{3}$/.test(code)) verified = verifyUserCode(user.id, code.replace(' ', '')).ok;
      else verified = consumeRecoveryCode(user.id, code);
      if (!verified) {
        recordAccountFailure('mfa', user.id);
        emit('auth.mfa.failure', { req, userId: user.id });
        return renderPage(req, res, 'auth/mfa', { title: 'Enter your one-time code', errors: { code: 'That code is not correct or was already used.' } }, 400);
      }
      clearAccount('mfa', user.id);
      const next = req.session.get<string>('next');
      await finishLogin(req, res, user, 'password+totp', next);
    },
  );

  defineRoute(router, { method: 'POST', path: '/logout', auth: 'public', summary: 'Sign out' }, (req, res) => {
    const userId = req.user?.id ?? req.session.userId ?? null;
    if (req.session.exists) {
      req.session.destroy();
      emit('auth.logout', { req, userId });
    }
    clearSiteData(res);
    res.redirect(303, '/login');
  });

  if (config.registrationMode === 'open') {
    defineRoute(router, { method: 'GET', path: '/register', auth: 'public', summary: 'Create an account' }, (req, res) => {
      if (req.user) return res.redirect(303, '/');
      renderPage(req, res, 'auth/register', { title: 'Create an account' });
    });
    defineRoute(
      router,
      { method: 'POST', path: '/register', auth: 'public', rateLimit: 'registration', schema: { body: RegisterBody }, onInvalid: rerender('auth/register'), summary: 'Create an account' },
      async (req, res) => {
        const { name, email, password, passwordConfirm } = req.valid.body;
        const fields: FieldErrors = {};
        if (passwordConfirm !== undefined && password !== passwordConfirm) fields['passwordConfirm'] = 'The two passwords do not match.';
        const policy = checkPasswordPolicy(password, { email, name });
        if (!policy.ok) fields['password'] = policy.reason ?? 'Please choose a different password.';
        if (Object.keys(fields).length) return renderPage(req, res, 'auth/register', { title: 'Create an account', errors: fields, values: { name: name ?? '', email } }, 400);
        if (findUserByEmail(email)) {
          // Same response as success so the form does not reveal which emails have accounts.
          req.session.flash('info', 'If that email address was free, your account was created. Please sign in.');
          return res.redirect(303, '/login');
        }
        const user = createUser({ email, name: name || null, passwordHash: await hashPassword(password), role: defaultRole() });
        emit('auth.login.success', { req, userId: user.id, factor: 'password', registration: true });
        req.session.rotate(user.id, true);
        req.session.flash('success', 'Welcome! Your account is ready.');
        res.redirect(303, '/');
      },
    );
  }

  defineRoute(router, { method: 'GET', path: '/register/invite/:token', auth: 'public', schema: { params: TokenParams }, summary: 'Accept an invitation' }, (req, res) => {
    const row = findLiveToken(req.valid.params.token);
    if (!row || row.kind !== 'invite') return renderPage(req, res, 'auth/token-invalid', { title: 'This link is no longer valid', kind: 'invite' }, 400);
    renderPage(req, res, 'auth/set-password', { title: 'Choose your password', action: `/register/invite/${req.valid.params.token}` });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/register/invite/:token',
      auth: 'public',
      rateLimit: 'reset',
      schema: { params: TokenParams, body: ResetBody },
      onInvalid: rerender('auth/set-password', (req) => ({ action: req.originalUrl })),
      summary: 'Set the password for an invited account',
    },
    async (req, res) => completeSetPassword(req, res, 'invite'),
  );

  defineRoute(router, { method: 'GET', path: '/forgot-password', auth: 'public', summary: 'Request a password reset' }, (req, res) => {
    renderPage(req, res, 'auth/forgot', { title: 'Reset your password' });
  });
  defineRoute(
    router,
    { method: 'POST', path: '/forgot-password', auth: 'public', rateLimit: 'reset', schema: { body: ForgotBody }, onInvalid: rerender('auth/forgot'), summary: 'Send a password reset link' },
    async (req, res) => {
      const { email } = req.valid.body;
      const limit = checkAccountLimit('reset', email);
      if (!limit.allowed) return tooManyAttempts(req, res, 'auth/forgot', limit.retryAfterSeconds, 'reset');
      recordAccountFailure('reset', email);
      const user = findUserByEmail(email);
      emit('auth.password.reset.requested', { req, userId: user?.id ?? null, emailHash: hashEmailForLogs(email) });
      if (user && user.status === 'active') {
        const token = createInviteOrResetToken(user.id, 'reset');
        const link = `${req.protocol}://${req.headers.host}/reset-password/${token}`;
        await deliver({
          to: user.email,
          subject: `Reset your ${config.appName} password`,
          text: `Someone asked to reset the password for this account. If that was you, open this link within ${RESET_TOKEN_MINUTES} minutes:\n\n${link}\n\nIf it was not you, you can ignore this message.`,
        });
      }
      renderPage(req, res, 'auth/forgot-sent', { title: 'Check your email' });
    },
  );

  defineRoute(router, { method: 'GET', path: '/reset-password/:token', auth: 'public', schema: { params: TokenParams }, summary: 'Reset password form' }, (req, res) => {
    const row = findLiveToken(req.valid.params.token);
    if (!row || row.kind !== 'reset') return renderPage(req, res, 'auth/token-invalid', { title: 'This link is no longer valid', kind: 'reset' }, 400);
    renderPage(req, res, 'auth/set-password', { title: 'Choose a new password', action: `/reset-password/${req.valid.params.token}` });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/reset-password/:token',
      auth: 'public',
      rateLimit: 'reset',
      schema: { params: TokenParams, body: ResetBody },
      onInvalid: rerender('auth/set-password', (req) => ({ action: req.originalUrl })),
      summary: 'Set a new password with a reset link',
    },
    async (req, res) => completeSetPassword(req, res, 'reset'),
  );

  defineRoute(router, { method: 'GET', path: PASSWORD_CHANGE_PATH, auth: 'user', summary: 'Change password form' }, (req, res) => {
    renderPage(req, res, 'auth/change-password', { title: 'Change your password', mustChange: req.user!.mustChangePassword });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: PASSWORD_CHANGE_PATH,
      auth: 'user',
      schema: { body: ChangePasswordBody },
      onInvalid: rerender('auth/change-password', (req) => ({ mustChange: req.user?.mustChangePassword ?? false })),
      summary: 'Change password (current password required)',
    },
    async (req, res) => {
      const user = findUserById(req.user!.id);
      if (!user) throw errors.unauthenticated();
      const { currentPassword, newPassword, newPasswordConfirm, logoutEverywhere } = req.valid.body;
      const fields: FieldErrors = {};
      if (!(await verifyPassword(currentPassword, user.password_hash))) fields['currentPassword'] = 'Your current password is not correct.';
      if (newPasswordConfirm !== undefined && newPassword !== newPasswordConfirm) fields['newPasswordConfirm'] = 'The two new passwords do not match.';
      const policy = checkPasswordPolicy(newPassword, { email: user.email, name: user.name });
      if (!policy.ok) fields['newPassword'] = policy.reason ?? 'Please choose a different password.';
      if (newPassword === currentPassword) fields['newPassword'] = 'Your new password must be different from the current one.';
      if (Object.keys(fields).length) return renderPage(req, res, 'auth/change-password', { title: 'Change your password', errors: fields, mustChange: user.must_change_password === 1 }, 400);
      updatePassword(user.id, await hashPassword(newPassword));
      emit('auth.password.changed', { req, userId: user.id });
      if (logoutEverywhere) revokeAllForUser(user.id, { exceptIdHash: req.session.idHash, reason: 'password-changed', req });
      req.session.flash('success', 'Your password was changed.');
      res.redirect(303, '/account');
    },
  );
}

async function completeSetPassword(
  req: Request & { valid: { params: { token: string }; body: { password: string; passwordConfirm?: string } } },
  res: Response,
  kind: 'reset' | 'invite',
): Promise<void> {
  const row = findLiveToken(req.valid.params.token);
  if (!row || row.kind !== kind) return renderPage(req, res, 'auth/token-invalid', { title: 'This link is no longer valid', kind }, 400);
  const user = findUserById(row.user_id);
  if (!user || user.status !== 'active') return renderPage(req, res, 'auth/token-invalid', { title: 'This link is no longer valid', kind }, 400);
  const { password, passwordConfirm } = req.valid.body;
  const fields: FieldErrors = {};
  if (passwordConfirm !== undefined && password !== passwordConfirm) fields['passwordConfirm'] = 'The two passwords do not match.';
  const policy = checkPasswordPolicy(password, { email: user.email, name: user.name });
  if (!policy.ok) fields['password'] = policy.reason ?? 'Please choose a different password.';
  if (Object.keys(fields).length) return renderPage(req, res, 'auth/set-password', { title: 'Choose a password', errors: fields, action: req.originalUrl }, 400);
  const hash = await hashPassword(password);
  withTransaction(() => {
    run('UPDATE password_resets SET used_at = ? WHERE id = ?', [nowIso(), row.id]);
    updatePassword(user.id, hash);
  });
  revokeAllForUser(user.id, { reason: kind === 'reset' ? 'password-reset' : 'invite-accepted', req });
  emit('auth.password.reset.completed', { req, userId: user.id, kind });
  req.session.flash('success', kind === 'reset' ? 'Your password was reset. Please sign in.' : 'Your password is set. Please sign in.');
  safeRedirect(res, '/login');
}
