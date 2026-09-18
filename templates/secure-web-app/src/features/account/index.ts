/**
 * The signed-in user's own account: profile, email address, active sessions, one-time codes (enrol / disable),
 * data export and account deletion. Changing the email address or one-time code settings requires re-entering
 * the password (and a code when enrolled) within the last five minutes.
 */
import type { Request, Response, Router } from 'express';
import { z } from 'zod';
import { config } from '../../config.ts';
import { errors } from '../../lib/errors.ts';
import { renderPage } from '../../lib/views.ts';
import { listEntities } from '../../security/authz.ts';
import { emit } from '../../security/events.ts';
import { verifyPassword } from '../../security/password.ts';
import { checkAccountLimit, checkClientLimit, clearAccount, recordAccountFailure, recordClientFailure } from '../../security/rate-limit.ts';
import { safeLocalPath } from '../../security/redirect.ts';
import { defineRoute } from '../../security/routes.ts';
import { listUserSessions, revokeAllForUser, revokeUserSession } from '../../security/session.ts';
import { schemas, type FieldErrors } from '../../security/validate.ts';
import { confirmEnrolment, disableMfa, isEnrolled, remainingRecoveryCodes, startEnrolment, verifyUserCode } from '../auth/mfa.ts';
import { countAdmins, findUserByEmail, findUserById, pseudonymiseAndDelete, toOwnerDto, updateProfile, type UserRow } from '../auth/repo.ts';

const ProfileBody = z.strictObject({ name: schemas.personName });
const EmailBody = z.strictObject({ email: schemas.email });
const SessionParams = z.strictObject({ id: z.string().regex(/^[a-f0-9]{12}$/) });
const CodeBody = z.strictObject({ code: schemas.totpCode });
const ReauthQuery = z.strictObject({ next: schemas.localPath.optional() });
const ReauthBody = z.strictObject({ password: schemas.password, code: z.string().trim().max(24).optional(), next: schemas.localPath.optional() });
const DeleteBody = z.strictObject({ password: schemas.password });

/** "Return to" targets after re-authentication stay inside the account area. */
const ACCOUNT_PATHS = ['/account'];

function currentUser(req: Request): UserRow {
  const user = findUserById(req.user!.id);
  if (!user) throw errors.unauthenticated();
  return user;
}

function accountLocals(req: Request, user: UserRow): Record<string, unknown> {
  return {
    title: 'Your account',
    account: toOwnerDto(user),
    recoveryCodesLeft: remainingRecoveryCodes(user.id),
    canDisableMfa: !(req.user!.isAdmin && config.ADMIN_MFA_REQUIRED),
    userMfaAvailable: config.USER_MFA_AVAILABLE || req.user!.isAdmin,
  };
}

/** Sends the user to the password confirmation page unless they confirmed it within the last five minutes. */
function requireRecentReauth(req: Request, res: Response, next: string): boolean {
  if (req.session.recentlyReauthenticated()) return true;
  res.redirect(303, `/account/reauth?next=${encodeURIComponent(safeLocalPath(next, ACCOUNT_PATHS, '/account'))}`);
  return false;
}

export function register(router: Router): void {
  defineRoute(router, { method: 'GET', path: '/account', auth: 'user', summary: 'Your account' }, (req, res) => {
    renderPage(req, res, 'account/index', accountLocals(req, currentUser(req)));
  });

  defineRoute(router, { method: 'GET', path: '/account/profile', auth: 'user', summary: 'Edit your name' }, (req, res) => {
    const user = currentUser(req);
    renderPage(req, res, 'account/profile', { title: 'Your details', account: toOwnerDto(user), values: { name: user.name ?? '' } });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/account/profile',
      auth: 'user',
      schema: { body: ProfileBody },
      onInvalid: (req, res, fields) => {
        const user = currentUser(req);
        renderPage(req, res, 'account/profile', { title: 'Your details', account: toOwnerDto(user), errors: fields, values: { name: user.name ?? '' } }, 400);
      },
      summary: 'Update your name',
    },
    (req, res) => {
      const user = currentUser(req);
      updateProfile(user.id, { name: req.valid.body.name || null });
      req.session.flash('success', 'Your details were saved.');
      res.redirect(303, '/account');
    },
  );

  defineRoute(router, { method: 'GET', path: '/account/email', auth: 'user', summary: 'Change your email address' }, (req, res) => {
    const user = currentUser(req);
    renderPage(req, res, 'account/email', { title: 'Change your email address', account: toOwnerDto(user), values: { email: user.email } });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/account/email',
      auth: 'user',
      schema: { body: EmailBody },
      onInvalid: (req, res, fields) => {
        const user = currentUser(req);
        renderPage(req, res, 'account/email', { title: 'Change your email address', account: toOwnerDto(user), errors: fields, values: {} }, 400);
      },
      summary: 'Change your email address (password confirmation required)',
    },
    (req, res) => {
      const user = currentUser(req);
      const { email } = req.valid.body;
      if (email === user.email) return res.redirect(303, '/account');
      if (!requireRecentReauth(req, res, '/account/email')) return;
      const taken = findUserByEmail(email);
      if (taken && taken.id !== user.id) {
        // Same outcome as success so the form does not reveal which addresses have accounts.
        req.session.flash('info', 'If that email address is available, your account now uses it.');
        return res.redirect(303, '/account');
      }
      updateProfile(user.id, { email });
      req.session.flash('success', 'Your email address was changed.');
      res.redirect(303, '/account');
    },
  );

  defineRoute(router, { method: 'GET', path: '/account/sessions', auth: 'user', summary: 'Devices signed in to your account' }, (req, res) => {
    renderPage(req, res, 'account/sessions', { title: 'Where you are signed in', sessions: listUserSessions(req.user!.id, req.session.idHash) });
  });
  defineRoute(
    router,
    { method: 'POST', path: '/account/sessions/:id/revoke', auth: 'user', schema: { params: SessionParams }, summary: 'Sign out one device' },
    (req, res) => {
      const ok = revokeUserSession(req.user!.id, req.valid.params.id);
      if (ok) emit('session.revoked', { req, count: 1, reason: 'user-revoked-one' });
      req.session.flash(ok ? 'success' : 'error', ok ? 'That device was signed out.' : 'That session was not found.');
      res.redirect(303, '/account/sessions');
    },
  );
  defineRoute(router, { method: 'POST', path: '/account/sessions/revoke-others', auth: 'user', summary: 'Sign out everywhere else' }, (req, res) => {
    revokeAllForUser(req.user!.id, { exceptIdHash: req.session.idHash, reason: 'user-revoked-all', req });
    req.session.flash('success', 'All other devices were signed out.');
    res.redirect(303, '/account/sessions');
  });

  defineRoute(router, { method: 'GET', path: '/account/reauth', auth: 'user', schema: { query: ReauthQuery }, summary: 'Confirm your password before a sensitive change' }, (req, res) => {
    renderPage(req, res, 'account/reauth', { title: 'Confirm it is you', next: safeLocalPath(req.valid.query.next, ACCOUNT_PATHS, '/account'), mfa: req.user!.mfaEnrolled });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/account/reauth',
      auth: 'user',
      rateLimit: 'login',
      schema: { body: ReauthBody },
      onInvalid: (req, res, fields) => renderPage(req, res, 'account/reauth', { title: 'Confirm it is you', errors: fields, next: '/account', mfa: req.user!.mfaEnrolled }, 400),
      summary: 'Confirm your password (and code)',
    },
    async (req, res) => {
      const user = currentUser(req);
      const next = safeLocalPath(req.valid.body.next, ACCOUNT_PATHS, '/account');
      const enrolled = isEnrolled(user.id);
      const limit = checkAccountLimit('login', user.email);
      const clientLimit = checkClientLimit('login', req);
      if (!limit.allowed || !clientLimit.allowed) {
        res.setHeader('Retry-After', String(limit.allowed ? clientLimit.retryAfterSeconds : limit.retryAfterSeconds));
        emit('ratelimit.hit', { req, bucket: 'login' });
        return renderPage(req, res, 'account/reauth', { title: 'Confirm it is you', errors: { _: 'Too many attempts. Please wait and try again.' }, next, mfa: enrolled }, 429);
      }
      let ok = await verifyPassword(req.valid.body.password, user.password_hash);
      if (ok && enrolled) ok = verifyUserCode(user.id, (req.valid.body.code ?? '').replace(' ', '')).ok;
      if (!ok) {
        recordClientFailure('login', req);
        recordAccountFailure('login', user.email);
        emit('auth.reauth.failure', { req, userId: user.id });
        return renderPage(req, res, 'account/reauth', { title: 'Confirm it is you', errors: { _: enrolled ? 'Password or code is incorrect.' : 'Password is incorrect.' }, next, mfa: enrolled }, 400);
      }
      clearAccount('login', user.email);
      req.session.markReauthenticated();
      emit('auth.reauth.success', { req, userId: user.id });
      res.redirect(303, next);
    },
  );

  defineRoute(router, { method: 'GET', path: '/account/mfa/enrol', auth: 'user', summary: 'Set up one-time codes (password confirmation required)' }, (req, res) => {
    if (!config.USER_MFA_AVAILABLE && !req.user!.isAdmin) throw errors.notFound();
    if (isEnrolled(req.user!.id)) {
      req.session.flash('info', 'One-time codes are already set up.');
      return res.redirect(303, '/account');
    }
    if (!requireRecentReauth(req, res, '/account/mfa/enrol')) return;
    const setup = startEnrolment(req.user!.id, req.user!.email);
    renderPage(req, res, 'account/mfa-enrol', { title: 'Set up one-time codes', setup });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/account/mfa/confirm',
      auth: 'user',
      rateLimit: 'mfa',
      schema: { body: CodeBody },
      onInvalid: (req, res, fields) => renderPage(req, res, 'account/mfa-enrol', { title: 'Set up one-time codes', errors: fields, setup: null }, 400),
      summary: 'Confirm the one-time code setup',
    },
    (req, res) => {
      const limit = checkAccountLimit('mfa', req.user!.id);
      if (!limit.allowed) {
        res.setHeader('Retry-After', String(limit.retryAfterSeconds));
        emit('ratelimit.hit', { req, bucket: 'mfa' });
        return renderPage(req, res, 'account/mfa-enrol', { title: 'Set up one-time codes', errors: { _: 'Too many attempts. Please wait and try again.' }, setup: null }, 429);
      }
      const result = confirmEnrolment(req.user!.id, req.valid.body.code.replace(' ', ''));
      if (!result.ok) {
        recordAccountFailure('mfa', req.user!.id);
        emit('auth.mfa.failure', { req, phase: 'enrol' });
        return renderPage(req, res, 'account/mfa-enrol', { title: 'Set up one-time codes', errors: { code: result.reason }, setup: null }, 400);
      }
      clearAccount('mfa', req.user!.id);
      emit('auth.mfa.enrolled', { req });
      revokeAllForUser(req.user!.id, { exceptIdHash: req.session.idHash, reason: 'mfa-enrolled', req });
      renderPage(req, res, 'account/mfa-recovery-codes', { title: 'Your recovery codes', codes: result.recoveryCodes });
    },
  );
  defineRoute(router, { method: 'POST', path: '/account/mfa/disable', auth: 'user', summary: 'Turn off one-time codes (password confirmation required)' }, (req, res) => {
    if (req.user!.isAdmin && config.ADMIN_MFA_REQUIRED) throw errors.forbidden('Administrators must keep one-time codes switched on.');
    if (!requireRecentReauth(req, res, '/account')) return;
    disableMfa(req.user!.id);
    emit('auth.mfa.disabled', { req });
    revokeAllForUser(req.user!.id, { exceptIdHash: req.session.idHash, reason: 'mfa-disabled', req });
    req.session.flash('success', 'One-time codes were switched off for your account.');
    res.redirect(303, '/account');
  });

  defineRoute(router, { method: 'GET', path: '/account/export', auth: 'user', kind: 'api', summary: 'Download a copy of your data (JSON)' }, (req, res) => {
    const user = currentUser(req);
    const data: Record<string, unknown> = {
      exportedAt: new Date().toISOString(),
      account: toOwnerDto(user),
      sessions: listUserSessions(user.id, req.session.idHash),
    };
    for (const entity of listEntities()) {
      if (entity.exportForUser) data[entity.name] = entity.exportForUser(user.id);
    }
    emit('data.exported', { req });
    res.setHeader('Content-Disposition', 'attachment; filename="my-data.json"');
    res.setHeader('Cache-Control', 'no-store, private');
    res.json(data);
  });

  defineRoute(router, { method: 'GET', path: '/account/delete', auth: 'user', summary: 'Delete your account (confirmation page)' }, (req, res) => {
    renderPage(req, res, 'account/delete', { title: 'Delete your account', lastAdmin: req.user!.isAdmin && countAdmins() <= 1 });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/account/delete',
      auth: 'user',
      rateLimit: 'login',
      schema: { body: DeleteBody },
      onInvalid: (req, res, fields: FieldErrors) => renderPage(req, res, 'account/delete', { title: 'Delete your account', errors: fields, lastAdmin: false }, 400),
      summary: 'Delete your account and data (password required)',
    },
    async (req, res) => {
      const user = currentUser(req);
      if (req.user!.isAdmin && countAdmins() <= 1) throw errors.forbidden('You are the only administrator. Make someone else an administrator first.');
      if (!(await verifyPassword(req.valid.body.password, user.password_hash))) {
        recordClientFailure('login', req);
        recordAccountFailure('login', user.email);
        emit('auth.reauth.failure', { req, userId: user.id, purpose: 'delete' });
        return renderPage(req, res, 'account/delete', { title: 'Delete your account', errors: { password: 'Your password is not correct.' }, lastAdmin: false }, 400);
      }
      // With one-time codes enrolled the password alone is not enough: the code was checked on the confirmation page.
      if (isEnrolled(user.id) && !requireRecentReauth(req, res, '/account/delete')) return;
      for (const entity of listEntities()) entity.deleteForUser?.(user.id);
      pseudonymiseAndDelete(user.id);
      emit('data.deleted', { req, userId: user.id });
      req.session.destroy();
      res.redirect(303, '/');
    },
  );
}
