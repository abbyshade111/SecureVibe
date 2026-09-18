/**
 * Administration: user management (create by invitation, disable, delete, reset one-time codes, sign out
 * everywhere, change role), the security event log with chain verification, and runtime settings such as the AI
 * kill switch. Every route requires the administrator role and every action is logged.
 */
import type { Router } from 'express';
import { z } from 'zod';
import { config } from '../../config.ts';
import { clampLimit, get } from '../../db/index.ts';
import { errors } from '../../lib/errors.ts';
import { aiRuntimeEnabled, setSetting } from '../../lib/settings.ts';
import { renderPage } from '../../lib/views.ts';
import { listEntities } from '../../security/authz.ts';
import { countAudit, queryAudit, verifyChain } from '../../security/audit.ts';
import { emit, SECURITY_EVENTS } from '../../security/events.ts';
import { generateOneTimePassword, hashPassword } from '../../security/password.ts';
import { defineRoute } from '../../security/routes.ts';
import { revokeAllForUser } from '../../security/session.ts';
import { schemas, type FieldErrors } from '../../security/validate.ts';
import { createInviteOrResetToken } from '../auth/index.ts';
import { disableMfa, isEnrolled } from '../auth/mfa.ts';
import { countAdmins, countUsers, createUser, findUserByEmail, findUserById, listUsers, pseudonymiseAndDelete, roleNames, setRole, setStatus, toAdminDto } from '../auth/repo.ts';

const UsersQuery = z.strictObject({ page: schemas.page });
const UserParams = z.strictObject({ id: schemas.id });
const NewUserBody = z.strictObject({ email: schemas.email, name: z.string().trim().max(80).optional(), role: z.string().trim().min(1).max(40) });
const RoleBody = z.strictObject({ role: z.string().trim().min(1).max(40) });
const ReasonBody = z.strictObject({ reason: z.string().trim().min(3).max(200) });
const OptionalReasonBody = z.strictObject({ reason: z.string().trim().max(200).optional() });
const AuditQuery = z.strictObject({
  page: schemas.page,
  event: z.string().trim().max(60).optional(),
  userId: z.string().trim().max(64).optional(),
});
const AiToggleBody = z.strictObject({ enabled: schemas.bool });

const ADMIN = `role:${config.adminRole}` as const;

function renderUserForm(errorsMap: FieldErrors, values: Record<string, string>) {
  return { errors: errorsMap, values, roles: config.roles };
}

export function register(router: Router): void {
  defineRoute(router, { method: 'GET', path: '/admin', auth: ADMIN, summary: 'Administration overview' }, (req, res) => {
    renderPage(req, res, 'admin/index', {
      title: 'Administration',
      stats: { users: countUsers(), admins: countAdmins(), events: countAudit(), entities: listEntities().map((e) => e.name) },
      aiEnabled: config.features.ai ? aiRuntimeEnabled(config.AI_ENABLED) : null,
    });
  });

  defineRoute(router, { method: 'GET', path: '/admin/users', auth: ADMIN, schema: { query: UsersQuery }, summary: 'List accounts' }, (req, res) => {
    const limit = clampLimit(25);
    const page = req.valid.query.page;
    const users = listUsers(limit, (page - 1) * limit).map(toAdminDto);
    renderPage(req, res, 'admin/users', { title: 'Accounts', users, page, hasMore: users.length === limit });
  });

  defineRoute(router, { method: 'GET', path: '/admin/users/new', auth: ADMIN, summary: 'Create an account form' }, (req, res) => {
    renderPage(req, res, 'admin/user-new', { title: 'Invite someone', ...renderUserForm({}, {}) });
  });
  defineRoute(
    router,
    {
      method: 'POST',
      path: '/admin/users',
      auth: ADMIN,
      schema: { body: NewUserBody },
      onInvalid: (req, res, fields) => renderPage(req, res, 'admin/user-new', { title: 'Invite someone', ...renderUserForm(fields, {}) }, 400),
      summary: 'Create an account and an invitation link',
    },
    async (req, res) => {
      const { email, name, role } = req.valid.body;
      const fields: FieldErrors = {};
      if (!roleNames().includes(role)) fields['role'] = 'Please choose one of the listed roles.';
      if (findUserByEmail(email)) fields['email'] = 'An account with this email address already exists.';
      if (Object.keys(fields).length) return renderPage(req, res, 'admin/user-new', { title: 'Invite someone', ...renderUserForm(fields, { email, name: name ?? '' }) }, 400);
      // The account starts with a random password nobody knows; the person sets their own through the invitation link.
      const user = createUser({ email, name: name || null, passwordHash: await hashPassword(generateOneTimePassword()), role, mustChangePassword: true });
      const token = createInviteOrResetToken(user.id, 'invite');
      emit('admin.user.created', { req, targetUserId: user.id, role });
      renderPage(req, res, 'admin/user-invited', {
        title: 'Invitation ready',
        account: toAdminDto(user),
        inviteLink: `${req.protocol}://${req.headers.host}/register/invite/${token}`,
      });
    },
  );

  defineRoute(router, { method: 'GET', path: '/admin/users/:id', auth: ADMIN, schema: { params: UserParams }, summary: 'Account details' }, (req, res) => {
    const user = findUserById(req.valid.params.id);
    if (!user) throw errors.notFound();
    renderPage(req, res, 'admin/user-show', {
      title: user.email,
      account: toAdminDto(user),
      roles: config.roles,
      isSelf: user.id === req.user!.id,
      activeSessions: get<{ n: number }>("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > datetime('now')", [user.id])?.n ?? 0,
    });
  });

  const action = (name: string, summary: string, handler: (req: Parameters<Parameters<typeof defineRoute>[2]>[0] & { valid: { params: { id: string }; body: unknown } }, targetId: string) => void | Promise<void>, body?: z.ZodType) => {
    defineRoute(
      router,
      { method: 'POST', path: `/admin/users/:id/${name}`, auth: ADMIN, schema: { params: UserParams, ...(body ? { body } : {}) }, summary },
      async (req, res) => {
        const target = findUserById(req.valid.params.id);
        if (!target) throw errors.notFound();
        await handler(req as never, target.id);
        res.redirect(303, `/admin/users/${target.id}`);
      },
    );
  };

  action(
    'disable',
    'Disable an account and sign it out everywhere',
    (req, targetId) => {
      if (targetId === req.user!.id) throw errors.forbidden('You cannot disable your own account.');
      setStatus(targetId, 'disabled');
      revokeAllForUser(targetId, { reason: 'admin-disabled', req });
      emit('admin.user.disabled', { req, targetUserId: targetId, reason: (req.valid.body as { reason?: string }).reason ?? null });
      req.session.flash('success', 'The account was disabled and signed out everywhere.');
    },
    OptionalReasonBody,
  );
  action('enable', 'Re-enable an account', (req, targetId) => {
    setStatus(targetId, 'active');
    req.session.flash('success', 'The account was re-enabled.');
  });
  action('delete', 'Delete an account and its data', (req, targetId) => {
    if (targetId === req.user!.id) throw errors.forbidden('You cannot delete your own account here. Use your account page.');
    for (const entity of listEntities()) entity.deleteForUser?.(targetId);
    pseudonymiseAndDelete(targetId);
    emit('admin.user.deleted', { req, targetUserId: targetId });
    emit('data.deleted', { req, userId: targetId, by: 'admin' });
    req.session.flash('success', 'The account was deleted.');
  });
  action(
    'mfa-reset',
    'Remove one-time codes from an account (reason required)',
    (req, targetId) => {
      const reason = (req.valid.body as { reason: string }).reason;
      if (!isEnrolled(targetId)) throw errors.badRequest('This account does not have one-time codes set up.');
      disableMfa(targetId);
      revokeAllForUser(targetId, { reason: 'admin-mfa-reset', req });
      emit('admin.user.mfa_reset', { req, targetUserId: targetId, reason });
      req.session.flash('success', 'One-time codes were removed. The person will be asked to set them up again at next sign-in if required.');
    },
    ReasonBody,
  );
  action('sessions/revoke', 'Sign an account out everywhere', (req, targetId) => {
    const count = revokeAllForUser(targetId, { reason: 'admin-revoked', req });
    emit('admin.user.sessions_revoked', { req, targetUserId: targetId, count });
    req.session.flash('success', `Signed out ${count} session(s).`);
  });
  action(
    'role',
    'Change the role of an account',
    (req, targetId) => {
      const role = (req.valid.body as { role: string }).role;
      if (!roleNames().includes(role)) throw errors.badRequest('Please choose one of the listed roles.');
      if (targetId === req.user!.id) throw errors.forbidden('You cannot change your own role.');
      setRole(targetId, role);
      revokeAllForUser(targetId, { reason: 'role-changed', req });
      req.session.flash('success', 'The role was changed. The person was signed out so the change takes effect.');
    },
    RoleBody,
  );
  action('invite', 'Send a new invitation link', (req, targetId) => {
    const token = createInviteOrResetToken(targetId, 'invite');
    req.session.flash('info', `New invitation link: ${req.protocol}://${req.headers.host}/register/invite/${token}`);
  });

  defineRoute(router, { method: 'GET', path: '/admin/audit', auth: ADMIN, schema: { query: AuditQuery }, summary: 'Security event log' }, (req, res) => {
    const limit = clampLimit(50);
    const { page, event, userId } = req.valid.query;
    const rows = queryAudit({ limit, offset: (page - 1) * limit, event: event || undefined, userId: userId || undefined });
    renderPage(req, res, 'admin/audit', {
      title: 'Security events',
      rows,
      page,
      hasMore: rows.length === limit,
      filters: { event: event ?? '', userId: userId ?? '' },
      eventNames: Object.keys(SECURITY_EVENTS),
      total: countAudit(),
    });
  });
  defineRoute(router, { method: 'GET', path: '/admin/audit/verify', auth: ADMIN, summary: 'Check the event log has not been tampered with' }, (req, res) => {
    renderPage(req, res, 'admin/audit-verify', { title: 'Event log check', result: verifyChain() });
  });

  defineRoute(router, { method: 'GET', path: '/admin/settings', auth: ADMIN, summary: 'Runtime settings' }, (req, res) => {
    renderPage(req, res, 'admin/settings', {
      title: 'Settings',
      aiFeature: config.features.ai,
      aiEnvEnabled: config.AI_ENABLED,
      aiEnabled: aiRuntimeEnabled(config.AI_ENABLED),
      registrationMode: config.registrationMode,
      sessionPolicy: { idle: config.sessionIdleMinutes, absolute: config.sessionAbsoluteHours, max: config.sessionMaxConcurrent },
    });
  });
  defineRoute(router, { method: 'POST', path: '/admin/ai/kill-switch', auth: ADMIN, schema: { body: AiToggleBody }, summary: 'Switch the AI assistant on or off' }, (req, res) => {
    if (!config.features.ai) throw errors.notFound();
    setSetting('ai_enabled', req.valid.body.enabled ? '1' : '0', req.user!.id);
    emit('ai.killswitch.toggled', { req, enabled: req.valid.body.enabled });
    req.session.flash('success', req.valid.body.enabled ? 'The AI assistant is switched on.' : 'The AI assistant is switched off.');
    res.redirect(303, '/admin/settings');
  });
}
