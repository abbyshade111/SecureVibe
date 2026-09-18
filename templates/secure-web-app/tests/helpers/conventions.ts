/**
 * Route paths, form field names and header names the security tests rely on.
 *
 * docs/CONTRACTS.md fixes the HTTP behaviour of the template but not every concrete path or field name.
 * Everything the tests assume beyond the contract lives here, so aligning the template with the tests
 * (or the tests with the template) is a one-file change. Anything discoverable at runtime is taken from
 * `GET /__securevibe/routes` instead (see helpers/app.ts).
 */

export const paths = {
  /** Public pages. */
  home: '/',
  login: '/login',
  /** Second login step for accounts with TOTP enrolled. Accepts a TOTP code or a recovery code in `fields.code`. */
  loginMfa: '/login/mfa',
  logout: '/logout',
  register: '/register',
  forgotPassword: '/forgot-password',
  /** Reset page: GET/POST `/reset-password/<token>`. */
  resetPassword: (token: string) => `/reset-password/${token}`,

  /** Authenticated account pages (`auth: 'user'`). */
  account: '/account',
  changePassword: '/account/password',
  changeEmail: '/account/email',
  profile: '/account/profile',
  reauth: '/account/reauth',
  sessions: '/account/sessions',
  sessionRevoke: (id: string) => `/account/sessions/${id}/revoke`,
  sessionsRevokeOthers: '/account/sessions/revoke-others',
  mfaEnrol: '/account/mfa/enrol',
  mfaConfirm: '/account/mfa/confirm',
  mfaDisable: '/account/mfa/disable',
  dataExport: '/account/export',
  dataDelete: '/account/delete',
  apiKeys: '/account/api-keys',
  apiKeyRevoke: (id: string) => `/account/api-keys/${id}/revoke`,

  /** Admin pages (`auth: 'role:admin'`). */
  adminUsers: '/admin/users',
  adminUserDisable: (id: string) => `/admin/users/${id}/disable`,
  adminUserRevokeSessions: (id: string) => `/admin/users/${id}/sessions/revoke`,
  adminAudit: '/admin/audit',
  adminAiKillSwitch: '/admin/ai/kill-switch',

  /** Optional features. */
  ai: '/ai',
  aiReset: '/ai/reset',
  aiConfirm: (proposalId: string) => `/ai/confirm/${proposalId}`,
  uploads: '/uploads',
  upload: (id: string) => `/uploads/${id}`,
  apiV1: '/api/v1',

  /** Reference feature (mounted with EXAMPLE_FEATURE=1). */
  notesApi: '/api/notes',
  noteApi: (id: string) => `/api/notes/${id}`,

  /** Health and test-mode endpoints (contract §1.5, §1.16). */
  healthz: '/healthz',
  readyz: '/readyz',
  testRoutes: '/__securevibe/routes',
  testEvents: '/__securevibe/events',
  testResetRateLimits: '/__securevibe/reset-rate-limits',
} as const;

export const fields = {
  csrf: '_csrf',
  email: 'email',
  password: 'password',
  /** TOTP code or recovery code on the MFA login step, and on MFA enrol confirmation. */
  code: 'code',
  currentPassword: 'currentPassword',
  newPassword: 'newPassword',
  /** "Log out everywhere" checkbox on the password change form ("1" = checked). */
  logoutEverywhere: 'logoutEverywhere',
  /** Display name on the profile form. */
  name: 'name',
  /** Return-to path accepted by the login page (query string and hidden field). */
  next: 'next',
  /** Multipart field carrying the file on the upload form. */
  file: 'file',
  /** AI assistant message. */
  message: 'message',
  /** API key label on the create form. */
  label: 'label',
  /** Reason field on admin actions (MFA reset, disable). */
  reason: 'reason',
} as const;

export const headers = {
  csrf: 'x-csrf-token',
  idempotency: 'Idempotency-Key',
} as const;

/** Body shape of the reference "notes" entity used for validation, DTO, ownership and idempotency tests. */
export const exampleNote = { title: 'Security test note', body: 'Created by the security test suite.' } as const;

/** Seeded test-mode users (contract §1.16). */
export const users = {
  admin: 'admin@test.local',
  staff: 'staff@test.local',
  member: 'member@test.local',
  member2: 'member2@test.local',
} as const;

/**
 * Test-mode AI provider stub. Without ANTHROPIC_API_KEY in test mode the AI module must answer with a
 * deterministic built-in provider; a message starting with one of these markers selects a scripted reply
 * so the output-side controls can be exercised without a real model.
 */
export const aiStub = {
  /** Reply is malformed (does not match the output schema) -> the app must fall back. */
  malformed: '[[stub:malformed]]',
  /** Reply repeats the system prompt verbatim -> the disclosure filter must block it. */
  disclose: '[[stub:disclose]]',
  /** Reply has stop_reason 'refusal' -> fixed fallback message. */
  refusal: '[[stub:refusal]]',
  /** Reply is longer than 4000 characters -> must be rejected/bounded. */
  overlong: '[[stub:overlong]]',
  /** Reply proposes a mutating tool call (ai-actions) -> must return a proposal, not execute. */
  action: '[[stub:action]]',
  /** Reply contains content the moderation classifier scores above threshold (ai-moderation). */
  harmful: '[[stub:harmful]]',
} as const;

/** Text shown by the app when the AI reply was replaced by the fixed fallback message. */
export const aiFallbackHint = /sorry|cannot|can't|unable|not able|try again/i;
