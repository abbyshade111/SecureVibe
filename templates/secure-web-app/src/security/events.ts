/**
 * Security event catalog. `emit()` writes every event as a JSON log line AND as a row in the hash-chained audit
 * table. Event names are fixed here so documentation, tests and the SecureVibe scanner agree on them.
 */
import type { Request } from 'express';
import { logger, redactObject } from '../lib/logger.ts';
import { appendAudit, type AuditRecord } from './audit.ts';

export type Outcome = 'success' | 'failure' | 'blocked';

/** Event name → default outcome and a plain-language description (used by docs/logging.md). */
export const SECURITY_EVENTS = {
  'auth.login.success': { outcome: 'success', description: 'Someone signed in. `factor` says whether a one-time code was used.' },
  'auth.login.failure': { outcome: 'failure', description: 'A sign-in attempt failed (`reason`: wrong password, unknown account, disabled, locked, expired bootstrap).' },
  'auth.logout': { outcome: 'success', description: 'Someone signed out.' },
  'auth.password.changed': { outcome: 'success', description: 'A user changed their password.' },
  'auth.password.reset.requested': { outcome: 'success', description: 'A password reset link was requested (logged whether or not the account exists).' },
  'auth.password.reset.completed': { outcome: 'success', description: 'A password was reset with a valid link.' },
  'auth.mfa.enrolled': { outcome: 'success', description: 'A user set up a one-time code app.' },
  'auth.mfa.disabled': { outcome: 'success', description: 'A user (or an admin) removed one-time codes from an account.' },
  'auth.mfa.failure': { outcome: 'failure', description: 'A one-time code was wrong or reused.' },
  'auth.reauth.success': { outcome: 'success', description: 'A user confirmed their password before a sensitive change.' },
  'auth.reauth.failure': { outcome: 'failure', description: 'Password confirmation before a sensitive change failed.' },
  'auth.lockout': { outcome: 'blocked', description: 'An account was temporarily locked after repeated failed sign-ins.' },
  'authz.denied': { outcome: 'blocked', description: 'Someone tried to open a page or record they are not allowed to use.' },
  'session.revoked': { outcome: 'success', description: 'Sessions were ended (`count`, `reason`).' },
  'validation.rejected': { outcome: 'blocked', description: 'A request was rejected because its input was not valid.' },
  'csrf.rejected': { outcome: 'blocked', description: 'A form or API request failed the cross-site request check.' },
  'ratelimit.hit': { outcome: 'blocked', description: 'A rate limit was reached (`bucket`).' },
  'upload.rejected': { outcome: 'blocked', description: 'An upload was refused (`reason`).' },
  'upload.stored': { outcome: 'success', description: 'A file was stored.' },
  'download.denied': { outcome: 'blocked', description: 'Someone tried to download a file they do not own.' },
  'admin.user.created': { outcome: 'success', description: 'An administrator created an account.' },
  'admin.user.disabled': { outcome: 'success', description: 'An administrator disabled an account.' },
  'admin.user.deleted': { outcome: 'success', description: 'An administrator deleted an account.' },
  'admin.user.mfa_reset': { outcome: 'success', description: 'An administrator removed one-time codes from an account (`reason` recorded).' },
  'admin.user.sessions_revoked': { outcome: 'success', description: 'An administrator signed a user out everywhere.' },
  'data.exported': { outcome: 'success', description: 'A user downloaded a copy of their data.' },
  'data.deleted': { outcome: 'success', description: 'A user account and its data were deleted.' },
  'ai.request': { outcome: 'success', description: 'A request was sent to the AI model (token counts, hashes — never the text).' },
  'ai.input.flagged': { outcome: 'success', description: 'AI input matched a suspicious pattern but was allowed (`rule`).' },
  'ai.input.rejected': { outcome: 'blocked', description: 'AI input was refused (`reason`).' },
  'ai.output.rejected': { outcome: 'blocked', description: 'An AI answer was withheld (`reason`).' },
  'ai.moderation.decision': { outcome: 'success', description: 'The content moderation check made a decision.' },
  'ai.budget.exceeded': { outcome: 'blocked', description: 'A user reached their daily AI budget.' },
  'ai.killswitch.toggled': { outcome: 'success', description: 'An administrator switched the AI assistant on or off.' },
  'outbound.blocked': { outcome: 'blocked', description: 'The app refused to contact a host that is not on the allow-list (`host`).' },
  'outbound.failure': { outcome: 'failure', description: 'A call to an external service failed (`host`).' },
  'breaker.open': { outcome: 'blocked', description: 'Calls to an external service were paused after repeated failures (`host`).' },
  'error.unhandled': { outcome: 'failure', description: 'An unexpected error happened (`reqId` links to the log line).' },
  'config.startup': { outcome: 'success', description: 'The app started (`algorithm` for password hashing, `tlsMode`).' },
} as const;

export type SecurityEventName = keyof typeof SECURITY_EVENTS;

export interface EmitOptions {
  req?: Request;
  userId?: string | null;
  outcome?: Outcome;
  route?: string | null;
  [field: string]: unknown;
}

const listeners = new Set<(record: AuditRecord) => void>();

/** Test hooks and feature modules may observe events (for example to keep in-memory counters). */
export function onSecurityEvent(listener: (record: AuditRecord) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function routeLabel(req: Request | undefined): string | null {
  if (!req) return null;
  const spec = req.routeSpec;
  if (spec) return `${spec.method} ${spec.path}`;
  const path = (req.baseUrl ?? '') + (req.path ?? '');
  return `${req.method} ${path.slice(0, 200)}`;
}

export function emit(event: SecurityEventName, options: EmitOptions = {}): AuditRecord {
  const { req, userId, outcome, route, ...fields } = options;
  const record: AuditRecord = {
    ts: new Date().toISOString(),
    event,
    reqId: req?.id ?? null,
    userId: userId === undefined ? (req?.user?.id ?? null) : userId,
    ip: req?.ip ?? null,
    route: route === undefined ? routeLabel(req) : route,
    outcome: outcome ?? SECURITY_EVENTS[event].outcome,
    fields: redactObject(fields),
  };
  logger.info({ securityEvent: true, ...record }, event);
  try {
    appendAudit(record);
  } catch (err) {
    logger.error({ err: (err as Error).message, event }, 'Could not write the audit row for a security event');
  }
  for (const listener of listeners) {
    try {
      listener(record);
    } catch {
      // A misbehaving listener must never break request handling.
    }
  }
  return record;
}
