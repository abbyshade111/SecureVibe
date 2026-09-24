/**
 * Rate-limit presets (in-memory, fixed windows). Keys are the client IP as Express reports it (which honors
 * TRUST_PROXY_HOPS and nothing else), the signed-in user, or the account being targeted. Account presets add an
 * exponential soft lock that grows with repeated failures and always expires — never a permanent lockout.
 * 429 responses always carry Retry-After.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { config } from '../config.ts';
import { errors } from '../lib/errors.ts';
import { emit } from './events.ts';

export type RateLimitPreset = 'general' | 'login' | 'mfa' | 'registration' | 'reset' | 'ai' | 'uploads' | 'api-key';

export interface PresetDefinition {
  /** Human description used in docs/SECURITY.md. */
  description: string;
  windowMs: number;
  /** Limit keyed by client IP (undefined = no IP limit for this preset). */
  perIp?: number;
  /** Limit keyed by signed-in user (undefined = none). */
  perUser?: number;
  /** Limit keyed by the targeted account (checked inside handlers, see checkAccountLimit). */
  perAccount?: number;
  /**
   * When set, the per-IP budget counts failed attempts only and is checked inside handlers
   * (see checkClientLimit / recordClientFailure) instead of by the middleware. Anti-automation limits exist to
   * stop guessing: counting successful sign-ins as well would lock out everyone behind a shared address.
   */
  perIpCountsFailuresOnly?: boolean;
  /** Whether repeated failures grow a temporary soft lock. */
  backoff?: boolean;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

export function presetDefinitions(): Record<RateLimitPreset, PresetDefinition> {
  const rl = config.rateLimits;
  return {
    general: { description: 'All requests', windowMs: MINUTE, perIp: rl.generalPerMin },
    login: {
      description: 'Sign-in attempts',
      windowMs: 15 * MINUTE,
      perIp: rl.loginPerIp,
      perIpCountsFailuresOnly: true,
      perAccount: rl.loginPerAccount,
      backoff: true,
    },
    mfa: { description: 'One-time code attempts', windowMs: 15 * MINUTE, perAccount: rl.mfaPerAccount, backoff: true },
    registration: { description: 'New account sign-ups', windowMs: HOUR, perIp: rl.registrationPerHour },
    reset: { description: 'Password reset requests', windowMs: HOUR, perIp: rl.resetPerIp, perAccount: rl.resetPerAccount },
    ai: { description: 'AI assistant requests', windowMs: HOUR, perUser: rl.aiPerHour },
    uploads: { description: 'File uploads', windowMs: HOUR, perUser: rl.uploadsPerHour },
    'api-key': { description: 'API requests per key', windowMs: MINUTE, perUser: rl.apiKeyPerMin },
  };
}

interface Bucket {
  count: number;
  windowStart: number;
  /** Consecutive soft locks for this key (drives the exponential backoff). */
  strikes: number;
  lockedUntil: number;
}

const buckets = new Map<string, Bucket>();
const MAX_BUCKETS = 50_000;
const MAX_LOCK_MS = 60 * MINUTE;

function bucketFor(key: string, now: number, windowMs: number): Bucket {
  let b = buckets.get(key);
  if (!b || now - b.windowStart >= windowMs) {
    if (!b && buckets.size >= MAX_BUCKETS) sweep(now);
    b = { count: 0, windowStart: now, strikes: b?.strikes ?? 0, lockedUntil: b?.lockedUntil ?? 0 };
    buckets.set(key, b);
  }
  return b;
}

function sweep(now: number): void {
  for (const [key, b] of buckets) {
    if (now - b.windowStart > 2 * HOUR && b.lockedUntil < now) buckets.delete(key);
  }
}

export interface LimitDecision {
  allowed: boolean;
  retryAfterSeconds: number;
  remaining: number;
}

/** Counts one hit and decides. Used by the middleware and by account-level checks. */
export function hit(key: string, limit: number, windowMs: number, now: number = Date.now()): LimitDecision {
  const b = bucketFor(key, now, windowMs);
  if (b.lockedUntil > now) {
    return { allowed: false, retryAfterSeconds: Math.ceil((b.lockedUntil - now) / 1000), remaining: 0 };
  }
  b.count += 1;
  if (b.count > limit) {
    const retry = Math.ceil((b.windowStart + windowMs - now) / 1000);
    return { allowed: false, retryAfterSeconds: Math.max(1, retry), remaining: 0 };
  }
  return { allowed: true, retryAfterSeconds: 0, remaining: limit - b.count };
}

function keyForRequest(preset: RateLimitPreset, req: Request, scope: 'ip' | 'user'): string {
  if (scope === 'user') return `${preset}:user:${req.user?.id ?? `ip:${req.ip ?? 'unknown'}`}`;
  return `${preset}:ip:${req.ip ?? 'unknown'}`;
}

function reject(req: Request, res: Response, next: NextFunction, preset: RateLimitPreset, decision: LimitDecision): void {
  res.setHeader('Retry-After', String(decision.retryAfterSeconds));
  emit('ratelimit.hit', { req, bucket: preset });
  next(errors.rateLimited(decision.retryAfterSeconds));
}

/** Express middleware for a preset (IP and/or user keyed parts). */
export function limiter(preset: RateLimitPreset): RequestHandler {
  return (req, res, next) => {
    const def = presetDefinitions()[preset];
    if (def.perIp !== undefined && !def.perIpCountsFailuresOnly) {
      const d = hit(keyForRequest(preset, req, 'ip'), def.perIp, def.windowMs);
      if (!d.allowed) return reject(req, res, next, preset, d);
    }
    if (def.perUser !== undefined) {
      const d = hit(keyForRequest(preset, req, 'user'), def.perUser, def.windowMs);
      if (!d.allowed) return reject(req, res, next, preset, d);
    }
    next();
  };
}

function accountKey(preset: RateLimitPreset, account: string): string {
  return `${preset}:acct:${account.trim().toLowerCase()}`;
}

function clientKey(preset: RateLimitPreset, req: Request): string {
  return keyForRequest(preset, req, 'ip');
}

/**
 * Per-client-address check for presets whose IP budget counts failures only (login). Call before verifying
 * credentials; when it returns `allowed: false` respond 429 with Retry-After, and record every failed attempt
 * with recordClientFailure().
 */
export function checkClientLimit(preset: RateLimitPreset, req: Request, now: number = Date.now()): LimitDecision {
  const def = presetDefinitions()[preset];
  if (def.perIp === undefined) return { allowed: true, retryAfterSeconds: 0, remaining: Number.POSITIVE_INFINITY };
  const b = bucketFor(clientKey(preset, req), now, def.windowMs);
  if (b.lockedUntil > now) return { allowed: false, retryAfterSeconds: Math.ceil((b.lockedUntil - now) / 1000), remaining: 0 };
  if (b.count >= def.perIp) {
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((b.windowStart + def.windowMs - now) / 1000)), remaining: 0 };
  }
  return { allowed: true, retryAfterSeconds: 0, remaining: def.perIp - b.count };
}

/** Records one failed attempt against the client address budget of a failure-counted preset. */
export function recordClientFailure(preset: RateLimitPreset, req: Request, now: number = Date.now()): void {
  const def = presetDefinitions()[preset];
  if (def.perIp === undefined) return;
  bucketFor(clientKey(preset, req), now, def.windowMs).count += 1;
}

/**
 * Per-account check for login / mfa / reset. Call before verifying credentials; when it returns `allowed: false`
 * respond 429 with Retry-After. Failures are recorded with recordAccountFailure(); successes clear the counter.
 */
export function checkAccountLimit(preset: RateLimitPreset, account: string, now: number = Date.now()): LimitDecision {
  const def = presetDefinitions()[preset];
  if (def.perAccount === undefined) return { allowed: true, retryAfterSeconds: 0, remaining: Number.POSITIVE_INFINITY };
  const b = bucketFor(accountKey(preset, account), now, def.windowMs);
  if (b.lockedUntil > now) return { allowed: false, retryAfterSeconds: Math.ceil((b.lockedUntil - now) / 1000), remaining: 0 };
  if (b.count >= def.perAccount) {
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((b.windowStart + def.windowMs - now) / 1000)), remaining: 0 };
  }
  return { allowed: true, retryAfterSeconds: 0, remaining: def.perAccount - b.count };
}

/** Records a failed attempt. Returns the soft-lock length in seconds when the limit was just crossed (0 otherwise). */
export function recordAccountFailure(preset: RateLimitPreset, account: string, now: number = Date.now()): number {
  const def = presetDefinitions()[preset];
  if (def.perAccount === undefined) return 0;
  const b = bucketFor(accountKey(preset, account), now, def.windowMs);
  b.count += 1;
  if (b.count >= def.perAccount) {
    if (!def.backoff) return 0;
    b.strikes += 1;
    const lockMs = Math.min(MAX_LOCK_MS, MINUTE * 2 ** (b.strikes - 1));
    b.lockedUntil = now + lockMs;
    b.count = 0;
    b.windowStart = now;
    return Math.ceil(lockMs / 1000);
  }
  return 0;
}

export function clearAccount(preset: RateLimitPreset, account: string): void {
  buckets.delete(accountKey(preset, account));
}

/** Test mode only: clears every counter and lock. */
export function resetRateLimits(): void {
  buckets.clear();
}
