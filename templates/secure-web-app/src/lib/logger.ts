/**
 * Structured JSON logging (pino). Every line has a UTC timestamp, the request id when inside a request, and never
 * a secret: keys that look like passwords, tokens, secrets, cookies or authorization headers are redacted at any
 * depth before the line is written. Session ids only ever appear as the first 8 characters of their hash.
 */
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import pino from 'pino';
import type { Logger } from 'pino';
import { config } from '../config.ts';

const SENSITIVE_KEY = /password|passwd|token|secret|totp|api[_-]?key|apikey|authorization|^cookie$|set-cookie|recovery|private[_-]?key/i;
/**
 * Token *counts* are telemetry, not credentials, and AISVS C12.1.3 requires them in the AI log. Without this
 * exception `inputTokens` would match `token` above and be replaced by the string "[redacted]".
 */
const TOKEN_COUNT_KEY = /^(input|output|total|prompt|completion|cache[_-]?read|cache[_-]?write)[_-]?tokens?$|^tokens?[_-]?(count|used|usage)$/i;
const MAX_DEPTH = 6;

/** Returns a copy of `value` with sensitive keys replaced by "[redacted]" (bounded depth, cycle-safe). */
export function redactObject<T>(value: T, depth = 0, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== 'object' || depth > MAX_DEPTH) return value;
  if (seen.has(value as object)) return '[circular]' as unknown as T;
  seen.add(value as object);
  if (Array.isArray(value)) return value.map((v) => redactObject(v, depth + 1, seen)) as unknown as T;
  if (value instanceof Date || Buffer.isBuffer(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY.test(k) && !TOKEN_COUNT_KEY.test(k) ? '[redacted]' : redactObject(v, depth + 1, seen);
  }
  return out as T;
}

/** Only the first 8 hex characters of the SHA-256 of a session id ever reach a log line. */
export function sessionHashPrefix(sessionIdOrHash: string): string {
  return createHash('sha256').update(sessionIdOrHash).digest('hex').slice(0, 8);
}

function buildDestinations(): pino.DestinationStream {
  mkdirSync(dirname(config.logFile), { recursive: true, mode: 0o700 });
  // The log may contain user ids and request details: owner-only permissions, like the database.
  const file = pino.destination({ dest: config.logFile, sync: true, mkdir: true, mode: 0o600 });
  try {
    chmodSync(config.logFile, 0o600);
  } catch {
    // Created a moment later by the destination itself; the mode above applies then.
  }
  // In test mode stdout is reserved for the single "listening" line the SecureVibe harness waits for.
  const console = pino.destination({ fd: config.testMode ? 2 : 1, sync: true });
  return pino.multistream([
    { stream: file, level: config.LOG_LEVEL },
    { stream: console, level: config.LOG_LEVEL },
  ]);
}

export const logger: Logger = pino(
  {
    level: config.LOG_LEVEL,
    timestamp: pino.stdTimeFunctions.isoTime,
    base: { app: config.appName, pid: process.pid },
    messageKey: 'msg',
    formatters: {
      level: (label) => ({ level: label }),
      log: (obj) => redactObject(obj),
    },
    redact: {
      paths: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]'],
      censor: '[redacted]',
    },
  },
  buildDestinations(),
);

export type { Logger };
