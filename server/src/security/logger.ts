/**
 * Structured pino logger with redaction of anything secret-shaped, plus the per-request correlation id middleware.
 * The Anthropic key never reaches the logger: it is read from the environment only inside the LLM provider.
 */
import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import { pino, type Logger as PinoLogger } from 'pino';

export type Logger = PinoLogger;

export const REDACT_PATHS = [
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
  '*.password',
  '*.apiKey',
  '*.api_key',
  '*.token',
  '*.secret',
  '*.authorization',
  '*.cookie',
  'password',
  'apiKey',
  'api_key',
  'token',
  'secret',
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'GOOGLE_API_KEY',
  '*.ANTHROPIC_API_KEY',
];

export interface LoggerOptions {
  level?: string;
  /** Tests pass `silent: true`. */
  silent?: boolean;
  destination?: NodeJS.WritableStream;
}

export function createLogger(opts: LoggerOptions = {}): Logger {
  const level = opts.silent ? 'silent' : (opts.level ?? 'info');
  const options = {
    level,
    redact: { paths: REDACT_PATHS, censor: '[redacted]' },
    base: { app: 'securevibe' },
    timestamp: pino.stdTimeFunctions.isoTime,
  };
  return opts.destination ? pino(options, opts.destination) : pino(options);
}

/** Assigns a correlation id to every request (honouring a well-formed incoming X-Correlation-Id). */
export function correlationIdMiddleware(): RequestHandler {
  return (req, res, next) => {
    const incoming = req.header('x-correlation-id');
    const id = incoming && /^[A-Za-z0-9_-]{8,64}$/.test(incoming) ? incoming : randomUUID();
    res.locals['correlationId'] = id;
    res.setHeader('X-Correlation-Id', id);
    next();
  };
}

/** One JSON line per request with method, path, status, duration and correlation id. */
export function requestLogMiddleware(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const started = process.hrtime.bigint();
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      logger.info(
        { method: req.method, path: req.path, status: res.statusCode, ms: Math.round(ms), correlationId: res.locals['correlationId'] },
        'request',
      );
    });
    next();
  };
}
