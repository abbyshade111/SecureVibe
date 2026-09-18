/**
 * Uniform error model (shared/src/api.ts ApiErrorSchema): every error the API returns is
 * { error: { code, message, details?, correlationId } } with a safe, user-readable message and never a stack trace.
 */
import type { ErrorRequestHandler, RequestHandler } from 'express';
import { z } from 'zod';
import type { ApiError } from '@shared/api.js';
import type { Logger } from './logger.js';

export type ApiErrorCode =
  | 'validation_error'
  | 'not_found'
  | 'llm_unavailable'
  | 'forbidden'
  | 'unauthorized'
  | 'rate_limited'
  | 'internal'
  | 'conflict'
  | 'payload_too_large'
  | 'timeout';

const STATUS_BY_CODE: Record<ApiErrorCode, number> = {
  validation_error: 400,
  not_found: 404,
  llm_unavailable: 503,
  forbidden: 403,
  unauthorized: 401,
  rate_limited: 429,
  internal: 500,
  conflict: 409,
  payload_too_large: 413,
  timeout: 503,
};

export class HttpError extends Error {
  readonly status: number;
  /** Stable security-event name for the log (e.g. "csrf.rejected"); derived from the status when absent. */
  event?: string;

  constructor(
    readonly code: ApiErrorCode,
    message: string,
    readonly details?: unknown,
    status?: number,
  ) {
    super(message);
    this.name = 'HttpError';
    this.status = status ?? STATUS_BY_CODE[code];
  }
}

/** Tags an error with the security-event name it is logged under. */
export function withEvent(err: HttpError, event: string): HttpError {
  err.event = event;
  return err;
}

export function notFound(message = 'That was not found.'): HttpError {
  return new HttpError('not_found', message);
}

export function forbidden(message: string): HttpError {
  return new HttpError('forbidden', message);
}

export function validationError(message: string, details?: unknown): HttpError {
  return new HttpError('validation_error', message, details);
}

export function conflict(message: string): HttpError {
  return new HttpError('conflict', message);
}

export function llmUnavailable(message = 'AI is not configured. Add an Anthropic API key and restart SecureVibe to use this.'): HttpError {
  return new HttpError('llm_unavailable', message);
}

export function toApiError(err: unknown, correlationId?: string): { status: number; body: ApiError } {
  if (err instanceof HttpError) {
    return {
      status: err.status,
      body: { error: { code: err.code, message: err.message, ...(err.details !== undefined ? { details: err.details } : {}), ...(correlationId ? { correlationId } : {}) } },
    };
  }
  if (err instanceof z.ZodError) {
    return {
      status: 400,
      body: {
        error: {
          code: 'validation_error',
          message: 'Some of the information sent was not valid.',
          details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
          ...(correlationId ? { correlationId } : {}),
        },
      },
    };
  }
  const e = err as { type?: string; status?: number; message?: string; code?: string; name?: string };
  // A missing or malformed project id (the store refuses anything that is not a well-formed id) and a path that
  // would leave the workspace are both "not found" to the caller. Matched by name to keep this module store-free.
  if (e && (e.name === 'ProjectNotFoundError' || e.name === 'PathConfinementError')) {
    return { status: 404, body: { error: { code: 'not_found', message: 'That project could not be found.', ...(correlationId ? { correlationId } : {}) } } };
  }
  // body-parser errors
  if (e && e.type === 'entity.too.large') {
    return { status: 413, body: { error: { code: 'payload_too_large', message: 'The request was too large (the limit is 1 MB).', ...(correlationId ? { correlationId } : {}) } } };
  }
  if (e && e.type === 'entity.parse.failed') {
    return { status: 400, body: { error: { code: 'validation_error', message: 'The request body was not valid JSON.', ...(correlationId ? { correlationId } : {}) } } };
  }
  if (e && typeof e.status === 'number' && e.status >= 400 && e.status < 500) {
    return { status: e.status, body: { error: { code: 'validation_error', message: 'The request could not be processed.', ...(correlationId ? { correlationId } : {}) } } };
  }
  return {
    status: 500,
    body: {
      error: {
        code: 'internal',
        message: 'Something went wrong inside SecureVibe. The details are in the server log.',
        ...(correlationId ? { correlationId } : {}),
      },
    },
  };
}

/** A stable name for a refused request, so the log can be searched and counted. */
export function rejectionEvent(status: number, code: string): string {
  if (status === 401) return 'auth.denied';
  if (status === 403) return 'access.denied';
  if (status === 429) return 'rate_limit.exceeded';
  if (status === 404) return 'request.not_found';
  if (status === 409) return 'request.conflict';
  return 'validation.rejected';
}

export function errorHandler(logger: Logger): ErrorRequestHandler {
  return (err, req, res, _next) => {
    const correlationId = res.locals['correlationId'] as string | undefined;
    const { status, body } = toApiError(err, correlationId);
    if (status >= 500) logger.error({ err, correlationId, path: req.path }, 'request failed');
    else {
      // Refusals are security events (ASVS V16.3): kept at the default log level with a stable event name.
      // A missing page is not, so it stays at debug.
      const event = (err instanceof HttpError && err.event) || rejectionEvent(status, body.error.code);
      const entry = { event, code: body.error.code, status, correlationId, method: req.method, path: req.path, ip: req.ip };
      if (event === 'request.not_found') logger.debug(entry, 'request rejected');
      else if (status === 401 || status === 403 || status === 429) logger.warn(entry, 'request refused');
      else logger.info(entry, 'request rejected');
    }
    if (res.headersSent) {
      res.end();
      return;
    }
    res.status(status).json(body);
  };
}

export const apiNotFoundHandler: RequestHandler = (_req, res) => {
  res.status(404).json({ error: { code: 'not_found', message: 'That API route does not exist.' } } satisfies ApiError);
};
