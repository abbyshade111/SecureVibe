/**
 * Uniform error model. Handlers throw HttpError; the error handler in app.ts turns it into a JSON body
 * `{ error: { code, message, fields? } }` for the API or an error page for pages. Anything that is not an HttpError
 * becomes a generic 500 — clients never see stack traces, SQL or file paths.
 */
export type ErrorCode =
  | 'bad_request'
  | 'invalid_json'
  | 'validation_error'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'method_not_allowed'
  | 'conflict'
  | 'payload_too_large'
  | 'unsupported_media_type'
  | 'rate_limited'
  | 'csrf_rejected'
  | 'reauth_required'
  | 'password_change_required'
  | 'idempotency_key_reuse'
  | 'quota_exceeded'
  | 'service_unavailable'
  | 'internal_error';

export class HttpError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly fields: Record<string, string> | undefined;
  readonly retryAfterSeconds: number | undefined;

  constructor(status: number, code: ErrorCode, message: string, options: { fields?: Record<string, string>; retryAfterSeconds?: number } = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.fields = options.fields;
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

export const errors = {
  badRequest: (message = 'The request could not be understood.') => new HttpError(400, 'bad_request', message),
  validation: (fields: Record<string, string>, message = 'Some of the information you entered is not valid.') =>
    new HttpError(400, 'validation_error', message, { fields }),
  unauthenticated: (message = 'Please sign in to continue.') => new HttpError(401, 'unauthenticated', message),
  forbidden: (message = 'You do not have permission to do that.') => new HttpError(403, 'forbidden', message),
  notFound: (message = 'We could not find that page or record.') => new HttpError(404, 'not_found', message),
  conflict: (message = 'This record was changed by someone else. Please reload and try again.') => new HttpError(409, 'conflict', message),
  quota: (message = 'You have reached the limit for this kind of record.') => new HttpError(409, 'quota_exceeded', message),
  rateLimited: (retryAfterSeconds: number) =>
    new HttpError(429, 'rate_limited', 'Too many attempts. Please wait a moment and try again.', { retryAfterSeconds }),
  csrf: () => new HttpError(403, 'csrf_rejected', 'Your form session expired or the request did not come from this site. Please try again.'),
  reauthRequired: () => new HttpError(403, 'reauth_required', 'Please confirm your password before making this change.'),
  unavailable: (message = 'This feature is currently switched off.') => new HttpError(503, 'service_unavailable', message),
};

/** Plain-language text for HTTP status codes shown on error pages. */
export function statusMessage(status: number): { title: string; explanation: string } {
  switch (status) {
    case 400:
      return { title: 'That request did not look right', explanation: 'Something in the request was missing or not valid. Please go back and try again.' };
    case 401:
      return { title: 'Please sign in', explanation: 'You need to sign in to see this page.' };
    case 403:
      return { title: 'Not allowed', explanation: 'Your account does not have permission to do that.' };
    case 404:
      return { title: 'Page not found', explanation: 'We could not find that page. Check the address or go back to the home page.' };
    case 405:
      return { title: 'Not supported', explanation: 'This page does not accept that kind of request.' };
    case 409:
      return { title: 'Something changed', explanation: 'The record was changed by someone else or the action was already done. Please reload and try again.' };
    case 413:
      return { title: 'Too large', explanation: 'What you sent is larger than this app accepts.' };
    case 429:
      return { title: 'Too many attempts', explanation: 'Please wait a little while before trying again.' };
    case 503:
      return { title: 'Temporarily unavailable', explanation: 'This part of the app is switched off right now. Please try again later.' };
    default:
      return { title: 'Something went wrong', explanation: 'An unexpected problem happened on our side. It has been logged. Please try again in a moment.' };
  }
}
