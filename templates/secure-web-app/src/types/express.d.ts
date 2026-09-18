/**
 * Request fields added by the template's middleware. Handlers registered with defineRoute receive
 * `req.valid` (validated input), `req.user` (signed-in user or undefined) and `req.session`.
 */
import type { SessionUser } from '../features/auth/repo.ts';
import type { RouteSpec } from '../security/routes.ts';
import type { SessionHandle } from '../security/session.ts';

declare global {
  namespace Express {
    interface Request {
      /** Correlation id for logs (also returned as the X-Request-Id header). */
      id: string;
      user?: SessionUser;
      session: SessionHandle;
      valid: { params: unknown; query: unknown; body: unknown };
      /** Row loaded by the registry's owner check, when the route declares `owner`. */
      entity?: Record<string, unknown>;
      routeSpec?: RouteSpec;
      /** Raw request body as received before validation (used by idempotency hashing). */
      rawBodyHash?: string;
    }
  }
}

export {};
