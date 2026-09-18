/** Helpers for `npm run self-assess` (kept apart from the CLI so they can be tested without running it). */
import type { RoutesExport } from '../scanners/dast/types.js';

export interface ExpressLayer {
  route?: { path: string; methods: Record<string, boolean> };
  handle?: { stack?: ExpressLayer[] };
  matchers?: ((path: string) => unknown)[];
}

const PUBLIC_PATHS = new Set(['/auth/token', '/healthz']);

/**
 * SecureVibe's own routes, read from the Express app, in the shape the runtime probes expect. Routers are only
 * mounted under /api (server/src/app.ts); the SPA catch-all is left out because it is not a concrete path.
 */
export function selfRoutes(app: { router?: { stack?: ExpressLayer[] } }): RoutesExport {
  const routes: RoutesExport['routes'] = [];
  const walk = (stack: ExpressLayer[] | undefined, prefix: string): void => {
    for (const layer of stack ?? []) {
      if (layer.route) {
        const path = `${prefix}${layer.route.path}`;
        if (path.includes('*')) continue;
        for (const method of Object.keys(layer.route.methods)) {
          const upper = method.toUpperCase() as RoutesExport['routes'][number]['method'];
          routes.push({ method: upper, path, auth: PUBLIC_PATHS.has(path) ? 'public' : 'user', kind: prefix === '/api' ? 'api' : 'page', params: [...path.matchAll(/:([A-Za-z0-9_]+)/g)].map((m) => m[1]!) });
        }
      } else if (layer.handle?.stack) {
        walk(layer.handle.stack, layer.matchers?.[0]?.('/api/') ? '/api' : prefix);
      }
    }
  };
  walk(app.router?.stack, '');
  return { routes, roles: ['owner'], adminRole: 'owner', entities: [] };
}

/** Runtime probes written for generated apps' sign-in, sign-up and password pages, which SecureVibe does not have. */
export const NOT_APPLICABLE_TO_SECUREVIBE: Record<string, string> = Object.fromEntries(
  [
    'dast.auth.password-field-type',
    'dast.auth.weak-password-rejected',
    'dast.auth.uniform-unknown-user',
    'dast.auth.reset-uniform-response',
    'dast.auth.admin-mfa-enforced',
    'dast.auth.mfa-rate-limited',
    'dast.rate.registration-limited',
    'dast.rate.reset-limited',
    'dast.input.oversized-body',
    'dast.input.unknown-field',
    'dast.input.type-confusion',
    'dast.input.duplicate-param',
    'dast.errors.method-not-allowed',
    'dast.log.login-failure-logged',
    'dast.log.validation-rejected-logged',
    'dast.log.authz-denial-logged',
    'dast.redirect.open-redirect-blocked',
  ]
    .map((id): [string, string] => [id, 'SecureVibe has no sign-in, sign-up or password pages (access uses the startup link) and no generated-app security event log, so this generated-app check does not apply.'])
    .concat([
      ['dast.authz.non-owner-denied', 'SecureVibe has a single owner and no per-user records, so there is no second account to test ownership with.'],
      ['dast.authz.unregistered-route', 'routes.manifest.json belongs to generated apps. The route list used for this scan is read from SecureVibe\'s running Express app, so it cannot miss a route.'],
    ]),
);
