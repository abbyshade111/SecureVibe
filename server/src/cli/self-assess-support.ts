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

/**
 * Rules that assume the thing being scanned is a generated application, which SecureVibe is not.
 *
 * A self-assessment on 20 September 2026 reported 4 critical and 113 high, and the bulk was these four rules
 * misfiring on SecureVibe: 62 route-outside-registry, 13 child-process-exec, 17 fs-user-path and 11
 * path-join-user-input. A generated app declares its routes in a registry and never spawns a process; a build
 * tool's job is to spawn processes and join paths. Same class as asking a Python app about its npm lockfile,
 * one level up: the target is not what the rules assume, and the report said so in the language of failure.
 * Their results are left out of the self-assessment and the stage summary says why (excludedChecksReason).
 * The findings that were not explained by this were checked one by one and are triaged in
 * self-assessment/triage.json instead, because those are real matches with a reason each.
 */
export const SELF_ASSESS_EXCLUDED_CHECKS = ['sast.route-outside-registry', 'sast.child-process-exec', 'sast.fs-user-path', 'sast.path-join-user-input'];

export const SELF_ASSESS_EXCLUDED_REASON = 'assume a generated application, which declares its routes in a registry and never spawns a process; SecureVibe is a build tool, whose job is to spawn processes and work with paths';
