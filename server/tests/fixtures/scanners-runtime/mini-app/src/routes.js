/**
 * The route registry of the fixture app: the single list that the router, the 405 handler and the test-mode
 * `/__securevibe/routes` export all read, exactly as the real template does (CONTRACTS §1.4).
 */

export const ROUTES = [
  { method: 'GET', path: '/', auth: 'public', kind: 'page', summary: 'Home' },
  { method: 'GET', path: '/login', auth: 'public', kind: 'page', summary: 'Sign-in form' },
  { method: 'POST', path: '/login', auth: 'public', kind: 'page', csrf: true, rateLimit: 'login', summary: 'Sign in' },
  { method: 'GET', path: '/login/mfa', auth: 'public', kind: 'page', summary: 'One-time code form' },
  { method: 'POST', path: '/login/mfa', auth: 'public', kind: 'page', csrf: true, rateLimit: 'mfa', summary: 'Check the one-time code' },
  { method: 'GET', path: '/forgot-password', auth: 'public', kind: 'page', summary: 'Ask for a password reset' },
  { method: 'POST', path: '/forgot-password', auth: 'public', kind: 'page', csrf: true, rateLimit: 'reset', summary: 'Send a password reset' },
  { method: 'POST', path: '/logout', auth: 'user', kind: 'page', csrf: true, summary: 'Sign out' },
  { method: 'GET', path: '/account', auth: 'user', kind: 'page', summary: 'Your account' },
  { method: 'GET', path: '/notes', auth: 'user', kind: 'page', entity: 'note', summary: 'Your notes' },
  {
    method: 'GET',
    path: '/notes/:id',
    auth: 'user',
    kind: 'page',
    entity: 'note',
    owner: { entity: 'note', param: 'id', ownerField: 'owner_id' },
    summary: 'One note',
  },
  {
    method: 'POST',
    path: '/notes/:id/delete',
    auth: 'user',
    kind: 'page',
    csrf: true,
    entity: 'note',
    owner: { entity: 'note', param: 'id', ownerField: 'owner_id' },
    summary: 'Delete a note',
  },
  { method: 'GET', path: '/admin', auth: 'role:admin', kind: 'page', summary: 'Administration' },
  { method: 'GET', path: '/api/notes', auth: 'user', kind: 'api', entity: 'note', summary: 'List notes' },
  { method: 'POST', path: '/api/notes', auth: 'user', kind: 'api', csrf: true, entity: 'note', idempotent: true, summary: 'Create a note' },
  {
    method: 'GET',
    path: '/api/notes/:id',
    auth: 'user',
    kind: 'api',
    entity: 'note',
    owner: { entity: 'note', param: 'id', ownerField: 'owner_id' },
    summary: 'Read one note',
  },
  { method: 'GET', path: '/healthz', auth: 'public', kind: 'api', summary: 'Liveness' },
  { method: 'GET', path: '/readyz', auth: 'public', kind: 'api', summary: 'Readiness' },
];

export const ROLES = ['admin', 'staff', 'member'];
export const ADMIN_ROLE = 'admin';

function segmentRegex(segment) {
  return segment.startsWith(':') ? '[^/]+' : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function pathToRegex(path) {
  return new RegExp(`^${path.split('/').map(segmentRegex).join('/')}$`);
}

const MATCHERS = ROUTES.map((route) => ({ route, re: pathToRegex(route.path) }));

/** Methods registered for a live path, used to answer 405 with an Allow header instead of 404. */
export function methodsForPath(pathname) {
  const methods = MATCHERS.filter((m) => m.re.test(pathname)).map((m) => m.route.method);
  if (methods.includes('GET') && !methods.includes('HEAD')) methods.push('HEAD');
  return [...new Set(methods)];
}

export function findRoute(method, pathname) {
  return MATCHERS.find((m) => m.route.method === method && m.re.test(pathname))?.route;
}
