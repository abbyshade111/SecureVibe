/**
 * The menu, built from the routes the app actually registered (contract "Route registry"): every feature's own
 * list page shows up by itself, including features SecureVibe's generator adds, so a working page is never
 * invisible. Signed-in, parameter-free GET pages only, and the account/administration links stay where they are in
 * the layout.
 *
 * Two ways in, because one was not enough. A record type's own list page is offered automatically, one per record
 * type. Anything else has to ask, by giving its route a `menu` label: a page that spans several record types has no
 * single record type to be listed under, and a page below the top level ("/charts/runs") is not a list page, so
 * neither was reachable from anywhere at all — not the menu, not the home page, which shows the same items.
 *
 * A page that asks is still only shown to somebody the route's own `auth` and `roles` let in. The menu decides
 * where a link appears, never who may follow it.
 */
import { listRoutes } from '../security/routes.ts';
import type { SessionUser } from '../features/auth/repo.ts';

export interface NavItem {
  href: string;
  label: string;
  /** The route's own one-line summary, used as the link's title. */
  summary: string;
}

/** Paths the layout already links, or that are not pages a person browses to. */
const NEVER = new Set(['/', '/account', '/admin', '/login', '/logout', '/register', '/healthz', '/ai']);

function labelFor(path: string, entity: string): string {
  const word = (path.replace(/^\//, '').split('/')[0] || entity).replace(/[-_]+/g, ' ');
  return word.charAt(0).toUpperCase() + word.slice(1);
}

export function navItems(user: SessionUser | null): NavItem[] {
  if (!user) return [];
  const seen = new Set<string>();
  const items: NavItem[] = [];
  for (const route of listRoutes()) {
    if (route.method !== 'GET' || (route.kind ?? 'page') !== 'page') continue;
    if (route.path.includes(':') || NEVER.has(route.path)) continue;
    if (route.auth === 'public') continue;
    // A page restricted to roles is only offered to someone who has one of them.
    if (route.auth.startsWith('role:') && !user.isAdmin && !(route.roles ?? []).some((r) => r === user.role)) continue;
    // A page that asked for a place in the menu gets one under its own label, whatever its depth, and is not
    // counted against the one-link-per-record-type rule below.
    if (route.menu) {
      items.push({ href: route.path, label: route.menu, summary: route.summary ?? '' });
      continue;
    }
    // One automatic link per record type: its top-level list page ("/research", not "/research/new").
    if (!route.entity || route.path.split('/').length !== 2) continue;
    if (seen.has(route.entity)) continue;
    seen.add(route.entity);
    items.push({ href: route.path, label: labelFor(route.path, route.entity), summary: route.summary ?? '' });
  }
  return items.sort((a, b) => a.label.localeCompare(b.label));
}
