/**
 * The menu, built from the routes the app actually registered (contract "Route registry"): every feature's own
 * list page shows up by itself, including features SecureVibe's generator adds, so a working page is never
 * invisible. Only signed-in, parameter-free GET pages that belong to a record type are offered, and the
 * account/administration links stay where they are in the layout.
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
    if (!route.entity || route.path.includes(':') || NEVER.has(route.path)) continue;
    // One link per record type: its top-level list page ("/research", not "/research/new").
    if (route.path.split('/').length !== 2) continue;
    if (route.auth === 'public') continue;
    // A page restricted to roles is only offered to someone who has one of them.
    if (route.auth.startsWith('role:') && !user.isAdmin && !(route.roles ?? []).some((r) => r === user.role)) continue;
    if (seen.has(route.entity)) continue;
    seen.add(route.entity);
    items.push({ href: route.path, label: labelFor(route.path, route.entity), summary: route.summary ?? '' });
  }
  return items.sort((a, b) => a.label.localeCompare(b.label));
}
