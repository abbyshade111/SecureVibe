/**
 * The bounds a list query is held to, kept apart from `db/index.ts` on purpose: that module opens the database
 * and reads the configuration at load time, and the page cap needs neither. Keeping them separate is what lets
 * the query builder be tested as a plain function, with no database, no configuration and no app to start.
 */

/** No list may return more than this many rows in one response, whatever anything asks for. */
export const MAX_PAGE_SIZE = 200;

/** The page size used when nothing sensible was asked for. */
export const DEFAULT_PAGE_SIZE = 50;

/** Clamp a page size so list queries always carry a bounded LIMIT. */
export function clampLimit(requested: number | undefined, fallback = DEFAULT_PAGE_SIZE, max = MAX_PAGE_SIZE): number {
  if (requested === undefined || !Number.isFinite(requested)) return fallback;
  return Math.max(1, Math.min(max, Math.floor(requested)));
}
