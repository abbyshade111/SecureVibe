/**
 * Data transfer object helpers. Raw database rows never leave the app: every entity module exports
 * toPublicDto / toOwnerDto / toAdminDto built with these helpers so each audience sees exactly its fields.
 */
export function pick<T extends object, K extends keyof T>(obj: T, keys: readonly K[]): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const key of keys) {
    if (key in obj) out[key] = obj[key];
  }
  return out;
}

export function omit<T extends object, K extends keyof T>(obj: T, keys: readonly K[]): Omit<T, K> {
  const out = { ...obj } as T;
  for (const key of keys) delete out[key];
  return out as Omit<T, K>;
}

/** Converts a snake_case row into camelCase keys (values untouched). */
export function camelCaseKeys<T extends Record<string, unknown>>(row: T): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    out[k.replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase())] = v;
  }
  return out;
}

/** SQLite stores booleans as 0/1; DTOs expose real booleans. */
export function asBool(value: unknown): boolean {
  return value === 1 || value === true || value === '1';
}
