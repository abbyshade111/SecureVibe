/** Small dotted-path get/set helpers for editing a PartialDesignProfile from question ids like "app.name". */

export function getPath(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let cur: unknown = obj;
  for (const part of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** Returns a new object with `value` set at `path`, cloning only the objects along the path. */
export function setPath<T extends object>(obj: T, path: string, value: unknown): T {
  const parts = path.split('.');
  const clone = (source: unknown, index: number): unknown => {
    const base = source && typeof source === 'object' ? { ...(source as Record<string, unknown>) } : {};
    const key = parts[index];
    if (key === undefined) return base;
    if (index === parts.length - 1) {
      base[key] = value;
      return base;
    }
    base[key] = clone(base[key], index + 1);
    return base;
  };
  return clone(obj, 0) as T;
}
