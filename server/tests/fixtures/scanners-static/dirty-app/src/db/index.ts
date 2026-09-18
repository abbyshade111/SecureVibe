// Fixture stand-in for the real db wrapper; only the shape (named helpers) matters for the scanner.
export function get(_sql: string, _params?: unknown[]): unknown {
  return undefined;
}
export function all(_sql: string, _params?: unknown[]): unknown[] {
  return [];
}
export function run(_sql: string, _params?: unknown[]): void {}
export function withTransaction<T>(fn: () => T): T {
  return fn();
}
