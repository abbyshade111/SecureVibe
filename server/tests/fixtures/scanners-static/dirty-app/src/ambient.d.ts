// Ambient declarations so `tsc` can type-check this fixture even though these packages are not
// installed (they only need to exist as source text for the SAST scanner, which parses syntax, not
// types). Declaration files are never scanned by the SAST engine (`scriptKindFor` skips `.d.ts`).
declare module 'openai' {
  export const Configuration: unknown;
}
declare module 'js-yaml' {
  export function load(input: string, options?: unknown): unknown;
  export function loadAll(input: string, options?: unknown): unknown;
}
