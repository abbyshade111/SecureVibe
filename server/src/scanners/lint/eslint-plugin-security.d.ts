/**
 * eslint-plugin-security ships no types. Its rule objects do not conform to ESLint's own `Plugin` type
 * (a common situation for older plugins), so this is deliberately untyped at the boundary; `index.ts`
 * only ever reads `.configs.recommended.rules` (a plain rule-severity map) out of it.
 */
declare module 'eslint-plugin-security' {
  const plugin: unknown;
  export default plugin;
}
