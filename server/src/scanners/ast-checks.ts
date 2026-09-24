/**
 * Named semantic checks referenced by the template manifest (`{ type: 'ast', check, file? }`).
 * Each check parses the relevant files with the SAST engine and answers with { passed, detail }.
 */
import ts from 'typescript';
import { calleeName, calleeTail, propertyName, resolveObjectLiteral, stringValue, text, type ScanTree, type TsFile } from './sast/engine.js';
import { buildScanTree, runRulesOnTree } from './sast/index.js';
import { cryptoCreateCipher, dbRawOutsideWrapper, directRouteCalls, isDbHelperCall, sqlStringConcat, weakHashSecurityContext } from './sast/rules/index.js';
import { importsOf } from './sast/rules/base.js';
import type { AstCheckResult, ScanContext } from './types.js';

export const AST_CHECK_NAMES = [
  'helmet-csp-configured',
  'routes-have-schemas',
  'all-routes-registered',
  'db-wrapper-only',
  'node-crypto-only',
  'ai-context-user-scoped',
] as const;
export type AstCheckName = (typeof AST_CHECK_NAMES)[number];

const CRYPTO_LIBRARIES = ['crypto-js', 'md5', 'sha1', 'sha.js', 'js-sha256', 'js-sha1', 'js-md5', 'tweetnacl', 'node-forge', 'bcrypt', 'bcryptjs', 'argon2', 'aes-js', 'elliptic', 'jssha', 'jsrsasign', 'sjcl', 'hash.js'];

function tsFiles(tree: ScanTree, filter: (f: TsFile) => boolean = () => true): TsFile[] {
  return tree.files.filter((f): f is TsFile => f.kind === 'ts' && filter(f));
}

function sourceFiles(f: TsFile): boolean {
  return f.relPath.startsWith('src/') && !f.isTest;
}

function line(node: ts.Node, file: TsFile): number {
  return file.sf.getLineAndCharacterOfPosition(node.getStart(file.sf)).line + 1;
}

function prop(obj: ts.ObjectLiteralExpression | undefined, name: string): ts.PropertyAssignment | undefined {
  return obj?.properties.find((p) => ts.isPropertyAssignment(p) && propertyName(p.name) === name) as ts.PropertyAssignment | undefined;
}

function stringsIn(expr: ts.Expression | undefined, file: TsFile): string[] {
  if (!expr) return [];
  if (ts.isArrayLiteralExpression(expr)) return expr.elements.map((e) => (stringValue(e) !== undefined ? stringValue(e)! : ts.isArrowFunction(e) || ts.isFunctionExpression(e) ? text(e, file) : text(e, file)));
  const s = stringValue(expr);
  return s !== undefined ? s.split(/\s+/) : [text(expr, file)];
}

// ---------------------------------------------------------------------------------------------

function helmetCspConfigured(tree: ScanTree, only?: string): AstCheckResult {
  const candidates = tsFiles(tree, (f) => (only ? f.relPath === only : /^src\/(security\/headers|app)\.[cm]?[jt]s$/.test(f.relPath)));
  if (candidates.length === 0) return { passed: false, detail: `No file to inspect (${only ?? 'src/security/headers.ts or src/app.ts'} not found).` };
  const problems: string[] = [];
  let helmetCalls = 0;
  for (const file of candidates) {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && (calleeName(node) === 'helmet' || calleeName(node) === 'helmet.default')) {
        helmetCalls += 1;
        const opts = resolveObjectLiteral(node.arguments[0], file);
        const csp = prop(opts, 'contentSecurityPolicy');
        if (!csp) {
          problems.push(`${file.relPath}:${line(node, file)}: helmet() is called without a contentSecurityPolicy setting (helmet's default policy has no nonce)`);
          return;
        }
        if (csp.initializer.kind === ts.SyntaxKind.FalseKeyword) {
          problems.push(`${file.relPath}:${line(csp, file)}: contentSecurityPolicy is switched off`);
          return;
        }
        const directives = resolveObjectLiteral(prop(resolveObjectLiteral(csp.initializer, file), 'directives')?.initializer, file);
        if (!directives) {
          problems.push(`${file.relPath}:${line(csp, file)}: contentSecurityPolicy has no explicit directives`);
          return;
        }
        const get = (names: string[]): string[] | undefined => {
          for (const n of names) {
            const p = prop(directives, n);
            if (p) return stringsIn(p.initializer, file);
          }
          return undefined;
        };
        const scriptSrc = get(['script-src', 'scriptSrc']);
        if (!scriptSrc) problems.push('script-src is not set');
        else {
          if (!scriptSrc.some((v) => /nonce/.test(v))) problems.push('script-src has no nonce source');
          if (scriptSrc.some((v) => /'unsafe-inline'|'unsafe-eval'|^\*$/.test(v))) problems.push(`script-src allows ${scriptSrc.filter((v) => /'unsafe-inline'|'unsafe-eval'|^\*$/.test(v)).join(' ')}`);
        }
        for (const [names, want] of [
          [['default-src', 'defaultSrc'], "'self'"],
          [['object-src', 'objectSrc'], "'none'"],
          [['frame-ancestors', 'frameAncestors'], "'none'"],
          [['base-uri', 'baseUri'], "'none'"],
          [['form-action', 'formAction'], "'self'"],
        ] as const) {
          const values = get([...names]);
          if (!values) problems.push(`${names[0]} is not set`);
          else if (!values.includes(want)) problems.push(`${names[0]} should be ${want} (found ${values.join(' ')})`);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
  }
  if (helmetCalls === 0) return { passed: false, detail: `helmet() is not called in ${candidates.map((f) => f.relPath).join(', ')}.` };
  if (problems.length > 0) return { passed: false, detail: problems.join('; ') };
  return { passed: true, detail: `helmet() configures a nonce-based Content Security Policy with default-src 'self', object-src 'none', frame-ancestors 'none', base-uri 'none' and form-action 'self' (${candidates.map((f) => f.relPath).join(', ')}).` };
}

interface RouteSpecInfo {
  file: TsFile;
  node: ts.CallExpression;
  method?: string;
  path?: string;
  hasParamsSchema: boolean;
  hasBodySchema: boolean;
}

function defineRouteCalls(tree: ScanTree, only?: string): RouteSpecInfo[] {
  const out: RouteSpecInfo[] = [];
  for (const file of tsFiles(tree, (f) => (only ? f.relPath === only : sourceFiles(f)))) {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && calleeTail(node) === 'defineRoute') {
        const spec = resolveObjectLiteral(node.arguments[1], file);
        const schema = resolveObjectLiteral(prop(spec, 'schema')?.initializer, file);
        out.push({
          file,
          node,
          method: stringValue(prop(spec, 'method')?.initializer),
          path: stringValue(prop(spec, 'path')?.initializer),
          hasParamsSchema: !!prop(schema, 'params'),
          hasBodySchema: !!prop(schema, 'body'),
        });
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
  }
  return out;
}

function routesHaveSchemas(tree: ScanTree, only?: string): AstCheckResult {
  const routes = defineRouteCalls(tree, only);
  if (routes.length === 0) return { passed: false, detail: 'No defineRoute() calls were found.' };
  // The template's registry validates a route without schema.body against a strict empty object, so such a route
  // accepts no fields at all (only the CSRF token, which is removed first). Only an app without that default must
  // declare a body schema on every state-changing route.
  const registry = tsFiles(tree, (f) => /^src\/security\/routes\.[cm]?[jt]s$/.test(f.relPath))[0];
  const strictEmptyDefault = !!registry && /schema\?\.body\s*\?\?\s*EMPTY\b/.test(registry.text) && /const\s+EMPTY\s*=\s*z\.strictObject\(\s*\{\s*\}\s*\)/.test(registry.text);
  const problems: string[] = [];
  for (const r of routes) {
    const where = `${r.method ?? '?'} ${r.path ?? '?'} (${r.file.relPath}:${line(r.node, r.file)})`;
    if (r.path && /:[A-Za-z0-9_]+/.test(r.path) && !r.hasParamsSchema) problems.push(`${where} has path parameters but no schema.params`);
    if (!strictEmptyDefault && r.method && /^(POST|PUT|PATCH)$/.test(r.method) && !r.hasBodySchema) problems.push(`${where} accepts a body but has no schema.body`);
  }
  if (problems.length > 0) return { passed: false, detail: problems.join('; ') };
  return {
    passed: true,
    detail: strictEmptyDefault
      ? `All ${routes.length} registered routes declare schemas for their path parameters; request bodies are validated by their schema or, when none is declared, must be empty.`
      : `All ${routes.length} registered routes declare schemas for their path parameters and request bodies.`,
  };
}

function allRoutesRegistered(tree: ScanTree, only?: string): AstCheckResult {
  const problems: string[] = [];
  for (const file of tsFiles(tree, (f) => (only ? f.relPath === only : sourceFiles(f)))) {
    for (const call of directRouteCalls(file)) problems.push(`${file.relPath}:${line(call, file)}: ${text(call.expression, file)}() bypasses defineRoute()`);
  }
  const app = tsFiles(tree, (f) => /^src\/app\.[cm]?[jt]s$/.test(f.relPath))[0];
  if (!app) problems.push('src/app.ts was not found');
  else if (!/assertAllRoutesRegistered\s*\(/.test(app.text)) problems.push('src/app.ts does not call assertAllRoutesRegistered()');
  if (problems.length > 0) return { passed: false, detail: problems.join('; ') };
  const count = defineRouteCalls(tree, only).length;
  return { passed: true, detail: `${count} routes are registered through defineRoute() and src/app.ts asserts that no route bypassed the registry.` };
}

function dbWrapperOnly(tree: ScanTree, only?: string): AstCheckResult {
  const subset: ScanTree = { ...tree, files: tree.files.filter((f) => (only ? f.relPath === only : f.kind !== 'ts' || sourceFiles(f))) };
  const findings = runRulesOnTree(subset, [dbRawOutsideWrapper, sqlStringConcat]);
  if (findings.length > 0) {
    return { passed: false, detail: findings.map((f) => `${f.location?.file}:${f.location?.line}: ${f.evidence}`).join('; ') };
  }
  const wrapper = tsFiles(tree, (f) => /^src\/db\/index\.[cm]?[jt]s$/.test(f.relPath))[0];
  if (!wrapper) return { passed: false, detail: 'src/db/index.ts (the database wrapper) was not found.' };
  return { passed: true, detail: 'Every database access goes through src/db/index.ts with bound parameters; no driver calls or string-built SQL outside the wrapper.' };
}

function nodeCryptoOnly(tree: ScanTree, only?: string): AstCheckResult {
  const problems: string[] = [];
  for (const file of tsFiles(tree, (f) => (only ? f.relPath === only : sourceFiles(f)))) {
    for (const imp of importsOf(file, CRYPTO_LIBRARIES)) problems.push(`${file.relPath}:${line(imp.node, file)}: imports "${imp.specifier}" instead of node:crypto`);
  }
  const subset: ScanTree = { ...tree, files: tree.files.filter((f) => (only ? f.relPath === only : f.kind !== 'ts' || sourceFiles(f))) };
  for (const f of runRulesOnTree(subset, [weakHashSecurityContext, cryptoCreateCipher])) problems.push(`${f.location?.file}:${f.location?.line}: ${f.evidence}`);
  if (problems.length > 0) return { passed: false, detail: problems.join('; ') };
  return { passed: true, detail: 'Only node:crypto primitives are used; no MD5/SHA-1 in security contexts and no deprecated ciphers.' };
}

const USER_SCOPE = /\b(user_id|owner_id|userId|ownerId|session_hash|sessionHash)\b/;
const UNSCOPED_TABLES_OK = /\bFROM\s+(settings|ai_settings|ai_models|models|_migrations|feature_flags)\b/i;

function aiContextUserScoped(tree: ScanTree, only?: string): AstCheckResult {
  const files = tsFiles(tree, (f) => (only ? f.relPath === only : f.relPath.startsWith('src/features/ai/') && !f.isTest));
  if (files.length === 0) return { passed: false, detail: `${only ?? 'src/features/ai/'} was not found.` };
  const problems: string[] = [];
  let reads = 0;
  for (const file of files) {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        if (isDbHelperCall(node, file, new Set(['get', 'all']))) {
          reads += 1;
          const sqlNode = node.arguments[0];
          const sql = sqlNode ? (stringValue(sqlNode) ?? text(sqlNode, file)) : '';
          const params = node.arguments[1] ? text(node.arguments[1], file) : '';
          if (/\bSELECT\b/i.test(sql) && !UNSCOPED_TABLES_OK.test(sql) && !USER_SCOPE.test(sql) && !USER_SCOPE.test(params) && !/req\.user/.test(params)) {
            problems.push(`${file.relPath}:${line(node, file)}: query is not limited to the signed-in user: ${sql.replace(/\s+/g, ' ').slice(0, 80)}`);
          }
        } else if (ts.isIdentifier(node.expression)) {
          // Repository functions imported from other features must receive the user id.
          const imp = file.imports.find((i) => i.names.has(node.expression.getText()) && /repo|repository|data|store/i.test(i.specifier));
          if (imp) {
            reads += 1;
            const args = node.arguments.map((a) => text(a, file)).join(', ');
            if (!USER_SCOPE.test(args) && !/req\.user|user\.id|\buser\b/.test(args)) {
              problems.push(`${file.relPath}:${line(node, file)}: ${node.expression.getText()}(${args.slice(0, 60)}) is called without the signed-in user`);
            }
          }
        }
      }
      if (ts.isPropertyAccessExpression(node) && /^(req|request)\.(body|query|params)$/.test(text(node.expression, file))) {
        problems.push(`${file.relPath}:${line(node, file)}: raw ${text(node, file)} is read; use req.valid`);
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
  }
  if (problems.length > 0) return { passed: false, detail: problems.join('; ') };
  return {
    passed: true,
    detail:
      reads === 0
        ? `The AI feature (${files.length} file${files.length === 1 ? '' : 's'}) reads no application data directly.`
        : `All ${reads} data reads in the AI feature are limited to the signed-in user (user_id / owner_id scoping).`,
  };
}

const CHECKS: Record<AstCheckName, (tree: ScanTree, only?: string) => AstCheckResult> = {
  'helmet-csp-configured': helmetCspConfigured,
  'routes-have-schemas': routesHaveSchemas,
  'all-routes-registered': allRoutesRegistered,
  'db-wrapper-only': dbWrapperOnly,
  'node-crypto-only': nodeCryptoOnly,
  'ai-context-user-scoped': aiContextUserScoped,
};

export function isAstCheckName(name: string): name is AstCheckName {
  return (AST_CHECK_NAMES as readonly string[]).includes(name);
}

/**
 * Runs one named check. `file` narrows the check to a single path (relative to the app root) when the
 * manifest specifies one. Unknown names fail explicitly so a typo in the manifest is visible in the report.
 */
export async function runAstCheck(name: string, ctx: ScanContext, file?: string, tree?: ScanTree): Promise<AstCheckResult> {
  if (!isAstCheckName(name)) return { passed: false, detail: `Unknown AST check "${name}". Known checks: ${AST_CHECK_NAMES.join(', ')}.` };
  const scanTree = tree ?? buildScanTree(ctx);
  if (ctx.abort.aborted) return { passed: false, detail: 'The run was canceled before this check completed.', skippedReason: 'the build was canceled' };
  try {
    return CHECKS[name](scanTree, file);
  } catch (err) {
    return { passed: false, detail: `The check could not run: ${err instanceof Error ? err.message : String(err)}` };
  }
}
