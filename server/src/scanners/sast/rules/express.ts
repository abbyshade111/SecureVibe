/**
 * Express-specific rules: cookie flags, helmet/CSP weakening, static dotfiles, trust proxy, routes that
 * bypass the registry, routes without an auth declaration and raw req.body reads.
 */
import ts from 'typescript';
import { calleeName, calleeTail, enclosingFunction, propertyName, resolveObjectLiteral, stringValue, text, type TsFile } from '../engine.js';
import { defineRule, hasAncestor, isFalseLiteral, isTrueLiteral } from './base.js';

const ROUTE_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all', 'head', 'options']);
const ROUTER_NAME = /^(app|router|api|server|r|apiRouter|pageRouter)$/;
const UNSAFE_CSP_SOURCE = /'unsafe-inline'|'unsafe-eval'|^\*$|^https?:$|^data:$/;

/** Is `receiver` an express app or router (by name or by initializer)? */
function isRouterLike(receiver: ts.Expression, file: TsFile): boolean {
  if (!ts.isIdentifier(receiver)) return false;
  if (ROUTER_NAME.test(receiver.text)) return true;
  const init = file.declarations.get(receiver.text);
  return !!init && /^(express\(\)|express\.Router\(|Router\()/.test(text(init, file));
}

function isPathLiteral(arg: ts.Expression | undefined): boolean {
  if (!arg) return false;
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) return arg.text.startsWith('/');
  if (ts.isTemplateExpression(arg)) return arg.head.text.startsWith('/');
  if (ts.isRegularExpressionLiteral(arg)) return true;
  if (ts.isArrayLiteralExpression(arg)) return arg.elements.every((e) => isPathLiteral(e));
  return false;
}

/** Route registrations that bypass defineRoute (shared with ast-checks). */
export function directRouteCalls(file: TsFile): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text;
      if (ROUTE_METHODS.has(method) && node.arguments.length >= 2 && isPathLiteral(node.arguments[0]) && isRouterLike(node.expression.expression, file)) out.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(file.sf);
  return out;
}

function cookieOptionIssues(opts: ts.ObjectLiteralExpression): { httpOnly: boolean; sameSite: boolean } {
  const prop = (name: string): ts.PropertyAssignment | undefined =>
    opts.properties.find((p) => ts.isPropertyAssignment(p) && propertyName(p.name) === name) as ts.PropertyAssignment | undefined;
  const httpOnly = prop('httpOnly');
  const sameSite = prop('sameSite');
  return {
    httpOnly: !httpOnly || !isTrueLiteral(httpOnly.initializer),
    sameSite: !sameSite || isFalseLiteral(sameSite.initializer) || stringValue(sameSite.initializer)?.toLowerCase() === 'none',
  };
}

interface CookieSite {
  node: ts.Node;
  issues: { httpOnly: boolean; sameSite: boolean };
  label: string;
}

function cookieSites(file: TsFile): CookieSite[] {
  const out: CookieSite[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      const tail = calleeTail(node);
      if (name === 'res.cookie') {
        const optsArg = node.arguments[2];
        if (!optsArg) out.push({ node, issues: { httpOnly: true, sameSite: true }, label: 'res.cookie() without options' });
        else {
          const opts = resolveObjectLiteral(optsArg, file);
          if (opts) out.push({ node, issues: cookieOptionIssues(opts), label: 'res.cookie()' });
        }
      } else if ((tail === 'setHeader' || tail === 'append' || tail === 'header' || tail === 'set') && stringValue(node.arguments[0])?.toLowerCase() === 'set-cookie') {
        const value = stringValue(node.arguments[1]);
        // Dynamic header values (e.g. `${attrs()}`) cannot be judged statically.
        if (value !== undefined) out.push({ node, issues: { httpOnly: !/httponly/i.test(value), sameSite: !/samesite=(strict|lax)/i.test(value) }, label: 'Set-Cookie header' });
      } else if (tail === 'session' || tail === 'cookieSession') {
        const opts = resolveObjectLiteral(node.arguments[0], file);
        const cookie = opts?.properties.find((p) => ts.isPropertyAssignment(p) && propertyName(p.name) === 'cookie') as ts.PropertyAssignment | undefined;
        const cookieOpts = cookie ? resolveObjectLiteral(cookie.initializer, file) : undefined;
        if (cookieOpts) out.push({ node, issues: cookieOptionIssues(cookieOpts), label: `${tail}() cookie options` });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file.sf);
  return out;
}

export const cookieMissingHttpOnly = defineRule({
  id: 'sast.cookie-missing-httponly',
  title: 'A cookie can be read by page scripts',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-1004'],
  asvs: ['V3.3.4'],
  exploitability: 'theoretical',
  description: 'A cookie is set without the HttpOnly flag.',
  impact: 'If any script injection succeeds, the cookie (often a session) can be stolen with one line of JavaScript.',
  fix: 'Set httpOnly: true (and use the built-in session cookie instead of custom cookies where possible).',
  appliesTo: ['ts'],
  checkFile(file, report) {
    for (const site of cookieSites(file)) if (site.issues.httpOnly) report(site.node, { evidence: `${site.label} lacks HttpOnly` });
  },
});

export const cookieMissingSameSite = defineRule({
  id: 'sast.cookie-missing-samesite',
  title: 'A cookie is sent on cross-site requests',
  severity: 'low',
  confidence: 'high',
  cwe: ['CWE-1275'],
  asvs: ['V3.3.2'],
  exploitability: 'theoretical',
  description: 'A cookie is set without SameSite=Strict or Lax.',
  impact: 'Other websites can make the browser send the cookie along with forged requests.',
  fix: 'Set sameSite: "strict" (or "lax" when cross-site navigation must keep the user signed in).',
  appliesTo: ['ts'],
  checkFile(file, report) {
    for (const site of cookieSites(file)) if (site.issues.sameSite) report(site.node, { evidence: `${site.label} lacks SameSite` });
  },
});

function directiveIssues(directives: ts.ObjectLiteralExpression, file: TsFile): string[] {
  const issues: string[] = [];
  for (const p of directives.properties) {
    if (!ts.isPropertyAssignment(p)) continue;
    const name = propertyName(p.name) ?? '';
    const isScript = /^(script-?src|scriptSrc|default-?src|defaultSrc)$/i.test(name);
    if (!isScript) continue;
    const init = p.initializer;
    const values: string[] = [];
    if (ts.isArrayLiteralExpression(init)) for (const el of init.elements) if (stringValue(el) !== undefined) values.push(stringValue(el)!);
    else if (stringValue(init) !== undefined) values.push(...(stringValue(init) ?? '').split(/\s+/));
    for (const v of values) if (UNSAFE_CSP_SOURCE.test(v)) issues.push(`${name} allows ${v}`);
    void file;
  }
  return issues;
}

export const helmetDisabledCsp = defineRule({
  id: 'sast.helmet-disabled-csp',
  title: 'The Content Security Policy is disabled or weakened',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-693'],
  asvs: ['V3.4.3', 'V3.4.6'],
  exploitability: 'theoretical',
  description: 'helmet() is configured with contentSecurityPolicy: false, or the policy allows unsafe-inline / unsafe-eval / any source for scripts.',
  impact: 'The browser no longer blocks injected scripts, so any cross-site scripting bug becomes fully exploitable.',
  fix: 'Keep the template’s nonce-based policy from src/security/headers.ts and load scripts with the nonce.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    const name = calleeName(node);
    const tail = calleeTail(node);
    if (name === 'helmet' || name === 'helmet.default') {
      const opts = resolveObjectLiteral(node.arguments[0], file);
      const csp = opts?.properties.find((p) => ts.isPropertyAssignment(p) && propertyName(p.name) === 'contentSecurityPolicy') as ts.PropertyAssignment | undefined;
      if (!csp) return;
      if (isFalseLiteral(csp.initializer)) {
        report(csp, { evidence: 'contentSecurityPolicy: false' });
        return;
      }
      const cspOpts = resolveObjectLiteral(csp.initializer, file);
      const directives = cspOpts?.properties.find((p) => ts.isPropertyAssignment(p) && propertyName(p.name) === 'directives') as ts.PropertyAssignment | undefined;
      const dir = directives ? resolveObjectLiteral(directives.initializer, file) : undefined;
      const issues = dir ? directiveIssues(dir, file) : [];
      if (issues.length > 0) report(csp, { evidence: issues.join('; ') });
    } else if (name === 'helmet.contentSecurityPolicy') {
      const opts = resolveObjectLiteral(node.arguments[0], file);
      const directives = opts?.properties.find((p) => ts.isPropertyAssignment(p) && propertyName(p.name) === 'directives') as ts.PropertyAssignment | undefined;
      const dir = directives ? resolveObjectLiteral(directives.initializer, file) : undefined;
      const issues = dir ? directiveIssues(dir, file) : [];
      if (issues.length > 0) report(node, { evidence: issues.join('; ') });
    } else if (tail === 'setHeader' && stringValue(node.arguments[0])?.toLowerCase() === 'content-security-policy') {
      const value = stringValue(node.arguments[1]) ?? '';
      const script = /script-src([^;]*)/i.exec(value)?.[1] ?? '';
      if (/'unsafe-inline'|'unsafe-eval'|\s\*(\s|$)/.test(script)) report(node, { evidence: `script-src allows ${script.trim()}` });
    } else if (tail === 'removeHeader' && stringValue(node.arguments[0])?.toLowerCase() === 'content-security-policy') {
      report(node, { evidence: 'The Content-Security-Policy header is removed' });
    }
  },
});

export const expressStaticDotfilesAllow = defineRule({
  id: 'sast.express-static-dotfiles-allow',
  title: 'Hidden files can be downloaded from the static folder',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-538'],
  asvs: ['V13.4.1'],
  exploitability: 'requires-network-exposure',
  description: 'Static file serving is configured with dotfiles: "allow".',
  impact: 'Files such as .env or .git inside the public folder become downloadable.',
  fix: 'Use dotfiles: "deny" (the template default).',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    if (ts.isPropertyAssignment(node) && propertyName(node.name) === 'dotfiles' && stringValue(node.initializer) === 'allow') report(node);
  },
});

export const trustProxyTrue = defineRule({
  id: 'sast.trust-proxy-true',
  title: 'The app trusts any proxy header',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-348'],
  asvs: ['V4.1.3', 'V15.3.4'],
  exploitability: 'requires-network-exposure',
  description: 'app.set("trust proxy", true) (or "*") makes the app believe X-Forwarded-For from anyone.',
  impact: 'Clients can fake their IP address, which defeats rate limits and poisons the logs.',
  fix: 'Set TRUST_PROXY_HOPS in .env to the exact number of proxies in front of the app (0 when there is none).',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (tail === 'set' && stringValue(node.arguments[0]) === 'trust proxy') {
      const v = node.arguments[1];
      if (v && (isTrueLiteral(v) || stringValue(v) === '*')) report(node);
    } else if (tail === 'enable' && stringValue(node.arguments[0]) === 'trust proxy') report(node);
  },
});

export const routeOutsideRegistry = defineRule({
  id: 'sast.route-outside-registry',
  title: 'A route bypasses the route registry',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-862'],
  asvs: ['V8.2.1', 'V8.3.1'],
  sbd: ['AC-03'],
  exploitability: 'trivial',
  description: 'A route is registered with app.get()/router.post() etc. instead of defineRoute().',
  impact: 'The route has no declared access rule, no input schema, no CSRF check and no rate limit — it is reachable by anyone.',
  fix: 'Register the route with defineRoute(router, { method, path, auth, schema }, handler).',
  appliesTo: ['ts'],
  checkFile(file, report) {
    for (const call of directRouteCalls(file)) {
      report(call, { evidence: `${text(call.expression, file)}(${text(call.arguments[0]!, file)}) is not registered through defineRoute()` });
    }
  },
});

export const missingAuthzDeclaration = defineRule({
  id: 'sast.missing-authz-declaration',
  title: 'A route does not say who may use it',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-862'],
  asvs: ['V8.2.1'],
  sbd: ['AC-03'],
  exploitability: 'trivial',
  description: 'A defineRoute() call has no auth value (or an invalid one).',
  impact: 'Without an explicit rule the route’s access policy is unknown; the app refuses to start, or worse, someone "fixes" it by making it public.',
  fix: "Add auth: 'user', auth: 'role:<name>' or, only for pages anyone may see, auth: 'public'.",
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node) || calleeTail(node) !== 'defineRoute') return;
    const spec = resolveObjectLiteral(node.arguments[1], file);
    if (!spec) return;
    const auth = spec.properties.find((p) => p.name && propertyName(p.name) === 'auth');
    if (!auth) {
      // A spread of a base spec may carry `auth`.
      const spreads = spec.properties.filter((p) => ts.isSpreadAssignment(p));
      for (const s of spreads) {
        const base = resolveObjectLiteral((s as ts.SpreadAssignment).expression, file);
        if (base?.properties.some((p) => p.name && propertyName(p.name) === 'auth')) return;
      }
      report(node, { evidence: `defineRoute(${text(node.arguments[1]!, file).slice(0, 100)}) has no auth` });
      return;
    }
    if (ts.isPropertyAssignment(auth)) {
      const v = stringValue(auth.initializer);
      if (v !== undefined && !/^(public|user|role:[A-Za-z0-9_-]+)$/.test(v)) report(node, { evidence: `auth: '${v}' is not a valid access rule` });
    }
  },
});

const reported = new WeakMap<ts.SourceFile, Set<string>>();

export const reqBodyUnvalidated = defineRule({
  id: 'sast.req-body-unvalidated',
  title: 'Request data is read without validation',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-20'],
  asvs: ['V2.2.1', 'V15.3.3'],
  sbd: ['AS-05'],
  exploitability: 'requires-auth',
  description: 'A handler reads req.body / req.query / req.params directly instead of the validated req.valid values produced by the route schema.',
  impact: 'The value may be missing, the wrong type, an array instead of a string, or far too long — every later step has to cope with that.',
  fix: 'Declare a strict zod schema in the route (schema: { body, query, params }) and read req.valid.body / req.valid.query / req.valid.params.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (file.isTest || file.isScript || file.relPath.startsWith('src/security/')) return;
    if (!ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node)) return;
    const base = text(node.expression, file);
    const m = /^(req|request)\.(body|query|params)$/.exec(base);
    if (!m) return;
    const part = m[2]!;
    // Inside a defineRoute handler whose spec declares a schema for this part, the read is a convention slip but
    // the data is at least validated; only unvalidated reads are reported.
    const fn = enclosingFunction(node);
    if (fn && hasAncestor(fn, (n) => n === fn.parent) && ts.isCallExpression(fn.parent) && calleeTail(fn.parent) === 'defineRoute') {
      const spec = resolveObjectLiteral(fn.parent.arguments[1], file);
      const schemaProp = spec?.properties.find((p) => p.name && propertyName(p.name) === 'schema') as ts.PropertyAssignment | undefined;
      const schema = schemaProp ? resolveObjectLiteral(schemaProp.initializer, file) : undefined;
      if (schema?.properties.some((p) => p.name && propertyName(p.name) === part)) return;
    }
    const key = `${fn ? fn.pos : -1}:${part}`;
    let set = reported.get(file.sf);
    if (!set) {
      set = new Set();
      reported.set(file.sf, set);
    }
    if (set.has(key)) return;
    set.add(key);
    report(node, { evidence: `${text(node, file)} is read without a schema` });
  },
});

export const expressRules = [
  cookieMissingHttpOnly,
  cookieMissingSameSite,
  helmetDisabledCsp,
  expressStaticDotfilesAllow,
  trustProxyTrue,
  routeOutsideRegistry,
  missingAuthzDeclaration,
  reqBodyUnvalidated,
];
