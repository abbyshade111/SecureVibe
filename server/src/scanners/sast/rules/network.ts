/**
 * Network rules: TLS verification, CORS, outbound HTTP outside the http-client, open redirects and
 * mail headers built from request data.
 */
import ts from 'typescript';
import { calleeName, calleeTail, isStringLike, isTainted, propertyName, RAW_REQ_TAINT, REQ_TAINT, resolveObjectLiteral, stringValue, text, unwrapAwait, type TsFile } from '../engine.js';
import { defineRule, importsOf, isFalseLiteral, isTrueLiteral, moduleFunctionOfCall, SANITIZER_CALL } from './base.js';

/** The outbound client itself, and the assistant's client, which applies the same host allow-list before calling fetch. */
const HTTP_CLIENT_FILE = /(^|\/)(http-client\.[cm]?[jt]sx?|features\/ai\/client\.[cm]?[jt]sx?)$/;
const HTTP_LIBRARIES = ['axios', 'got', 'node-fetch', 'undici', 'superagent', 'request', 'needle', 'phin', 'ky', 'cross-fetch', 'bent'];
const MAIL_HEADERS = new Set(['to', 'from', 'cc', 'bcc', 'replyTo', 'reply_to', 'subject', 'headers', 'sender']);

export const tlsRejectUnauthorizedFalse = defineRule({
  id: 'sast.tls-reject-unauthorized-false',
  title: 'Certificate checks are switched off',
  severity: 'critical',
  confidence: 'high',
  cwe: ['CWE-295'],
  asvs: ['V12.3.2'],
  exploitability: 'requires-network-exposure',
  description: 'The code sets rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0, which accepts any certificate.',
  impact: 'Anyone on the network path can impersonate the service the app talks to and read or change the traffic.',
  fix: 'Remove the setting. If a service uses a private certificate authority, add its certificate with the `ca` option or NODE_EXTRA_CA_CERTS.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (ts.isPropertyAssignment(node) && propertyName(node.name) === 'rejectUnauthorized' && isFalseLiteral(node.initializer)) report(node);
    else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = text(node.left, file);
      if (/^process\.env(\.NODE_TLS_REJECT_UNAUTHORIZED|\[['"]NODE_TLS_REJECT_UNAUTHORIZED['"]\])$/.test(left) && stringValue(node.right) === '0') report(node);
    }
  },
});

interface CorsSummary {
  node: ts.Node;
  origin: 'wildcard' | 'reflected' | 'specific';
  credentials: boolean;
}

function corsCalls(file: TsFile): { summaries: CorsSummary[]; credentialsHeaderSet: boolean } {
  const summaries: CorsSummary[] = [];
  let credentialsHeaderSet = false;
  const originKind = (value: ts.Expression | undefined): CorsSummary['origin'] => {
    if (!value) return 'wildcard';
    if (stringValue(value) === '*' || isTrueLiteral(value)) return 'wildcard';
    if (isTainted(value, file, REQ_TAINT) || /origin/i.test(text(value, file))) return 'reflected';
    return 'specific';
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      if (tail === 'cors' && (ts.isIdentifier(node.expression) || /cors/i.test(calleeName(node) ?? ''))) {
        const opts = resolveObjectLiteral(node.arguments[0], file);
        if (!node.arguments[0]) summaries.push({ node, origin: 'wildcard', credentials: false });
        else if (opts) {
          const origin = opts.properties.find((p) => p.name && propertyName(p.name) === 'origin') as ts.PropertyAssignment | undefined;
          const cred = opts.properties.find((p) => p.name && propertyName(p.name) === 'credentials') as ts.PropertyAssignment | undefined;
          summaries.push({ node, origin: originKind(origin?.initializer), credentials: !!cred && isTrueLiteral(cred.initializer) });
        }
      } else if ((tail === 'setHeader' || tail === 'header' || tail === 'set' || tail === 'append') && node.arguments.length >= 2) {
        const header = stringValue(node.arguments[0])?.toLowerCase();
        const value = node.arguments[1]!;
        if (header === 'access-control-allow-origin') {
          const v = stringValue(value);
          const kind: CorsSummary['origin'] = v === '*' ? 'wildcard' : v !== undefined ? 'specific' : isTainted(value, file, REQ_TAINT) || /origin/i.test(text(value, file)) ? 'reflected' : 'specific';
          summaries.push({ node, origin: kind, credentials: false });
        } else if (header === 'access-control-allow-credentials' && (stringValue(value) === 'true' || isTrueLiteral(value))) {
          credentialsHeaderSet = true;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file.sf);
  return { summaries, credentialsHeaderSet };
}

export const corsWildcardCredentials = defineRule({
  id: 'sast.cors-wildcard-credentials',
  title: 'Cross-origin requests with credentials are allowed from any site',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-942'],
  asvs: ['V3.4.2'],
  exploitability: 'requires-network-exposure',
  description: 'CORS allows any origin (or reflects the request origin) while also allowing credentials.',
  impact: 'Any website a signed-in user visits can call the app as that user and read the responses.',
  fix: 'Remove CORS entirely (the app serves its own pages) or allow-list exact origins and never combine "*" with credentials.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    const { summaries, credentialsHeaderSet } = corsCalls(file);
    for (const s of summaries) {
      if (s.origin !== 'specific' && (s.credentials || credentialsHeaderSet)) report(s.node, { evidence: `${s.origin === 'wildcard' ? 'Any origin' : 'The request origin'} is allowed together with credentials` });
    }
  },
});

export const corsAnyOrigin = defineRule({
  id: 'sast.cors-any-origin',
  title: 'Cross-origin requests are allowed from any site',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-942'],
  asvs: ['V3.4.2'],
  exploitability: 'requires-network-exposure',
  description: 'CORS allows any origin ("*") or reflects whatever origin the request carries.',
  impact: 'Other websites can read responses from the app’s API in the visitor’s browser.',
  fix: 'Remove CORS (the app does not need it) or allow-list the exact origins that may call the API.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    const { summaries, credentialsHeaderSet } = corsCalls(file);
    for (const s of summaries) {
      if (s.origin !== 'specific' && !s.credentials && !credentialsHeaderSet) report(s.node, { evidence: s.origin === 'wildcard' ? 'Any origin is allowed' : 'The request origin is reflected' });
    }
  },
});

export const fetchOutsideHttpClient = defineRule({
  id: 'sast.fetch-outside-http-client',
  title: 'The app calls other servers without the outbound client',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-918'],
  asvs: ['V1.3.6', 'V13.2.4'],
  sbd: ['AS-01'],
  exploitability: 'requires-auth',
  description: 'fetch() is called directly instead of outboundFetch() from src/lib/http-client.ts.',
  impact: 'The call skips the host allow-list, timeout, size cap, redirect handling and circuit breaker, so a bad URL can reach internal services or hang the app.',
  fix: 'Use outboundFetch(url, init) and add the host to OUTBOUND_ALLOWED_HOSTS.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    if (file.isTest || file.isPublic || HTTP_CLIENT_FILE.test(file.relPath)) return;
    const name = calleeName(node);
    if (name === 'fetch' || name === 'globalThis.fetch') report(node);
  },
});

export const httpRequestOutsideClient = defineRule({
  id: 'sast.http-request-outside-client',
  title: 'An HTTP library is used instead of the outbound client',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-918'],
  asvs: ['V1.3.6', 'V13.2.4'],
  sbd: ['AS-01'],
  exploitability: 'requires-auth',
  description: 'The code uses http.request/https.get or a third-party HTTP library instead of outboundFetch().',
  impact: 'Requests bypass the host allow-list, timeouts and size caps that protect the app from abuse.',
  fix: 'Replace the call with outboundFetch() from src/lib/http-client.ts.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    if (file.isTest || HTTP_CLIENT_FILE.test(file.relPath)) return;
    for (const imp of importsOf(file, HTTP_LIBRARIES)) report(imp.node, { evidence: `${file.relPath} imports "${imp.specifier}"` });
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const fn = moduleFunctionOfCall(node, file, ['http', 'https', 'node:http', 'node:https']);
        if (fn === 'request' || fn === 'get') report(node, { evidence: `${text(node.expression, file)}() bypasses the outbound client` });
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
  },
});

function redirectTargetUnsafe(expr: ts.Expression, file: TsFile, depth = 0): boolean {
  if (depth > 3) return false;
  const e = unwrapAwait(expr);
  if (isStringLike(e)) return false;
  if (ts.isTemplateExpression(e)) {
    const head = e.head.text;
    if (/^\/[^/]/.test(head)) return false; // "/login?next=..." always stays on this site
    return e.templateSpans.some((s) => redirectTargetUnsafe(s.expression, file, depth + 1));
  }
  if (ts.isConditionalExpression(e)) return redirectTargetUnsafe(e.whenTrue, file, depth + 1) || redirectTargetUnsafe(e.whenFalse, file, depth + 1);
  if (ts.isBinaryExpression(e)) {
    const op = e.operatorToken.kind;
    if (op === ts.SyntaxKind.QuestionQuestionToken || op === ts.SyntaxKind.BarBarToken) {
      return redirectTargetUnsafe(e.left, file, depth + 1) || redirectTargetUnsafe(e.right, file, depth + 1);
    }
    if (op === ts.SyntaxKind.PlusToken) {
      const head = isStringLike(e.left) ? e.left.text : undefined;
      if (head !== undefined && /^\/[^/]/.test(head)) return false;
      return redirectTargetUnsafe(e.left, file, depth + 1) || redirectTargetUnsafe(e.right, file, depth + 1);
    }
    return false;
  }
  if (ts.isCallExpression(e)) {
    const tail = calleeTail(e) ?? '';
    if (SANITIZER_CALL.test(tail)) return false;
    return e.arguments.some((a) => isTainted(a, file, REQ_TAINT));
  }
  if (ts.isIdentifier(e)) {
    const init = file.declarations.get(e.text);
    return init ? redirectTargetUnsafe(init, file, depth + 1) : false;
  }
  return isTainted(e, file, REQ_TAINT);
}

export const openRedirect = defineRule({
  id: 'sast.open-redirect',
  title: 'A redirect goes wherever the request says',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-601'],
  asvs: ['V3.7.2'],
  exploitability: 'trivial',
  description: 'res.redirect() is called with a target taken from the request without checking it is a local path.',
  impact: 'A link that looks like it points to your app can send people to a look-alike site that steals their password.',
  fix: 'Use safeRedirect(res, target) from src/security/redirect.ts, which only allows local paths.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node) || calleeName(node) !== 'res.redirect') return;
    const args = node.arguments;
    const target = args.length >= 2 && ts.isNumericLiteral(args[0]!) ? args[1] : args[0];
    if (!target) return;
    if (redirectTargetUnsafe(target, file)) report(node, { evidence: `res.redirect(${text(target, file).slice(0, 100)})` });
  },
});

export const mailerHeaderUserInput = defineRule({
  id: 'sast.mailer-header-user-input',
  title: 'Request data is placed in an email header',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-93'],
  asvs: ['V1.3.11'],
  exploitability: 'requires-auth',
  description: 'Unvalidated request data is used as the recipient, sender, subject or another header of an outgoing email.',
  impact: 'Line breaks in the value add extra recipients or headers, turning the app into a spam relay (mail header injection).',
  fix: 'Only use validated values (req.valid) and send through src/lib/mailer.ts, which strips line breaks from headers.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (!tail || !/^(sendMail|sendEmail|send|mail|sendMessage)$/.test(tail)) return;
    const receiver = ts.isPropertyAccessExpression(node.expression) ? text(node.expression.expression, file) : '';
    if (ts.isPropertyAccessExpression(node.expression) && !/mail|transport|smtp|ses|sendgrid|postmark|resend|mailgun/i.test(receiver)) return;
    const opts = resolveObjectLiteral(node.arguments[0], file);
    if (!opts) return;
    const tainted = opts.properties.filter((p) => {
      if (!ts.isPropertyAssignment(p) || !p.name) return false;
      const name = propertyName(p.name);
      return !!name && MAIL_HEADERS.has(name) && isTainted(p.initializer, file, RAW_REQ_TAINT);
    });
    if (tainted.length > 0) report(node, { evidence: `Email header(s) ${tainted.map((p) => propertyName((p as ts.PropertyAssignment).name)).join(', ')} come from raw request data` });
  },
});

export const networkRules = [tlsRejectUnauthorizedFalse, corsWildcardCredentials, corsAnyOrigin, fetchOutsideHttpClient, httpRequestOutsideClient, openRedirect, mailerHeaderUserInput];
