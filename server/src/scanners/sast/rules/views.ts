/**
 * Rules for EJS templates (and the few TypeScript counterparts): unescaped output, inline scripts and
 * event handlers, secret questions, sensitive data in GET forms and security TODOs left in views.
 */
import ts from 'typescript';
import { NONCE_ATTR } from '../ejs.js';
import { calleeTail, propertyName, resolveObjectLiteral, stringValue, text, type EjsFile, type TsFile } from '../engine.js';
import { AI_NAME, defineRule, SECRET_QUESTION, SENSITIVE_PARAM } from './base.js';

const ALLOWED_UNESCAPED = /^(nonce|csrfToken|csrfField)$/;
const ALLOWED_UNESCAPED_CALL = /^(include|safeHtml|partial)\s*\(/;
const NON_SCRIPT_TYPE = /\btype\s*=\s*["']?(application\/(ld\+)?json|text\/template|text\/x-template|text\/html|application\/x-template)/i;
const TODO = /\b(TODO|FIXME|XXX|HACK)\b/;
export const SECURITY_WORDS = /(auth|secur|csrf|xss|permission|authori[sz]|validat|sanitiz|escap|encrypt|password|token|secret|injection|owner|role|session|login|sign[- ]?in)/i;

function lineSnippet(file: EjsFile, offset: number): string {
  const line = file.doc.lineOf(offset);
  return (file.text.split('\n')[line - 1] ?? '').trim();
}

export const ejsUnescapedOutput = defineRule({
  id: 'sast.ejs-unescaped-output',
  title: 'A template outputs unescaped HTML',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-79'],
  asvs: ['V1.2.1', 'V1.1.2'],
  exploitability: 'requires-auth',
  description: 'A view uses `<%- ... %>`, which inserts a value into the page without escaping it, for something other than the nonce, the CSRF token, an include or safeHtml().',
  impact: 'If the value contains text a user typed, that text can run as script in other people’s browsers (cross-site scripting).',
  fix: 'Use `<%= ... %>` for data. Only the layout may output app-rendered HTML through safeHtml().',
  appliesTo: ['ejs'],
  checkEjs(file, report) {
    for (const tag of file.doc.tags) {
      if (tag.kind !== 'unescaped') continue;
      const code = tag.code;
      if (ALLOWED_UNESCAPED.test(code) || ALLOWED_UNESCAPED_CALL.test(code)) continue;
      if (file.isLayout && code === 'body') continue;
      if (AI_NAME.test(code)) continue; // sast.ai-output-rendered-unescaped reports these
      report({ line: tag.line, column: tag.column }, { snippet: file.text.slice(tag.start, tag.end), evidence: `Unescaped output <%- ${code} %> at line ${tag.line}` });
    }
  },
});

export const inlineScriptInView = defineRule({
  id: 'sast.inline-script-in-view',
  title: 'A script tag has no nonce',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-79'],
  asvs: ['V3.4.3'],
  exploitability: 'theoretical',
  description: 'A `<script>` tag in a view does not carry nonce="<%= nonce %>", so the Content Security Policy will block it — or someone will be tempted to weaken the policy to make it run.',
  impact: 'Either the feature silently breaks, or the policy that stops injected scripts gets relaxed.',
  fix: 'Move the code to public/js/features/<name>.js and load it with <script nonce="<%= nonce %>" src="/js/features/<name>.js"></script>.',
  appliesTo: ['ejs'],
  checkEjs(file, report) {
    const re = /<script\b([^>]*)>/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(file.doc.masked)) !== null) {
      const attrs = m[1] ?? '';
      if (NONCE_ATTR.test(attrs) || NON_SCRIPT_TYPE.test(attrs)) continue;
      const line = file.doc.lineOf(m.index);
      report({ line, column: file.doc.columnOf(m.index) }, { snippet: lineSnippet(file, m.index), evidence: `<script> without a nonce attribute at line ${line}` });
    }
  },
});

export const inlineEventHandler = defineRule({
  id: 'sast.inline-event-handler',
  title: 'An HTML element has an inline event handler',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-79'],
  asvs: ['V3.4.3'],
  exploitability: 'theoretical',
  description: 'A view uses an attribute like onclick="..." or href="javascript:...". The Content Security Policy blocks inline handlers.',
  impact: 'The handler will not run under the policy, and inline handlers are a classic place where injected data becomes script.',
  fix: 'Attach the behavior from a script in public/js/features/ with addEventListener().',
  appliesTo: ['ejs'],
  checkEjs(file, report) {
    const re = /<[a-zA-Z][^>]*?\s(on[a-z]+)\s*=|\bhref\s*=\s*["']\s*javascript:/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(file.doc.masked)) !== null) {
      const line = file.doc.lineOf(m.index);
      const what = m[1] ? `${m[1]}=` : 'href="javascript:"';
      report({ line, column: file.doc.columnOf(m.index) }, { snippet: lineSnippet(file, m.index), evidence: `Inline ${what} at line ${line}` });
    }
  },
});

export const secretQuestionField = defineRule({
  id: 'sast.secret-question-field',
  title: 'The app uses a security question or password hint',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-640'],
  asvs: ['V6.4.2'],
  exploitability: 'requires-network-exposure',
  description: 'A form field or data field is named like a security question, secret answer or password hint.',
  impact: 'Answers to such questions are easy to guess or look up, so they weaken account recovery.',
  fix: 'Remove the field. Use the built-in password reset by email and one-time codes instead.',
  appliesTo: ['ejs', 'ts'],
  checkEjs(file, report) {
    const re = /<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']*)["']/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(file.doc.masked)) !== null) {
      if (!SECRET_QUESTION.test(m[1] ?? '')) continue;
      const line = file.doc.lineOf(m.index);
      report({ line, column: file.doc.columnOf(m.index) }, { snippet: lineSnippet(file, m.index), evidence: `Form field "${m[1]}" at line ${line}` });
    }
  },
  visit(node, _file, report) {
    if (ts.isPropertyAssignment(node) || ts.isPropertySignature(node) || ts.isShorthandPropertyAssignment(node)) {
      const name = propertyName(node.name);
      if (name && SECRET_QUESTION.test(name)) report(node, { confidence: 'medium', evidence: `Field "${name}"` });
    }
  },
});

function schemaPropertyNames(schema: ts.Expression | undefined, file: TsFile): string[] {
  if (!schema) return [];
  let call: ts.Expression = schema;
  if (ts.isIdentifier(call)) {
    const init = file.declarations.get(call.text);
    if (!init) return [];
    call = init;
  }
  // z.strictObject({...}) / z.object({...}) / z.object({...}).strict()
  let cur: ts.Expression = call;
  for (let i = 0; i < 4; i++) {
    if (ts.isCallExpression(cur)) {
      const tail = calleeTail(cur);
      const arg = cur.arguments[0];
      if ((tail === 'strictObject' || tail === 'object' || tail === 'looseObject') && arg && ts.isObjectLiteralExpression(arg)) {
        return arg.properties.map((p) => (p.name ? (propertyName(p.name) ?? '') : '')).filter(Boolean);
      }
      if (ts.isPropertyAccessExpression(cur.expression)) cur = cur.expression.expression;
      else break;
    } else break;
  }
  return [];
}

export const sensitiveInGetParam = defineRule({
  id: 'sast.sensitive-in-get-param',
  title: 'Sensitive data travels in a URL',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-598'],
  asvs: ['V14.2.1'],
  sbd: ['DM-01'],
  exploitability: 'theoretical',
  description: 'A GET request (a form without method="post", or a route’s query schema) carries a password, card number or similar value.',
  impact: 'URLs end up in browser history, server logs and referrer headers, so the value leaks far beyond the request.',
  fix: 'Send sensitive values in a POST body (method="post" on the form; schema.body on the route).',
  appliesTo: ['ejs', 'ts'],
  checkEjs(file, report) {
    const masked = file.doc.masked;
    const formRe = /<form\b([^>]*)>/gi;
    let m: RegExpExecArray | null;
    while ((m = formRe.exec(masked)) !== null) {
      const attrs = m[1] ?? '';
      const method = /\bmethod\s*=\s*["']?\s*([a-z]+)/i.exec(attrs)?.[1]?.toLowerCase() ?? 'get';
      if (method !== 'get') continue;
      const end = masked.indexOf('</form', m.index);
      const body = masked.slice(m.index, end === -1 ? masked.length : end);
      const sensitive = /<input\b[^>]*\btype\s*=\s*["']?password/i.test(body) || [...body.matchAll(/\bname\s*=\s*["']([^"']*)["']/gi)].some((x) => SENSITIVE_PARAM.test(x[1] ?? ''));
      if (!sensitive) continue;
      const line = file.doc.lineOf(m.index);
      report({ line, column: file.doc.columnOf(m.index) }, { snippet: lineSnippet(file, m.index), evidence: `A GET form at line ${line} contains a sensitive field` });
    }
  },
  visit(node, file, report) {
    if (ts.isCallExpression(node) && calleeTail(node) === 'defineRoute') {
      const spec = resolveObjectLiteral(node.arguments[1], file);
      if (!spec) return;
      const method = stringValue((spec.properties.find((p) => p.name && propertyName(p.name) === 'method') as ts.PropertyAssignment | undefined)?.initializer);
      if (method !== 'GET') return;
      const schemaProp = spec.properties.find((p) => p.name && propertyName(p.name) === 'schema') as ts.PropertyAssignment | undefined;
      const schema = schemaProp ? resolveObjectLiteral(schemaProp.initializer, file) : undefined;
      const query = schema?.properties.find((p) => p.name && propertyName(p.name) === 'query') as ts.PropertyAssignment | undefined;
      const names = schemaPropertyNames(query?.initializer, file).filter((n) => SENSITIVE_PARAM.test(n));
      if (names.length > 0) report(node, { evidence: `GET route query schema contains: ${names.join(', ')}` });
      return;
    }
    if (ts.isPropertyAccessExpression(node)) {
      const full = text(node, file);
      const m = /^(req|request)\.(valid\.)?query\.([A-Za-z_]\w*)$/.exec(full);
      if (m && SENSITIVE_PARAM.test(m[3] ?? '')) report(node, { evidence: `${full} reads a sensitive value from the query string` });
    }
  },
});

/** EJS half of sast.todo-security; the TypeScript half lives in logging.ts. */
export function ejsSecurityTodos(file: EjsFile): { line: number; column: number; snippet: string }[] {
  const out: { line: number; column: number; snippet: string }[] = [];
  for (const tag of file.doc.tags) {
    if (tag.kind === 'comment' && TODO.test(tag.code) && SECURITY_WORDS.test(tag.code)) {
      out.push({ line: tag.line, column: tag.column, snippet: file.text.slice(tag.start, tag.end).trim() });
    }
  }
  const re = /<!--([\s\S]*?)-->/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(file.doc.masked)) !== null) {
    const body = file.text.slice(m.index, m.index + m[0].length);
    if (TODO.test(body) && SECURITY_WORDS.test(body)) {
      out.push({ line: file.doc.lineOf(m.index), column: file.doc.columnOf(m.index), snippet: body.replace(/\s+/g, ' ').trim().slice(0, 200) });
    }
  }
  return out;
}

export const viewRules = [ejsUnescapedOutput, inlineScriptInView, inlineEventHandler, secretQuestionField, sensitiveInGetParam];
