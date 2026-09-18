/**
 * Browser-side rules: innerHTML, document.write, React dangerouslySetInnerHTML, dynamic hrefs and
 * postMessage handlers that do not check the sender's origin.
 */
import ts from 'typescript';
import { calleeName, calleeTail, isStringLike, resolve, stringValue, text, type TsFile } from '../engine.js';
import { AI_NAME, defineRule, SANITIZER_CALL } from './base.js';

const SAFE_HREF_HEAD = /^(\/(?!\/)|#|https?:\/\/|mailto:|tel:)/;

function isHrefSafe(expr: ts.Expression, file: TsFile, depth = 0): boolean {
  if (depth > 3) return false;
  if (isStringLike(expr)) return true;
  if (ts.isTemplateExpression(expr)) return SAFE_HREF_HEAD.test(expr.head.text);
  if (ts.isParenthesizedExpression(expr) || ts.isAsExpression(expr) || ts.isNonNullExpression(expr)) return isHrefSafe(expr.expression, file, depth + 1);
  if (ts.isConditionalExpression(expr)) return isHrefSafe(expr.whenTrue, file, depth + 1) && isHrefSafe(expr.whenFalse, file, depth + 1);
  if (ts.isBinaryExpression(expr)) {
    if (expr.operatorToken.kind === ts.SyntaxKind.PlusToken) return isHrefSafe(expr.left, file, depth + 1);
    return isHrefSafe(expr.left, file, depth + 1) && isHrefSafe(expr.right, file, depth + 1);
  }
  if (ts.isCallExpression(expr)) {
    const tail = calleeTail(expr) ?? '';
    return SANITIZER_CALL.test(tail) || /^(encodeURI|encodeURIComponent|safeHref|sanitizeHref|isSafeHref|toSafeHref|safeUrl)$/.test(tail);
  }
  if (ts.isIdentifier(expr)) {
    const init = file.declarations.get(expr.text);
    return init ? isHrefSafe(init, file, depth + 1) : false;
  }
  return false;
}

export const innerHtmlAssignment = defineRule({
  id: 'sast.innerhtml-assignment',
  title: 'HTML is written into the page with innerHTML',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-79'],
  asvs: ['V3.2.2', 'V1.2.1'],
  exploitability: 'requires-auth',
  description: 'Browser code assigns a runtime value to innerHTML/outerHTML or calls insertAdjacentHTML().',
  impact: 'Any user-controlled text in that value runs as script in the visitor’s browser (DOM cross-site scripting).',
  fix: 'Use textContent, or build elements with document.createElement() and set their text.',
  appliesTo: ['ts', 'react'],
  visit(node, file, report) {
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (op !== ts.SyntaxKind.EqualsToken && op !== ts.SyntaxKind.PlusEqualsToken) return;
      if (!ts.isPropertyAccessExpression(node.left)) return;
      const name = node.left.name.text;
      if (name !== 'innerHTML' && name !== 'outerHTML') return;
      if (isStringLike(node.right)) return;
      if (AI_NAME.test(text(node.right, file))) return; // sast.ai-output-rendered-unescaped reports these
      report(node);
    } else if (ts.isCallExpression(node) && calleeTail(node) === 'insertAdjacentHTML') {
      const html = node.arguments[1];
      if (html && !isStringLike(html) && !AI_NAME.test(text(html, file))) report(node);
    }
  },
});

export const documentWrite = defineRule({
  id: 'sast.document-write',
  title: 'document.write() is used',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-79'],
  asvs: ['V3.2.2'],
  exploitability: 'requires-auth',
  description: 'Browser code calls document.write() or document.writeln().',
  impact: 'Text passed to document.write() is parsed as HTML, so user data in it can become script.',
  fix: 'Create elements with the DOM API and set textContent instead.',
  appliesTo: ['ts', 'react'],
  visit(node, _file, report) {
    if (!ts.isCallExpression(node)) return;
    const name = calleeName(node);
    if (name === 'document.write' || name === 'document.writeln') report(node);
  },
});

export const dangerouslySetInnerHtml = defineRule({
  id: 'sast.dangerously-set-inner-html',
  title: 'React renders raw HTML with dangerouslySetInnerHTML',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-79'],
  asvs: ['V3.2.2', 'V1.2.1'],
  exploitability: 'requires-auth',
  description: 'A component uses dangerouslySetInnerHTML, which bypasses React’s automatic escaping.',
  impact: 'User-controlled text in that HTML runs as script in other people’s browsers.',
  fix: 'Render the value as text ({value}) or sanitise it with an allow-list HTML sanitiser first.',
  appliesTo: ['react'],
  visit(node, _file, report) {
    if (ts.isJsxAttribute(node) && ts.isIdentifier(node.name) && node.name.text === 'dangerouslySetInnerHTML') report(node);
  },
});

export const hrefFromData = defineRule({
  id: 'sast.href-from-data',
  title: 'A link address comes from data without a protocol check',
  severity: 'medium',
  confidence: 'medium',
  cwe: ['CWE-79'],
  asvs: ['V1.2.2'],
  exploitability: 'requires-auth',
  description: 'An href (or location) is set from a runtime value without checking that it starts with a safe scheme or a local path.',
  impact: 'A value such as "javascript:..." runs script when the link is clicked.',
  fix: 'Only accept http(s):// URLs or local paths (starting with "/") and reject everything else before using the value.',
  appliesTo: ['ts', 'react'],
  visit(node, file, report) {
    if (ts.isJsxAttribute(node) && ts.isIdentifier(node.name) && node.name.text === 'href') {
      const init = node.initializer;
      if (init && ts.isJsxExpression(init) && init.expression && !isHrefSafe(init.expression, file)) report(node);
      return;
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = text(node.left, file);
      if (/(^|\.)(href)$|^(window\.)?location$/.test(left) && !isHrefSafe(node.right, file)) report(node);
      return;
    }
    if (ts.isCallExpression(node)) {
      const name = calleeName(node) ?? '';
      if (/^(window\.)?location\.(assign|replace)$/.test(name) && node.arguments[0] && !isHrefSafe(node.arguments[0], file)) report(node);
    }
  },
});

function resolveHandler(expr: ts.Expression, file: TsFile): ts.FunctionLikeDeclaration | undefined {
  const r = resolve(expr, file);
  if (ts.isArrowFunction(r) || ts.isFunctionExpression(r)) return r;
  if (ts.isIdentifier(expr)) return file.functions.get(expr.text);
  return undefined;
}

export const postMessageNoOriginCheck = defineRule({
  id: 'sast.postmessage-no-origin-check',
  title: 'A message handler does not check where the message came from',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-346'],
  asvs: ['V3.5.5'],
  exploitability: 'requires-network-exposure',
  description: 'A window "message" event handler never looks at event.origin.',
  impact: 'Any web page open in the same browser can send messages the app will act on.',
  fix: 'Compare event.origin with the expected origin at the top of the handler and ignore everything else.',
  appliesTo: ['ts', 'react'],
  visit(node, file, report) {
    let handler: ts.Expression | undefined;
    if (ts.isCallExpression(node) && calleeTail(node) === 'addEventListener' && stringValue(node.arguments[0]) === 'message') handler = node.arguments[1];
    else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && /^(window\.)?onmessage$/.test(text(node.left, file))) handler = node.right;
    if (!handler) return;
    const fn = resolveHandler(handler, file);
    if (!fn || !fn.body) return;
    if (!/\.origin\b/.test(text(fn.body, file))) report(node);
  },
});

export const domRules = [innerHtmlAssignment, documentWrite, dangerouslySetInnerHtml, hrefFromData, postMessageNoOriginCheck];
