/**
 * Helpers shared by the SAST rules: a compact rule constructor and the name patterns that several rules
 * use to decide whether a value is "security relevant" (secrets, sensitive fields, AI output, ...).
 */
import ts from 'typescript';
import type { Confidence, Exploitability, Severity } from '@shared/findings.js';
import type { EjsFile, Report, ReportOptions, RuleTarget, SastRule, ScanTree, TsFile } from '../engine.js';

export interface RuleSpec {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  asvs: string[];
  aisvs?: string[];
  sbd?: string[];
  exploitability: Exploitability;
  description: string;
  impact: string;
  /** One-sentence remediation summary (fallback when remediation.json has no entry). */
  fix: string;
  steps?: string[];
  references?: string[];
  howToConfirmFixed?: string;
  appliesTo: RuleTarget[];
  visit?(node: ts.Node, file: TsFile, report: Report): void;
  checkFile?(file: TsFile, report: Report): void;
  checkEjs?(file: EjsFile, report: Report): void;
  checkTree?(tree: ScanTree, report: (file: string, opts: ReportOptions & { line: number }) => void): void;
}

export function defineRule(spec: RuleSpec): SastRule {
  const { fix, steps, references, visit, checkFile, checkEjs, checkTree, ...meta } = spec;
  const rule: SastRule = {
    ...meta,
    aisvs: meta.aisvs ?? [],
    remediation: { summary: fix, steps: steps ?? [], references: references ?? [] },
  };
  if (visit) rule.visit = visit;
  if (checkFile) rule.checkFile = checkFile;
  if (checkEjs) rule.checkEjs = checkEjs;
  if (checkTree) rule.checkTree = checkTree;
  return rule;
}

// ---------------------------------------------------------------------------------------------
// Name patterns

/** Identifier / property names that hold credentials. */
export const SECRET_NAME =
  /(secret|passw(or)?d|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|signing[_-]?key|encryption[_-]?key|token)$/i;

/** Environment variable names that hold credentials. */
export const SECRET_ENV_NAME = /(SECRET|PASSWORD|PASSWD|_KEY$|_KEYS$|TOKEN|CREDENTIAL|SALT|HMAC)/;

/** Property names that must never be logged. */
export const SENSITIVE_LOG_KEY =
  /^(password|passwd|pwd|pass|secret|token|apiKey|api_key|apikey|authorization|cookie|cookies|totp|otp|recoveryCode|recoveryCodes|recovery_codes?|privateKey|private_key|ssn|cardNumber|card_number|cvv|sessionId|session_id|creditCard|credit_card|body|headers)$|(password|secret|token|apikey|api_key|totp|private_?key|card_?number|recovery_?code)/i;

/** Field / parameter names that must never travel in a URL. */
export const SENSITIVE_PARAM =
  /^(password|passwd|pwd|pass|secret|ssn|social_?security(_?number)?|card_?number|cc_?number|cvv|cvc|api_?key|apikey|otp|totp|iban|passport(_?number)?|national_?id|tax_?id|date_?of_?birth|dob|pin|credit_?card|access_?token|auth_?token|session_?id|secret_?key)$/i;

/** Names of security questions / password hints (V6.4.2). */
export const SECRET_QUESTION = /^(security|secret)[_-]?(question|answer)s?$|^(password|pwd|pass)[_-]?hint$|^hint$/i;

/** Context words meaning a value is a security artifact (used by weak-hash and Math.random rules). */
export const SECURITY_CONTEXT =
  /(token|secret|passw|session|nonce|otp|salt|csrf|recovery|verif|api_?key|private_?key|signature|hmac|credential|\bkey\b|\bpin\b|\bcode\b|auth)/i;

/** Names under which an AI answer usually travels. */
export const AI_NAME =
  /\b(answer|reply|completion|assistant(Reply|Message|Text|Output|Response)?|ai(Response|Output|Reply|Text|Answer|Message)|llm(Output|Response|Text|Answer)?|model(Output|Response|Text|Answer)|chat(Response|Reply|Answer)|generated(Text|Html|Answer))\b|\bai\.(answer|reply|text|output|response)\b/i;

/** Function names that turn a raw record into something safe to return. */
export const DTO_FUNCTION = /(dto|serializ|present|toPublic|toOwner|toAdmin|^pick$|^omit$|format|redact|sanitize|toJson|toView|shape)/i;

export const SANITIZER_CALL = /^(safeLocalPath|safeRedirect|safeUrl|sanitizeUrl|toLocalPath|localPath|isSafeUrl|safePath|sanitizeFilename|safeFilename|basename|encodeURIComponent)$/;

export const PLACEHOLDER_VALUE =
  /^(x+|\*+|\.+|-+|changeme|change-me|change_me|replace-me|replace_me|placeholder|example|sample|dummy|test|none|null|undefined|secret|password|token|apikey|api_key|todo|tbd|your[-_].*|<.*>|\{.*\}|__.*__)$/i;

export function looksLikePlaceholder(value: string): boolean {
  const v = value.trim();
  if (v.length === 0) return true;
  if (PLACEHOLDER_VALUE.test(v)) return true;
  return /(example|placeholder|changeme|change-me|replace|your[-_]|<[a-z_ -]+>|\$\{|generate_with)/i.test(v);
}

/** True when a string literal plausibly is a real credential rather than a name, key or placeholder. */
export function looksLikeSecretValue(value: string, name = ''): boolean {
  const v = value.trim();
  if (v.length < 8 || /\s/.test(v)) return false;
  if (looksLikePlaceholder(v)) return false;
  if (name && v.toLowerCase() === name.toLowerCase()) return false;
  if (/^[A-Z][A-Z0-9_]+$/.test(v)) return false; // an environment variable name, not a value
  if (/^(\/|\.\/|\.\.\/|https?:\/\/|[a-z]+:\/\/)/i.test(v)) return false; // paths and URLs
  if (/^[a-z-]+$/.test(v) && v.length < 16) return false; // short lowercase words are usually names
  return true;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Local name → imported name for a specifier matching `modules` (exact names or a `prefix*`). */
export function importedBindings(file: TsFile, modules: (string | RegExp)[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const imp of file.imports) {
    if (!moduleMatches(imp.specifier, modules)) continue;
    for (const [local, imported] of imp.names) out.set(local, imported);
  }
  return out;
}

export function moduleMatches(specifier: string, modules: (string | RegExp)[]): boolean {
  return modules.some((m) => (typeof m === 'string' ? m === specifier : m.test(specifier)));
}

export function importsOf(file: TsFile, modules: (string | RegExp)[]): TsFile['imports'] {
  return file.imports.filter((imp) => moduleMatches(imp.specifier, modules));
}

/**
 * For a call like `cp.exec(...)`, `exec(...)` or `require('child_process').exec(...)`, returns the name of
 * the function on the module when the callee resolves to one of `modules`.
 */
export function moduleFunctionOfCall(node: ts.CallExpression, file: TsFile, modules: (string | RegExp)[]): string | undefined {
  const bindings = importedBindings(file, modules);
  const e = node.expression;
  if (ts.isIdentifier(e)) {
    const imported = bindings.get(e.text);
    if (imported && imported !== '*' && imported !== 'default') return imported;
    return undefined;
  }
  if (ts.isPropertyAccessExpression(e)) {
    const obj = e.expression;
    if (ts.isIdentifier(obj)) {
      const imported = bindings.get(obj.text);
      if (imported === '*' || imported === 'default') return e.name.text;
      return undefined;
    }
    if (ts.isCallExpression(obj) && ts.isIdentifier(obj.expression) && obj.expression.text === 'require') {
      const arg = obj.arguments[0];
      if (arg && ts.isStringLiteralLike(arg) && moduleMatches(arg.text, modules)) return e.name.text;
    }
  }
  return undefined;
}

/** Nearest ancestor that is a property assignment or variable declaration, with its name. */
export function assignedName(node: ts.Node): string | undefined {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isVariableDeclaration(cur) && ts.isIdentifier(cur.name)) return cur.name.text;
    if (ts.isPropertyAssignment(cur)) {
      const n = cur.name;
      if (ts.isIdentifier(n) || ts.isStringLiteralLike(n)) return n.text;
      return undefined;
    }
    if (ts.isFunctionLike(cur) || ts.isSourceFile(cur) || ts.isBlock(cur)) return undefined;
    cur = cur.parent;
  }
  return undefined;
}

export function stringArg(node: ts.CallExpression | ts.NewExpression, index: number): string | undefined {
  const arg = node.arguments?.[index];
  if (arg && (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))) return arg.text;
  return undefined;
}

export function isTrueLiteral(node: ts.Node | undefined): boolean {
  return !!node && node.kind === ts.SyntaxKind.TrueKeyword;
}

export function isFalseLiteral(node: ts.Node | undefined): boolean {
  return !!node && node.kind === ts.SyntaxKind.FalseKeyword;
}

export function hasAncestor(node: ts.Node, pred: (n: ts.Node) => boolean): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (pred(cur)) return true;
    cur = cur.parent;
  }
  return false;
}

/** Root receiver of a call chain: `res.status(200).json(x)` → `res`. */
export function chainRoot(node: ts.Expression): ts.Expression {
  let cur: ts.Expression = node;
  for (;;) {
    if (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) cur = cur.expression;
    else if (ts.isCallExpression(cur) || ts.isNewExpression(cur)) cur = cur.expression;
    else if (ts.isNonNullExpression(cur) || ts.isParenthesizedExpression(cur) || ts.isAsExpression(cur)) cur = cur.expression;
    else return cur;
  }
}

export function chainRootName(node: ts.Expression): string | undefined {
  const root = chainRoot(node);
  return ts.isIdentifier(root) ? root.text : undefined;
}

/** The first string literal at the start of a `'a' + b + 'c'` concatenation, or the head of a template literal. */
export function leadingLiteralText(node: ts.Expression): string | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) return node.head.text;
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return leadingLiteralText(node.left);
  if (ts.isParenthesizedExpression(node)) return leadingLiteralText(node.expression);
  return undefined;
}

/** All non-literal operands of a concatenation / substitutions of a template literal. */
export function dynamicParts(node: ts.Expression): ts.Expression[] {
  if (ts.isTemplateExpression(node)) return node.templateSpans.map((s) => s.expression);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return [...dynamicParts(node.left), ...dynamicParts(node.right)];
  }
  if (ts.isParenthesizedExpression(node)) return dynamicParts(node.expression);
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isNumericLiteral(node)) return [];
  return [node];
}

/** Does the JSX attribute / property name equal `name` (case-sensitive)? */
export function jsxAttributeNamed(node: ts.Node, name: string): node is ts.JsxAttribute {
  return ts.isJsxAttribute(node) && ts.isIdentifier(node.name) && node.name.text === name;
}
