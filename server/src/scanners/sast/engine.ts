/**
 * The SAST rule engine. Source files are parsed once with the TypeScript compiler API and every rule
 * gets to look at each node; EJS templates go through the tokenizer in ejs.ts. Rules describe
 * themselves (severity, CWE, ASVS/AISVS mappings, remediation) and call `report()` on a hit.
 */
import ts from 'typescript';
import type { Confidence, Finding, Severity } from '@shared/findings.js';
import type { ScanContext } from '../types.js';
import { tokenizeEjs, type EjsDocument } from './ejs.js';
import { buildFinding, lineTextAt, type RuleMeta } from './findings.js';
import { matchesAnyGlob, originFor, type IntroducedBy } from './files.js';

export type RuleTarget = 'ts' | 'ejs' | 'react';

export interface ImportInfo {
  specifier: string;
  /** Local name → imported name (default import is recorded as "default", namespace as "*"). */
  names: Map<string, string>;
  node: ts.Node;
  /** How it was brought in: static import, require() or dynamic import(). */
  via: 'import' | 'require' | 'dynamic';
}

export interface TsFile {
  kind: 'ts';
  relPath: string;
  absPath: string;
  text: string;
  sf: ts.SourceFile;
  isReact: boolean;
  isTest: boolean;
  isScript: boolean;
  isPublic: boolean;
  isProtected: boolean;
  imports: ImportInfo[];
  /** Variable name → its initializer (first declaration wins). Used for one-level taint resolution. */
  declarations: Map<string, ts.Expression>;
  /** Names bound by destructuring (`const { row, fullKey } = create(...)`): their initializer is the whole value. */
  destructured: Set<string>;
  /** Function declarations by name (for resolving handler identifiers). */
  functions: Map<string, ts.FunctionLikeDeclaration>;
  origin: IntroducedBy;
}

export interface EjsFile {
  kind: 'ejs';
  relPath: string;
  absPath: string;
  text: string;
  doc: EjsDocument;
  isLayout: boolean;
  origin: IntroducedBy;
}

export type ScannedFile = TsFile | EjsFile;

export interface ScanTree {
  ctx: ScanContext;
  files: ScannedFile[];
  /** Every file in the app (not only source files), as posix relative paths. */
  allPaths: string[];
}

export interface ReportOptions {
  /** Text shown as "what the tool observed"; defaults to the offending line. */
  evidence?: string;
  snippet?: string;
  severity?: Severity;
  confidence?: Confidence;
  line?: number;
  column?: number;
  fingerprintExtra?: string;
}

export type Report = (target: ts.Node | { line: number; column?: number }, opts?: ReportOptions) => void;

export interface SastRule extends RuleMeta {
  appliesTo: RuleTarget[];
  /** Called for every node of a TypeScript/JavaScript file. */
  visit?(node: ts.Node, file: TsFile, report: Report): void;
  /** Called once per TypeScript/JavaScript file (before visiting nodes). */
  checkFile?(file: TsFile, report: Report): void;
  /** Called once per EJS/HTML file. */
  checkEjs?(file: EjsFile, report: Report): void;
  /** Called once per scan with the whole tree, for cross-file rules. */
  checkTree?(tree: ScanTree, report: (file: string, opts: ReportOptions & { line: number }) => void): void;
}

export const SAST_TOOL = { name: 'securevibe-sast', version: ts.version };

// ---------------------------------------------------------------------------------------------
// Parsing

const TS_EXTENSIONS: Record<string, ts.ScriptKind> = {
  '.ts': ts.ScriptKind.TS,
  '.mts': ts.ScriptKind.TS,
  '.cts': ts.ScriptKind.TS,
  '.tsx': ts.ScriptKind.TSX,
  '.js': ts.ScriptKind.JS,
  '.mjs': ts.ScriptKind.JS,
  '.cjs': ts.ScriptKind.JS,
  '.jsx': ts.ScriptKind.JSX,
};

export function scriptKindFor(relPath: string): ts.ScriptKind | undefined {
  if (relPath.endsWith('.d.ts')) return undefined;
  const ext = relPath.slice(relPath.lastIndexOf('.'));
  return TS_EXTENSIONS[ext];
}

export function isEjsPath(relPath: string): boolean {
  return relPath.endsWith('.ejs') || relPath.endsWith('.html');
}

/** Minified or generated bundles are skipped: rules would drown in noise and the code is not the app's own. */
export function looksMinified(relPath: string, text: string): boolean {
  if (/\.min\.(js|mjs|cjs)$/.test(relPath)) return true;
  let longest = 0;
  let current = 0;
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      if (current > longest) longest = current;
      current = 0;
    } else current++;
  }
  return Math.max(longest, current) > 2000;
}

export function parseTsFile(ctx: ScanContext, relPath: string, absPath: string, text: string): TsFile | undefined {
  const kind = scriptKindFor(relPath);
  if (kind === undefined) return undefined;
  const sf = ts.createSourceFile(absPath, text, ts.ScriptTarget.Latest, true, kind);
  const file: TsFile = {
    kind: 'ts',
    relPath,
    absPath,
    text,
    sf,
    isReact: kind === ts.ScriptKind.TSX || kind === ts.ScriptKind.JSX,
    isTest: relPath.startsWith('tests/') || /\.(test|spec)\.[cm]?[jt]sx?$/.test(relPath),
    isScript: relPath.startsWith('scripts/'),
    isPublic: relPath.startsWith('public/'),
    isProtected: matchesAnyGlob(relPath, ctx.manifest?.protectedPaths ?? []),
    imports: [],
    declarations: new Map(),
    destructured: new Set(),
    functions: new Map(),
    origin: originFor(ctx, relPath, text),
  };
  collectImports(file);
  collectDeclarations(file);
  return file;
}

export function parseEjsFile(ctx: ScanContext, relPath: string, absPath: string, text: string): EjsFile {
  return {
    kind: 'ejs',
    relPath,
    absPath,
    text,
    doc: tokenizeEjs(text),
    isLayout: /(^|\/)layouts?\//.test(relPath),
    origin: originFor(ctx, relPath, text),
  };
}

function collectImports(file: TsFile): void {
  const { sf } = file;
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const names = new Map<string, string>();
      const clause = node.importClause;
      if (clause?.name) names.set(clause.name.text, 'default');
      if (clause?.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) names.set(clause.namedBindings.name.text, '*');
        else for (const el of clause.namedBindings.elements) names.set(el.name.text, (el.propertyName ?? el.name).text);
      }
      file.imports.push({ specifier: node.moduleSpecifier.text, names, node, via: 'import' });
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      const expr = node.moduleReference.expression;
      if (ts.isStringLiteral(expr)) {
        file.imports.push({ specifier: expr.text, names: new Map([[node.name.text, '*']]), node, via: 'require' });
      }
    } else if (ts.isCallExpression(node)) {
      const arg = node.arguments[0];
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
      const isDynamic = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      if ((isRequire || isDynamic) && arg && ts.isStringLiteralLike(arg)) {
        const names = new Map<string, string>();
        const parent = node.parent;
        if (parent && ts.isVariableDeclaration(parent)) {
          if (ts.isIdentifier(parent.name)) names.set(parent.name.text, '*');
          else if (ts.isObjectBindingPattern(parent.name)) {
            for (const el of parent.name.elements) {
              if (ts.isIdentifier(el.name)) {
                const imported = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
                names.set(el.name.text, imported);
              }
            }
          }
        }
        file.imports.push({ specifier: arg.text, names, node, via: isRequire ? 'require' : 'dynamic' });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

function collectDeclarations(file: TsFile): void {
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      for (const name of bindingNames(node.name)) {
        if (!file.declarations.has(name)) file.declarations.set(name, node.initializer);
        if (!ts.isIdentifier(node.name)) file.destructured.add(name);
      }
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left) &&
      !file.declarations.has(node.left.text)
    ) {
      file.declarations.set(node.left.text, node.right);
    } else if (ts.isFunctionDeclaration(node) && node.name) {
      file.functions.set(node.name.text, node);
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = node.initializer;
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) file.functions.set(node.name.text, init);
    }
    ts.forEachChild(node, visit);
  };
  visit(file.sf);
}

export function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const out: string[] = [];
  for (const el of name.elements) {
    if (ts.isOmittedExpression(el)) continue;
    out.push(...bindingNames(el.name));
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Node helpers used by rules

export function text(node: ts.Node, file: TsFile): string {
  return node.getText(file.sf);
}

export function positionOf(node: ts.Node, file: TsFile): { line: number; column: number } {
  const { line, character } = file.sf.getLineAndCharacterOfPosition(node.getStart(file.sf));
  return { line: line + 1, column: character + 1 };
}

/** The callee as dotted text, e.g. "res.json", "db.get", "fetch"; undefined for computed callees. */
export function calleeName(node: ts.CallExpression | ts.NewExpression): string | undefined {
  const e = node.expression;
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) {
    const obj = e.expression;
    if (ts.isIdentifier(obj)) return `${obj.text}.${e.name.text}`;
    if (ts.isPropertyAccessExpression(obj) && ts.isIdentifier(obj.expression)) {
      return `${obj.expression.text}.${obj.name.text}.${e.name.text}`;
    }
    if (obj.kind === ts.SyntaxKind.ThisKeyword) return `this.${e.name.text}`;
    return `?.${e.name.text}`;
  }
  return undefined;
}

/** Last segment of a callee name ("json" for "res.json"). */
export function calleeTail(node: ts.CallExpression | ts.NewExpression): string | undefined {
  const name = calleeName(node);
  return name?.slice(name.lastIndexOf('.') + 1);
}

export function propertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) return name.text;
  if (ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) return name.text;
  return undefined;
}

export function objectProperty(obj: ts.ObjectLiteralExpression, key: string): ts.ObjectLiteralElementLike | undefined {
  return obj.properties.find((p) => p.name && propertyName(p.name) === key);
}

export function propertyValue(prop: ts.ObjectLiteralElementLike | undefined): ts.Expression | undefined {
  if (!prop) return undefined;
  if (ts.isPropertyAssignment(prop)) return prop.initializer;
  if (ts.isShorthandPropertyAssignment(prop)) return prop.name;
  return undefined;
}

export function isStringLike(node: ts.Node | undefined): node is ts.StringLiteralLike {
  return !!node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node));
}

export function stringValue(node: ts.Node | undefined): string | undefined {
  if (!node) return undefined;
  if (isStringLike(node)) return node.text;
  return undefined;
}

export function isLiteralish(node: ts.Expression): boolean {
  return (
    isStringLike(node) ||
    ts.isNumericLiteral(node) ||
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword ||
    (ts.isIdentifier(node) && node.text === 'undefined') ||
    ts.isTypeOfExpression(node) ||
    (ts.isPrefixUnaryExpression(node) && ts.isNumericLiteral(node.operand))
  );
}

export function enclosingFunction(node: ts.Node): ts.FunctionLikeDeclaration | undefined {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isFunctionLike(cur)) return cur as ts.FunctionLikeDeclaration;
    cur = cur.parent;
  }
  return undefined;
}

export function enclosingStatement(node: ts.Node): ts.Node {
  let cur: ts.Node = node;
  while (cur.parent && !ts.isStatement(cur) && !ts.isSourceFile(cur.parent)) cur = cur.parent;
  return cur;
}

export function functionName(fn: ts.FunctionLikeDeclaration | undefined): string {
  if (!fn) return '';
  if (fn.name && ts.isIdentifier(fn.name)) return fn.name.text;
  const parent = fn.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (parent && ts.isPropertyAssignment(parent) && parent.name) return propertyName(parent.name) ?? '';
  return '';
}

/** Resolves an identifier to its initializer in this file (one hop), or returns the node itself. */
export function resolve(node: ts.Expression, file: TsFile): ts.Expression {
  if (ts.isIdentifier(node)) {
    const init = file.declarations.get(node.text);
    if (init) return init;
  }
  return node;
}

export function resolveObjectLiteral(node: ts.Expression | undefined, file: TsFile): ts.ObjectLiteralExpression | undefined {
  if (!node) return undefined;
  const r = resolve(node, file);
  if (ts.isObjectLiteralExpression(r)) return r;
  if (ts.isAsExpression(r) || ts.isSatisfiesExpression(r)) return resolveObjectLiteral(r.expression, file);
  return undefined;
}

export function unwrapAwait(node: ts.Expression): ts.Expression {
  let cur = node;
  while (ts.isAwaitExpression(cur) || ts.isParenthesizedExpression(cur) || ts.isAsExpression(cur) || ts.isNonNullExpression(cur)) {
    cur = cur.expression;
  }
  return cur;
}

// ---------------------------------------------------------------------------------------------
// Taint: does an expression carry request-controlled data?

/** Anything read from the incoming request, including validated values (`req.valid`). */
export const REQ_TAINT = /\b(req|request)\.(body|query|params|valid|headers|cookies|hostname|originalUrl|url|path|get\(|header\()/;
/** Only raw, unvalidated request input. */
export const RAW_REQ_TAINT = /\b(req|request)\.(body|query|params|headers|cookies)\b/;

function identifiersIn(node: ts.Node, file: TsFile): string[] {
  const out: string[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isIdentifier(n)) {
      const p = n.parent;
      const isPropName = p && ts.isPropertyAccessExpression(p) && p.name === n;
      const isKey = p && (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) && p.name === n && !ts.isShorthandPropertyAssignment(p);
      if (!isPropName && !isKey) out.push(n.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  void file;
  return out;
}

export function isTainted(node: ts.Node, file: TsFile, pattern: RegExp = REQ_TAINT, depth = 0): boolean {
  if (pattern.test(text(node, file))) return true;
  if (depth >= 3) return false;
  for (const name of new Set(identifiersIn(node, file))) {
    const init = file.declarations.get(name);
    if (init && init !== node && isTainted(init, file, pattern, depth + 1)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// Running rules over a file

export interface RuleRunResult {
  findings: Finding[];
}

export function runRulesOnFile(ctx: ScanContext, rules: SastRule[], file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const makeReport =
    (rule: SastRule): Report =>
    (target, opts = {}) => {
      let line: number;
      let column: number | undefined;
      if ('kind' in target && typeof target.kind === 'number') {
        const pos = positionOf(target as ts.Node, file as TsFile);
        line = opts.line ?? pos.line;
        column = opts.column ?? pos.column;
      } else {
        const t = target as { line: number; column?: number };
        line = opts.line ?? t.line;
        column = opts.column ?? t.column;
      }
      const snippet = opts.snippet ?? lineTextAt(file.text, line);
      findings.push(
        buildFinding(ctx, {
          source: 'sast',
          rule,
          file: file.relPath,
          line,
          column,
          snippet,
          evidence: opts.evidence ?? `Line ${line} of ${file.relPath}: ${snippet}`,
          severity: opts.severity,
          confidence: opts.confidence,
          introducedBy: file.origin,
          tool: SAST_TOOL,
          fingerprintExtra: opts.fingerprintExtra,
        }),
      );
    };

  if (file.kind === 'ejs') {
    for (const rule of rules) {
      if (rule.appliesTo.includes('ejs') && rule.checkEjs) rule.checkEjs(file, makeReport(rule));
    }
    return findings;
  }

  const active = rules.filter((r) => r.appliesTo.includes('ts') || (file.isReact && r.appliesTo.includes('react')));
  const reporters = new Map(active.map((r) => [r.id, makeReport(r)] as const));
  for (const rule of active) if (rule.checkFile) rule.checkFile(file, reporters.get(rule.id)!);
  const visitors = active.filter((r) => r.visit);
  const walk = (node: ts.Node): void => {
    for (const rule of visitors) rule.visit!(node, file, reporters.get(rule.id)!);
    ts.forEachChild(node, walk);
  };
  walk(file.sf);
  return findings;
}
