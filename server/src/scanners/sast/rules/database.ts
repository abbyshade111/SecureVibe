/**
 * Database rules: SQL built from strings, direct driver access outside the db wrapper, raw rows sent to
 * clients, and multi-row writes outside a transaction.
 */
import posix from 'node:path/posix';
import ts from 'typescript';
import {
  calleeName,
  calleeTail,
  functionName,
  isTainted,
  positionOf,
  REQ_TAINT,
  resolve,
  text,
  unwrapAwait,
  type ScanTree,
  type TsFile,
} from '../engine.js';
import { chainRootName, defineRule, DTO_FUNCTION, dynamicParts, importedBindings, importsOf, leadingLiteralText } from './base.js';

const SQL_SINKS = new Set(['run', 'get', 'all', 'q', 'exec', 'prepare', 'query', 'execute']);
const SQL_START = /^\s*(select|insert|update|delete|replace|with|create|drop|alter|pragma)\b/i;
const WRITE_START = /^\s*(insert|update|delete|replace)\b/i;
const DB_MODULE = /(^|\/)db(\/index)?(\.[cm]?[jt]s)?$/;
const DB_RECEIVER = /^(db|database|sqlite|conn|connection|client|pool)$/;
const DB_DRIVERS = ['node:sqlite', 'sqlite', 'sqlite3', 'better-sqlite3', 'mysql', 'mysql2', 'pg', 'knex', 'sequelize', 'typeorm', '@prisma/client', 'mongodb', 'mongoose'];
const PASS_THROUGH = new Set(['reverse', 'slice', 'filter', 'sort', 'concat', 'flat', 'at', 'find', 'toSorted', 'toReversed']);

/** Was this expression built only from literals and constants declared in the file? */
function isConstant(expr: ts.Expression, file: TsFile, depth = 0): boolean {
  if (depth > 3) return false;
  if (ts.isStringLiteralLike(expr) || ts.isNumericLiteral(expr)) return true;
  if (ts.isTemplateExpression(expr)) return expr.templateSpans.every((s) => isConstant(s.expression, file, depth + 1));
  if (ts.isParenthesizedExpression(expr) || ts.isAsExpression(expr)) return isConstant(expr.expression, file, depth + 1);
  if (ts.isIdentifier(expr)) {
    const init = file.declarations.get(expr.text);
    if (init) return isConstant(init, file, depth + 1);
    // `for (const table of ['users', 'notes'])` — the loop variable only takes literal values.
    let cur: ts.Node | undefined = expr.parent;
    while (cur) {
      if (ts.isForOfStatement(cur) && ts.isVariableDeclarationList(cur.initializer)) {
        const decl = cur.initializer.declarations[0];
        if (decl && ts.isIdentifier(decl.name) && decl.name.text === expr.text) {
          return ts.isArrayLiteralExpression(cur.expression) && cur.expression.elements.every((e) => ts.isStringLiteralLike(e));
        }
      }
      cur = cur.parent;
    }
  }
  return false;
}

/** `ids.map(() => '?').join(', ')` — a list of placeholders, not data. */
function isPlaceholderList(expr: ts.Expression, file: TsFile): boolean {
  const r = ts.isIdentifier(expr) ? resolve(expr, file) : expr;
  return /\.map\(\s*\(?\w*\)?\s*=>\s*['"`]\?['"`]\s*\)\s*\.join\(/.test(text(r, file));
}

/** Is this a call into the db wrapper (`get`, `all`, `run`, `q` imported from src/db, or `db.get(...)`)? */
export function isDbHelperCall(node: ts.CallExpression, file: TsFile, names: Set<string>): boolean {
  const tail = calleeTail(node);
  if (!tail || !names.has(tail)) return false;
  const e = node.expression;
  if (ts.isIdentifier(e)) {
    const bindings = importedBindings(file, [DB_MODULE]);
    const imported = bindings.get(e.text);
    return imported !== undefined && names.has(imported);
  }
  if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) {
    const recv = e.expression.text;
    if (DB_RECEIVER.test(recv)) return true;
    const bindings = importedBindings(file, [DB_MODULE]);
    return bindings.get(recv) === '*';
  }
  return false;
}

function sqlArgument(node: ts.CallExpression, file: TsFile): ts.Expression | undefined {
  const arg = node.arguments[0];
  if (!arg) return undefined;
  return resolve(arg, file);
}

export const sqlStringConcat = defineRule({
  id: 'sast.sql-string-concat',
  title: 'SQL is built from pieces of text',
  severity: 'critical',
  confidence: 'high',
  cwe: ['CWE-89'],
  asvs: ['V1.2.4'],
  exploitability: 'trivial',
  description: 'A database query is assembled from text pieces instead of using bound parameters (the `?` placeholders).',
  impact: 'If any piece comes from a user, they can change the query to read, alter or delete any data (SQL injection).',
  fix: 'Keep the SQL text fixed and pass every value as a parameter: run("... WHERE id = ?", [id]).',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (!tail || !SQL_SINKS.has(tail)) return;
    const sql = sqlArgument(node, file);
    if (!sql) return;
    const head = leadingLiteralText(sql);
    if (head === undefined || !SQL_START.test(head)) return;
    const parts = dynamicParts(sql);
    if (parts.length === 0) return;
    if (parts.every((p) => isConstant(p, file) || isPlaceholderList(p, file))) return;
    const tainted = parts.some((p) => isTainted(p, file, REQ_TAINT));
    // Interpolated identifiers that do not come from a request are only reported in generated code: the
    // protected template files validate their table/column names, and tests/scripts never see request data.
    if (!tainted && (file.isProtected || file.isTest || file.isScript)) return;
    report(node, {
      severity: tainted ? 'critical' : 'high',
      confidence: tainted ? 'high' : 'medium',
      evidence: tainted
        ? `Request data is inserted into the SQL text: ${text(sql, file).slice(0, 160)}`
        : `A runtime value is inserted into the SQL text: ${text(sql, file).slice(0, 160)}`,
    });
  },
});

export const dbRawOutsideWrapper = defineRule({
  id: 'sast.db-raw-outside-wrapper',
  title: 'The database is used directly, outside the db wrapper',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-89'],
  asvs: ['V1.2.4', 'V2.3.3'],
  exploitability: 'requires-auth',
  description: 'Code outside src/db talks to the database driver directly instead of using the run/get/all helpers.',
  impact: 'Direct driver calls skip the protections the wrapper guarantees (parameters only, pragmas, bounded lists), so mistakes are easier to make and harder to review.',
  fix: 'Import run/get/all/withTransaction from src/db/index.ts and use them for every query.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    if (file.relPath.startsWith('src/db/') || file.isTest) return;
    for (const imp of importsOf(file, DB_DRIVERS)) report(imp.node, { evidence: `${file.relPath} imports the database driver "${imp.specifier}"` });
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        if (method === 'prepare' || method === 'exec') {
          const recv = node.expression.expression;
          const recvText = text(recv, file);
          const resolved = ts.isIdentifier(recv) ? resolve(recv, file) : recv;
          const resolvedText = text(resolved, file);
          const isDb =
            /^(getDb|openDb)\(\)$/.test(recvText) ||
            /^(getDb|openDb)\(\)$/.test(resolvedText) ||
            /^new DatabaseSync\(/.test(resolvedText) ||
            (ts.isIdentifier(recv) && DB_RECEIVER.test(recv.text) && !ts.isRegularExpressionLiteral(resolved));
          if (isDb) report(node, { evidence: `${recvText}.${method}() bypasses the db wrapper` });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
  },
});

// ---------------------------------------------------------------------------------------------
// Raw rows sent to the client

export function resolveImportedFile(tree: ScanTree, fromRel: string, specifier: string): TsFile | undefined {
  if (!specifier.startsWith('.')) return undefined;
  const base = posix.normalize(posix.join(posix.dirname(fromRel), specifier));
  const candidates = [base, base.replace(/\.js$/, '.ts'), base.replace(/\.mjs$/, '.mts'), `${base}.ts`, `${base}/index.ts`, `${base}.js`, `${base}/index.js`];
  for (const c of candidates) {
    const f = tree.files.find((x) => x.kind === 'ts' && x.relPath === c);
    if (f && f.kind === 'ts') return f;
  }
  return undefined;
}

type RawIndex = Map<TsFile, Set<string>>;

function returnExpressions(fn: ts.FunctionLikeDeclaration): ts.Expression[] {
  const out: ts.Expression[] = [];
  if (!fn.body) return out;
  if (!ts.isBlock(fn.body)) return [fn.body];
  const visit = (node: ts.Node): void => {
    if (ts.isReturnStatement(node) && node.expression) out.push(node.expression);
    if (ts.isFunctionLike(node) && node !== fn) return;
    ts.forEachChild(node, visit);
  };
  visit(fn.body);
  return out;
}

const DB_READS = new Set(['get', 'all']);

const ROW_NAME = /^(rows?|records?|entity|entities|items?|users?|result|results|data|found|existing|current|updated|created)$/i;

function isRawRow(expr: ts.Expression, file: TsFile, tree: ScanTree, index: RawIndex, depth: number, seen: Set<ts.Node>): boolean {
  if (depth > 4 || seen.has(expr)) return false;
  seen.add(expr);
  const e = unwrapAwait(expr);
  if (ts.isPropertyAccessExpression(e) && text(e, file) === 'req.entity') return true;
  if (ts.isIdentifier(e)) {
    // A name taken out of a result by destructuring is only the row when it is called one (`const { row } = …`);
    // the other parts (`fullKey`, `count`, …) are not the record.
    if (file.destructured.has(e.text) && !ROW_NAME.test(e.text)) return false;
    const init = file.declarations.get(e.text);
    return init ? isRawRow(init, file, tree, index, depth + 1, seen) : false;
  }
  if (ts.isObjectLiteralExpression(e)) {
    return e.properties.some((p) => {
      if (ts.isPropertyAssignment(p)) return isRawRow(p.initializer, file, tree, index, depth + 1, seen);
      if (ts.isShorthandPropertyAssignment(p)) return isRawRow(p.name, file, tree, index, depth + 1, seen);
      if (ts.isSpreadAssignment(p)) return isRawRow(p.expression, file, tree, index, depth + 1, seen);
      return false;
    });
  }
  if (ts.isArrayLiteralExpression(e)) return e.elements.some((el) => isRawRow(el, file, tree, index, depth + 1, seen));
  if (ts.isConditionalExpression(e)) {
    return isRawRow(e.whenTrue, file, tree, index, depth + 1, seen) || isRawRow(e.whenFalse, file, tree, index, depth + 1, seen);
  }
  if (ts.isCallExpression(e)) {
    if (isDbHelperCall(e, file, DB_READS)) return true;
    const name = calleeName(e) ?? '';
    const tail = calleeTail(e) ?? '';
    if (DTO_FUNCTION.test(name)) return false;
    // Statement objects: q('...').get(...) / prepare('...').all(...)
    if (DB_READS.has(tail) && ts.isPropertyAccessExpression(e.expression) && ts.isCallExpression(e.expression.expression)) {
      const inner = calleeTail(e.expression.expression);
      if (inner === 'q' || inner === 'prepare') return true;
    }
    if (ts.isPropertyAccessExpression(e.expression)) {
      const receiver = e.expression.expression;
      if (PASS_THROUGH.has(tail)) return isRawRow(receiver, file, tree, index, depth + 1, seen);
      if (tail === 'map') {
        const cb = e.arguments[0];
        if (!cb || !isRawRow(receiver, file, tree, index, depth + 1, seen)) return false;
        if (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) {
          const param = cb.parameters[0];
          const paramName = param && ts.isIdentifier(param.name) ? param.name.text : undefined;
          return returnExpressions(cb).some((r) => {
            const u = unwrapAwait(r);
            if (ts.isIdentifier(u) && u.text === paramName) return true;
            if (ts.isObjectLiteralExpression(u)) return u.properties.some((p) => ts.isSpreadAssignment(p) && ts.isIdentifier(p.expression) && p.expression.text === paramName);
            return false;
          });
        }
        return ts.isIdentifier(cb) && !DTO_FUNCTION.test(cb.text) && isRawReturningFunction(cb.text, file, tree, index, depth + 1, seen);
      }
      return false;
    }
    if (ts.isIdentifier(e.expression)) return isRawReturningFunction(e.expression.text, file, tree, index, depth + 1, seen);
  }
  return false;
}

function isRawReturningFunction(name: string, file: TsFile, tree: ScanTree, index: RawIndex, depth: number, seen: Set<ts.Node>): boolean {
  const local = file.functions.get(name);
  if (local) return returnExpressions(local).some((r) => isRawRow(r, file, tree, index, depth + 1, seen));
  for (const imp of file.imports) {
    const imported = imp.names.get(name);
    if (!imported) continue;
    const target = resolveImportedFile(tree, file.relPath, imp.specifier);
    if (!target) return false;
    const set = index.get(target);
    return set !== undefined && set.has(imported === 'default' ? name : imported);
  }
  return false;
}

function buildRawIndex(tree: ScanTree): RawIndex {
  const index: RawIndex = new Map();
  for (const file of tree.files) {
    if (file.kind !== 'ts') continue;
    const set = new Set<string>();
    for (const [name, fn] of file.functions) {
      if (DTO_FUNCTION.test(name)) continue;
      if (returnExpressions(fn).some((r) => isRawRow(r, file, tree, new Map(), 0, new Set()))) set.add(name);
    }
    index.set(file, set);
  }
  return index;
}

interface Sink {
  node: ts.CallExpression;
  payload: ts.Expression;
  label: string;
}

function responseSinks(file: TsFile): Sink[] {
  const out: Sink[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      const root = chainRootName(node.expression);
      if ((tail === 'json' || tail === 'send') && root === 'res' && node.arguments[0]) out.push({ node, payload: node.arguments[0], label: `res.${tail}()` });
      else if (tail === 'render' && root === 'res' && node.arguments[1]) out.push({ node, payload: node.arguments[1], label: 'res.render()' });
      else if (tail === 'renderPage' && node.arguments[3]) out.push({ node, payload: node.arguments[3], label: 'renderPage()' });
    }
    ts.forEachChild(node, visit);
  };
  visit(file.sf);
  return out;
}

export const resRawDbRow = defineRule({
  id: 'sast.res-raw-db-row',
  title: 'A raw database record is sent to the browser',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-213'],
  asvs: ['V15.3.1', 'V8.2.3'],
  exploitability: 'requires-auth',
  description: 'A row straight from the database is returned or rendered without passing through a DTO (toPublicDto / toOwnerDto / toAdminDto).',
  impact: 'Every column of the record leaks, including ones the person should not see (owner ids, internal flags, hashes, private notes).',
  fix: 'Return the DTO for the audience (toPublicDto / toOwnerDto / toAdminDto) instead of the row.',
  appliesTo: ['ts'],
  checkTree(tree, report) {
    const index = buildRawIndex(tree);
    for (const file of tree.files) {
      if (file.kind !== 'ts' || file.isTest) continue;
      for (const sink of responseSinks(file)) {
        if (isRawRow(sink.payload, file, tree, index, 0, new Set())) {
          const pos = positionOf(sink.node, file);
          report(file.relPath, {
            line: pos.line,
            column: pos.column,
            evidence: `${sink.label} sends ${text(sink.payload, file).slice(0, 120)} which comes straight from a database read`,
          });
        }
      }
    }
  },
});

// ---------------------------------------------------------------------------------------------
// Multiple writes without a transaction

export const multipleWritesNoTransaction = defineRule({
  id: 'sast.multiple-writes-no-transaction',
  title: 'Several database writes happen outside a transaction',
  severity: 'low',
  confidence: 'medium',
  cwe: ['CWE-362'],
  asvs: ['V2.3.3'],
  sbd: ['DM-03'],
  exploitability: 'theoretical',
  description: 'A function performs more than one INSERT/UPDATE/DELETE without wrapping them in withTransaction().',
  impact: 'If the app fails between the writes, the data is left half-changed, and two overlapping requests can both slip past a check (for example a quota).',
  fix: 'Wrap the related writes in withTransaction(() => { ... }) so they all succeed or all roll back.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    if (!file.relPath.startsWith('src/features/') || file.isProtected || file.isTest) return;
    const groups = new Map<ts.Node, ts.CallExpression[]>();
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && isDbHelperCall(node, file, new Set(['run']))) {
        const sql = sqlArgument(node, file);
        const head = sql ? leadingLiteralText(sql) : undefined;
        if (head !== undefined && WRITE_START.test(head)) {
          let inTransaction = false;
          let cur: ts.Node | undefined = node.parent;
          let owner: ts.Node | undefined;
          while (cur) {
            if (ts.isCallExpression(cur) && /^(withTransaction|transaction)$/.test(calleeTail(cur) ?? '')) inTransaction = true;
            if (!owner && ts.isFunctionLike(cur)) owner = cur;
            cur = cur.parent;
          }
          if (!inTransaction) {
            const key = owner ?? file.sf;
            const list = groups.get(key) ?? [];
            list.push(node);
            groups.set(key, list);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
    for (const [owner, calls] of groups) {
      if (calls.length < 2) continue;
      const second = calls[1]!;
      const name = ts.isFunctionLike(owner) ? functionName(owner as ts.FunctionLikeDeclaration) || '(anonymous function)' : 'module scope';
      report(second, { evidence: `${calls.length} writes in ${name} without withTransaction()`, fingerprintExtra: name });
    }
  },
});

export const databaseRules = [sqlStringConcat, dbRawOutsideWrapper, resRawDbRow, multipleWritesNoTransaction];
