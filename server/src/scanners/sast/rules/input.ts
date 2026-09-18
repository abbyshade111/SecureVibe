/**
 * Input-handling rules: unsafe regular expressions, regexes and file paths built from request data,
 * mass assignment, prototype pollution and password composition rules.
 */
import ts from 'typescript';
import { calleeName, calleeTail, enclosingStatement, isTainted, RAW_REQ_TAINT, REQ_TAINT, text, type TsFile } from '../engine.js';
import { assignedName, defineRule, importedBindings, stringArg } from './base.js';

const PATH_FUNCTIONS = new Set(['join', 'resolve', 'normalize']);
const FS_FUNCTIONS = new Set([
  'readFile',
  'readFileSync',
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'createReadStream',
  'createWriteStream',
  'unlink',
  'unlinkSync',
  'rm',
  'rmSync',
  'rmdir',
  'rmdirSync',
  'readdir',
  'readdirSync',
  'stat',
  'statSync',
  'lstat',
  'mkdir',
  'mkdirSync',
  'access',
  'accessSync',
  'open',
  'openSync',
  'rename',
  'renameSync',
  'copyFile',
  'copyFileSync',
  'existsSync',
  'truncate',
  'chmod',
  'chmodSync',
]);
const FS_MODULES = ['fs', 'node:fs', 'fs/promises', 'node:fs/promises'];
const PATH_MODULES = ['path', 'node:path', 'path/posix', 'node:path/posix', 'path/win32', 'node:path/win32'];
const SANITIZED_PATH = /\b(basename|sanitizeFilename|safeFilename|randomUUID|randomBytes|encodeURIComponent|stored\w*Path|\w*PathFor)\s*\(/;
const MERGE_FUNCTIONS = /^(merge|deepMerge|mergeDeep|extend|deepExtend|defaultsDeep|assignDeep|mergeWith|deepAssign)$/;

/**
 * Detects nested unbounded quantifiers such as (a+)+ or (\w*)*, the classic pattern behind catastrophic
 * backtracking. Character classes are skipped; escapes are honoured.
 */
export function hasNestedUnboundedQuantifier(pattern: string): boolean {
  const stack: { unbounded: boolean }[] = [];
  let inClass = false;
  let lastWasGroupClose = false;
  let closedGroupUnbounded = false;
  const unboundedAt = (i: number): number => {
    const c = pattern[i];
    if (c === '*' || c === '+') return 1;
    if (c === '{') {
      const m = /^\{(\d+),(\d*)\}/.exec(pattern.slice(i));
      if (m && (m[2] === '' || Number(m[2]) > 20)) return m[0].length;
    }
    return 0;
  };
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '\\') {
      i += 1;
      lastWasGroupClose = false;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      lastWasGroupClose = false;
      continue;
    }
    if (c === '(') {
      stack.push({ unbounded: false });
      lastWasGroupClose = false;
      continue;
    }
    if (c === ')') {
      const group = stack.pop();
      closedGroupUnbounded = group?.unbounded ?? false;
      lastWasGroupClose = true;
      continue;
    }
    const len = unboundedAt(i);
    if (len > 0) {
      if (lastWasGroupClose && closedGroupUnbounded) return true;
      const top = stack[stack.length - 1];
      if (top) top.unbounded = true;
      i += len - 1;
    }
    lastWasGroupClose = false;
  }
  return false;
}

export const unsafeRegex = defineRule({
  id: 'sast.unsafe-regex',
  title: 'A regular expression can take exponential time',
  severity: 'medium',
  confidence: 'medium',
  cwe: ['CWE-1333'],
  asvs: ['V1.2.9', 'V15.2.2'],
  sbd: ['RR-07'],
  exploitability: 'trivial',
  description: 'A pattern nests unbounded repetition (for example (a+)+), which backtracks catastrophically on crafted input.',
  impact: 'One request with a few dozen characters can keep the server busy for minutes (denial of service).',
  fix: 'Rewrite the pattern without nested repetition, bound the input length first, or use a simpler check.',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    let pattern: string | undefined;
    if (ts.isRegularExpressionLiteral(node)) pattern = node.text.replace(/^\/(.*)\/[a-z]*$/s, '$1');
    else if ((ts.isNewExpression(node) || ts.isCallExpression(node)) && calleeName(node) === 'RegExp') pattern = stringArg(node, 0);
    if (pattern && hasNestedUnboundedQuantifier(pattern)) report(node, { evidence: `Pattern ${pattern.slice(0, 80)} nests unbounded repetition` });
  },
});

export const regexFromUserInput = defineRule({
  id: 'sast.regex-from-user-input',
  title: 'A regular expression is built from request data',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-1333', 'CWE-20'],
  asvs: ['V1.2.9'],
  exploitability: 'requires-auth',
  description: 'new RegExp() receives text from the request.',
  impact: 'A user can supply a pattern that takes exponential time to evaluate and stall the server.',
  fix: 'Do not build patterns from input. Escape the text (replace /[.*+?^${}()|[\\]\\\\]/g) or use String.includes().',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isNewExpression(node) && !ts.isCallExpression(node)) return;
    if (calleeName(node) !== 'RegExp') return;
    const arg = node.arguments?.[0];
    if (arg && isTainted(arg, file, REQ_TAINT)) report(node);
  },
});

function isModuleFunction(node: ts.CallExpression, file: TsFile, modules: string[], names: Set<string>, receiverNames: RegExp): string | undefined {
  const tail = calleeTail(node);
  if (!tail || !names.has(tail)) return undefined;
  const e = node.expression;
  const bindings = importedBindings(file, modules);
  if (ts.isIdentifier(e)) {
    const imported = bindings.get(e.text);
    return imported && names.has(imported) ? imported : undefined;
  }
  if (ts.isPropertyAccessExpression(e)) {
    const recv = text(e.expression, file);
    if (receiverNames.test(recv)) return tail;
    if (ts.isIdentifier(e.expression)) {
      const imported = bindings.get(e.expression.text);
      if (imported === '*' || imported === 'default') return tail;
    }
  }
  return undefined;
}

export const pathJoinUserInput = defineRule({
  id: 'sast.path-join-user-input',
  title: 'A file path is built from request data',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-22'],
  asvs: ['V5.3.2'],
  exploitability: 'requires-auth',
  description: 'path.join()/resolve() combines a folder with a value from the request.',
  impact: 'A value like "../../.env" escapes the intended folder and reaches any file the app can read (path traversal).',
  fix: 'Never use user text as a file name. Store files under a random id and look the real path up in the database.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    const fn = isModuleFunction(node, file, PATH_MODULES, PATH_FUNCTIONS, /^path$/);
    if (!fn) return;
    const bad = node.arguments.find((a) => isTainted(a, file, REQ_TAINT) && !SANITIZED_PATH.test(text(a, file)));
    if (bad) report(node, { evidence: `${fn}(... ${text(bad, file).slice(0, 80)})` });
  },
});

export const fsUserPath = defineRule({
  id: 'sast.fs-user-path',
  title: 'A file is accessed at a path from the request',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-22', 'CWE-73'],
  asvs: ['V5.3.2'],
  exploitability: 'requires-auth',
  description: 'A file-system call (readFile, sendFile, createReadStream, unlink, ...) receives a path taken from the request.',
  impact: 'Users can read, overwrite or delete files outside the folder you intended.',
  fix: 'Look the file up by id in the database and use the stored, app-generated path (a helper named like storedUploadPath(id)); never pass request text to the file system.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    const name = calleeName(node);
    let fn = isModuleFunction(node, file, FS_MODULES, FS_FUNCTIONS, /^(fs|fsp|fsPromises|fs\.promises|promises)$/);
    if (!fn && (name === 'res.sendFile' || name === 'res.download')) fn = name;
    if (!fn) return;
    const pathArgs = fn === 'rename' || fn === 'renameSync' || fn === 'copyFile' || fn === 'copyFileSync' ? node.arguments.slice(0, 2) : node.arguments.slice(0, 1);
    const bad = pathArgs.find((a) => isTainted(a, file, REQ_TAINT) && !SANITIZED_PATH.test(text(a, file)));
    if (bad) report(node, { evidence: `${fn}(${text(bad, file).slice(0, 80)})` });
  },
});

export const objectAssignUserInput = defineRule({
  id: 'sast.object-assign-user-input',
  title: 'Request data is copied wholesale onto an object',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-915'],
  asvs: ['V15.3.3'],
  exploitability: 'requires-auth',
  description: 'Object.assign() or a spread copies the raw request body onto a record (mass assignment).',
  impact: 'Any field the client sends — role, ownerId, isAdmin, price — ends up on the record.',
  fix: 'Validate with a strict zod schema and copy only the fields you expect (const { title, body } = req.valid.body).',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (ts.isCallExpression(node) && calleeName(node) === 'Object.assign') {
      const bad = node.arguments.slice(1).find((a) => RAW_REQ_TAINT.test(text(a, file)));
      if (bad) report(node, { evidence: `Object.assign(..., ${text(bad, file)})` });
    } else if (ts.isSpreadAssignment(node) && RAW_REQ_TAINT.test(text(node.expression, file))) {
      report(node, { evidence: `{ ...${text(node.expression, file)} }` });
    }
  },
});

export const protoPollutionMerge = defineRule({
  id: 'sast.proto-pollution-merge',
  title: 'A deep merge can be poisoned with __proto__',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-1321'],
  asvs: ['V15.3.6'],
  exploitability: 'requires-auth',
  description: 'Request data is deep-merged into an object, or a hand-written merge copies keys without excluding __proto__ / constructor.',
  impact: 'A crafted body like {"__proto__":{"isAdmin":true}} changes every object in the process (prototype pollution).',
  fix: 'Do not merge request data; validate it with a strict schema and copy known fields. In merge helpers skip __proto__, constructor and prototype keys.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      if (tail && MERGE_FUNCTIONS.test(tail) && node.arguments.some((a) => RAW_REQ_TAINT.test(text(a, file)))) {
        report(node, { evidence: `${tail}() receives raw request data` });
      }
      return;
    }
    if (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      const name = ts.isFunctionDeclaration(node) && node.name ? node.name.text : (assignedName(node) ?? '');
      if (!/merge|extend|assign/i.test(name) || !node.body) return;
      const body = text(node.body, file);
      if (!/for\s*\(\s*(const|let|var)\s+\w+\s+in\b/.test(body)) return;
      if (!/\w+\[\s*\w+\s*\]\s*=/.test(body)) return;
      if (/__proto__|hasOwn|Object\.keys|constructor|prototype/.test(body)) return;
      report(node, { confidence: 'medium', evidence: `${name}() copies keys with for-in without guarding __proto__` });
    }
  },
});

const reportedStatements = new WeakMap<ts.SourceFile, Set<number>>();

export const passwordCompositionRule = defineRule({
  id: 'sast.password-composition-rule',
  title: 'Passwords must follow composition rules',
  severity: 'low',
  confidence: 'medium',
  cwe: ['CWE-521'],
  asvs: ['V6.2.5'],
  exploitability: 'theoretical',
  description: 'A password rule requires character mixes (uppercase, digits, symbols).',
  impact: 'Composition rules push people towards predictable patterns and do not improve strength; length and a common-password check do.',
  fix: 'Remove the composition rule. Keep the template policy: 12–256 characters, no common passwords, no trimming.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    let hit: string | undefined;
    if (ts.isRegularExpressionLiteral(node)) {
      const lookaheads = (node.text.match(/\(\?=/g) ?? []).length;
      const statement = text(enclosingStatement(node), file);
      if (lookaheads >= 2 || (lookaheads === 1 && /passw/i.test(statement))) hit = `pattern ${node.text.slice(0, 60)}`;
    } else if (ts.isStringLiteral(node) && /must (contain|include|have) (at least )?(an? |one )?(uppercase|upper-case|capital|lowercase|number|digit|symbol|special)/i.test(node.text)) {
      hit = `message "${node.text.slice(0, 60)}"`;
    }
    if (!hit) return;
    const stmt = enclosingStatement(node);
    let set = reportedStatements.get(file.sf);
    if (!set) {
      set = new Set();
      reportedStatements.set(file.sf, set);
    }
    if (set.has(stmt.pos)) return;
    set.add(stmt.pos);
    report(node, { evidence: `Composition rule: ${hit}` });
  },
});

export const inputRules = [unsafeRegex, regexFromUserInput, pathJoinUserInput, fsUserPath, objectAssignUserInput, protoPollutionMerge, passwordCompositionRule];
