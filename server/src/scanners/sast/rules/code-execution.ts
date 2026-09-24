/**
 * Rules about turning data into code: eval, new Function, the vm module, child processes,
 * unsafe deserialisation and XML external entities.
 */
import ts from 'typescript';
import { calleeName, isTainted, propertyName, REQ_TAINT, text, type TsFile } from '../engine.js';
import { defineRule, importsOf, isTrueLiteral, moduleFunctionOfCall } from './base.js';

const CHILD_PROCESS = ['child_process', 'node:child_process'];
const CHILD_PROCESS_FUNCTIONS = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);
const SERIALIZERS = ['node-serialize', 'serialize-to-js', 'funcster', 'cryo', 'js-yaml', 'yaml'];
const UNSAFE_DESERIALIZE_FUNCTIONS = new Set(['unserialize', 'deserialize', 'deepDeserialize', 'load', 'loadAll', 'parse']);

interface ChildProcessCall {
  node: ts.CallExpression;
  fn: string;
  tainted: boolean;
}

function childProcessCalls(file: TsFile): ChildProcessCall[] {
  const out: ChildProcessCall[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const fn = moduleFunctionOfCall(node, file, CHILD_PROCESS);
      if (fn && CHILD_PROCESS_FUNCTIONS.has(fn)) {
        out.push({ node, fn, tainted: node.arguments.some((a) => isTainted(a, file, REQ_TAINT)) });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file.sf);
  return out;
}

export const evalUsage = defineRule({
  id: 'sast.eval-usage',
  title: 'Code is run from text with eval()',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-95'],
  asvs: ['V1.3.2'],
  exploitability: 'requires-auth',
  description: 'The code calls eval(), which turns a piece of text into running program code.',
  impact: 'If any part of that text can be influenced by a user, they can run their own commands inside your app.',
  fix: 'Remove eval() and express the logic directly in code; parse data with JSON.parse and validate it with zod.',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    if (!ts.isCallExpression(node)) return;
    const name = calleeName(node);
    if (name === 'eval' || name === 'globalThis.eval' || name === 'window.eval') report(node);
  },
});

export const newFunction = defineRule({
  id: 'sast.new-function',
  title: 'Code is built from text with new Function()',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-95'],
  asvs: ['V1.3.2'],
  exploitability: 'requires-auth',
  description: 'The code uses new Function(...), which compiles text into a function at runtime, the same risk as eval().',
  impact: "Text that reaches that call can become arbitrary code running with the app's full permissions.",
  fix: 'Replace new Function() with a normal function or a lookup table of allowed operations.',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    if (!ts.isNewExpression(node) && !ts.isCallExpression(node)) return;
    const name = calleeName(node);
    if (name === 'Function' || name === 'globalThis.Function' || name === 'window.Function') report(node);
  },
});

export const vmModule = defineRule({
  id: 'sast.vm-module',
  title: 'The vm module is used to run code',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-94'],
  asvs: ['V1.3.2'],
  exploitability: 'requires-auth',
  description: "Node's vm module runs scripts from text. It is not a security sandbox: code inside it can escape and reach the whole app.",
  impact: 'Anyone who controls the script text can run their own code on the server.',
  fix: 'Remove the vm module; implement the behavior in normal code and validate inputs with zod.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    for (const imp of importsOf(file, ['vm', 'node:vm'])) report(imp.node, { evidence: `${file.relPath} imports "${imp.specifier}"` });
  },
});

export const childProcessExec = defineRule({
  id: 'sast.child-process-exec',
  title: 'The app starts operating-system commands',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-78'],
  asvs: ['V1.2.5'],
  exploitability: 'requires-auth',
  description: 'The code uses child_process to run programs on the computer that hosts the app.',
  impact: 'Running commands widens what a bug can do: a mistake in the command string can let someone run anything the app user can run.',
  fix: 'Avoid shelling out. If a command is essential, use execFile with a fixed program and an array of arguments, never a string built at runtime.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    // Setup scripts (gen-cert, setup) and the test harness start processes by design; request data never reaches them.
    if (file.isScript || file.isTest) return;
    const calls = childProcessCalls(file);
    const plain = calls.filter((c) => !c.tainted);
    for (const c of plain) report(c.node, { evidence: `${c.fn}() called at line ${file.sf.getLineAndCharacterOfPosition(c.node.getStart(file.sf)).line + 1}` });
    if (calls.length === 0) {
      for (const imp of importsOf(file, CHILD_PROCESS)) report(imp.node, { evidence: `${file.relPath} imports "${imp.specifier}"`, confidence: 'medium' });
    }
  },
});

export const childProcessUserInput = defineRule({
  id: 'sast.child-process-user-input',
  title: 'Request data reaches an operating-system command',
  severity: 'critical',
  confidence: 'high',
  cwe: ['CWE-78'],
  asvs: ['V1.2.5'],
  exploitability: 'trivial',
  description: 'Data from an incoming request is passed into a command that runs on the server (command injection).',
  impact: 'An attacker can append their own commands and take over the computer running the app.',
  fix: 'Never build commands from request data. Remove the command or use execFile with a fixed program and validated, allow-listed arguments.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    for (const c of childProcessCalls(file)) {
      if (c.tainted) report(c.node, { evidence: `${c.fn}() receives request data: ${text(c.node, file).slice(0, 160)}` });
    }
  },
});

export const deserializeUntrusted = defineRule({
  id: 'sast.deserialize-untrusted',
  title: 'Untrusted data is deserialised into objects or code',
  severity: 'critical',
  confidence: 'high',
  cwe: ['CWE-502'],
  asvs: ['V1.5.2'],
  exploitability: 'trivial',
  description: 'A serialization library that can rebuild functions or arbitrary objects is used on data the app did not create.',
  impact: 'Crafted input can execute code on the server when it is deserialised.',
  fix: 'Use JSON.parse plus a zod schema for untrusted data; remove libraries such as node-serialize.',
  appliesTo: ['ts'],
  checkFile(file, report) {
    const dangerous = importsOf(file, ['node-serialize', 'serialize-to-js', 'funcster', 'cryo']);
    let calls = 0;
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const fn = moduleFunctionOfCall(node, file, SERIALIZERS);
        const v8fn = moduleFunctionOfCall(node, file, ['v8', 'node:v8']);
        const tainted = node.arguments.some((a) => isTainted(a, file, REQ_TAINT));
        if (fn && UNSAFE_DESERIALIZE_FUNCTIONS.has(fn) && fn !== 'load' && fn !== 'loadAll' && fn !== 'parse') {
          calls += 1;
          report(node, { confidence: tainted ? 'high' : 'medium', evidence: `${fn}() ${tainted ? 'receives request data' : 'rebuilds objects from serialized text'}` });
        } else if (fn && (fn === 'load' || fn === 'loadAll' || fn === 'parse') && tainted) {
          // js-yaml / yaml: only dangerous when untrusted text is parsed with a custom (function-capable) schema.
          const optsText = node.arguments[1] ? text(node.arguments[1], file) : '';
          if (/DEFAULT_FULL_SCHEMA|customTags|schema/.test(optsText)) {
            calls += 1;
            report(node, { evidence: `${fn}() parses request data with a custom schema` });
          }
        } else if (v8fn === 'deserialize' && tainted) {
          calls += 1;
          report(node, { evidence: 'v8.deserialize() receives request data' });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
    if (calls === 0) {
      for (const imp of dangerous) report(imp.node, { confidence: 'medium', evidence: `${file.relPath} imports "${imp.specifier}"` });
    }
  },
});

const XXE_OPTIONS = new Set(['noent', 'dtdload', 'dtdvalid', 'resolveExternalEntities', 'expandEntities', 'resolveEntities', 'externalEntities', 'processExternalEntities']);

export const xmlExternalEntities = defineRule({
  id: 'sast.xml-external-entities',
  title: 'XML parsing allows external entities',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-611'],
  asvs: ['V1.5.1'],
  exploitability: 'requires-auth',
  description: 'An XML parser is configured to resolve external entities (for example `noent: true`).',
  impact: 'A crafted XML document can make the server read local files or call internal services.',
  fix: 'Turn external entity resolution off (remove `noent`/`dtdload` options) or avoid parsing XML from users.',
  appliesTo: ['ts'],
  visit(node, _file, report) {
    if (!ts.isPropertyAssignment(node)) return;
    const name = propertyName(node.name);
    if (name && XXE_OPTIONS.has(name) && isTrueLiteral(node.initializer)) report(node);
  },
});

export const codeExecutionRules = [evalUsage, newFunction, vmModule, childProcessExec, childProcessUserInput, deserializeUntrusted, xmlExternalEntities];
