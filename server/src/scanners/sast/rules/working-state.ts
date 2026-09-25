/**
 * A button that asks the assistant takes seconds to answer, and a person who cannot tell a slow answer from a broken
 * button presses it again, which pays for the answer twice. SC-26 tells the generation agent that such a form carries
 * `data-working="…"`, which the shared script in public/js/app.js turns into a disabled button and a spoken message.
 * This rule is the check that convention lacked: it finds the pages the agent wrote and looks.
 *
 * What it can and cannot see, so nobody reads a clean scan as more than it is:
 *  - It knows a route "asks the assistant" only when the route's handler (or a function in the same file it calls)
 *    uses something imported from the assistant's own client or providers. A page that reaches a model some other way,
 *    or a slow route that has nothing to do with the assistant, is not found.
 *  - It checks that the form carries `data-working`. It does not check the sentence about the wait that SC-26 also
 *    asks for; a sentence cannot be judged by a pattern.
 *  - It reads the pages SecureVibe did not take from the template. The template's own assistant page is checked by
 *    the template's own tests.
 */
import { posix } from 'node:path';
import ts from 'typescript';
import { calleeTail, propertyName, resolveObjectLiteral, stringValue, type EjsFile, type TsFile } from '../engine.js';
import { defineRule } from './base.js';

/** The assistant's own client and provider modules, as a resolved path without its extension. */
const AI_CLIENT_MODULE = /(^|\/)features\/ai\/(client|providers)$/;

interface AssistantRoute {
  path: string;
  file: string;
}

function resolvedModule(fromFile: string, specifier: string): string {
  const joined = specifier.startsWith('.') ? posix.join(posix.dirname(fromFile), specifier) : specifier;
  return joined.replace(/\.(m|c)?[jt]sx?$/, '');
}

/** The local names in a file that were imported from the assistant's client or providers. */
function assistantNames(file: TsFile): Set<string> {
  const names = new Set<string>();
  for (const imp of file.imports) {
    if (!AI_CLIENT_MODULE.test(resolvedModule(file.relPath, imp.specifier))) continue;
    for (const local of imp.names.keys()) names.add(local);
  }
  return names;
}

/** Whether `node` uses one of `names`, directly or through a function declared in the same file that it calls. */
function uses(node: ts.Node, names: Set<string>, file: TsFile, seen = new Set<ts.Node>()): boolean {
  if (seen.has(node)) return false;
  seen.add(node);
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(n) && names.has(n.text)) {
      found = true;
      return;
    }
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)) {
      const declared = file.functions.get(n.expression.text);
      if (declared && uses(declared, names, file, seen)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

function assistantRoutes(file: TsFile): AssistantRoute[] {
  const names = assistantNames(file);
  if (names.size === 0) return [];
  const routes: AssistantRoute[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && calleeTail(node) === 'defineRoute') {
      const spec = resolveObjectLiteral(node.arguments[1], file);
      const prop = (key: string) => (spec?.properties.find((p) => p.name && propertyName(p.name) === key) as ts.PropertyAssignment | undefined)?.initializer;
      const method = stringValue(prop('method'));
      const path = stringValue(prop('path'));
      const handler = node.arguments[node.arguments.length - 1];
      if (method?.toUpperCase() === 'POST' && path && handler && uses(ts.isIdentifier(handler) ? (file.functions.get(handler.text) ?? handler) : handler, names, file)) {
        routes.push({ path, file: file.relPath });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file.sf);
  return routes;
}

/** Same route: every segment equal, where a `:parameter` (or a value the template fills in) matches any segment. */
function sameRoute(routePath: string, actionPath: string): boolean {
  const a = routePath.split('/');
  const b = actionPath.split('/');
  return a.length === b.length && a.every((seg, i) => seg === b[i] || seg.startsWith(':') || b[i]!.startsWith(':'));
}

interface PostForm {
  line: number;
  column: number;
  action: string;
  working: boolean;
  snippet: string;
}

function postForms(file: EjsFile): PostForm[] {
  const forms: PostForm[] = [];
  const re = /<form\b[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(file.doc.masked)) !== null) {
    const tag = file.text.slice(m.index, m.index + m[0].length); // the same offsets, with the EJS tags still in
    if (!/\bmethod\s*=\s*["']?post\b/i.test(tag)) continue;
    const action = /\baction\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
    const value = action?.[1] ?? action?.[2];
    if (!value) continue;
    // Whatever the template fills in (an id, say) stands for one path segment.
    const path = (value.split(/[?#]/)[0] ?? '').replace(/<%[\s\S]*?%>/g, ':filled');
    forms.push({ line: file.doc.lineOf(m.index), column: file.doc.columnOf(m.index), action: path, working: /\bdata-working\b/i.test(tag), snippet: tag.replace(/\s+/g, ' ').slice(0, 200) });
  }
  return forms;
}

export const assistantFormNoWorkingState = defineRule({
  id: 'sast.assistant-form-no-working-state',
  title: 'A button that asks the assistant does not say it is working',
  severity: 'low',
  confidence: 'medium',
  cwe: [],
  asvs: [],
  exploitability: 'theoretical',
  description:
    'A page has a form that sends a question to the assistant, but the form does not carry data-working="…". The assistant can take many seconds to answer, and without a message the person cannot tell a slow answer from a broken button.',
  impact: 'The first thing anyone does is press the button again, and every press is a separate request to the AI service, paid for from the owner’s credit.',
  fix: 'Add data-working="Asking the assistant…" to the form, and say in plain words next to the button how long an answer can take.',
  steps: [
    'Open the view that holds the form and add data-working="Asking the assistant…" to the <form> tag: the shared script then disables the button and announces the message.',
    'Add a sentence next to the button, such as “An answer can take up to a minute; you do not need to press Ask again.” It is what a person without JavaScript has to go on.',
  ],
  howToConfirmFixed: 'Run the check again: the form is no longer reported.',
  appliesTo: ['ts', 'ejs'],
  checkTree(tree, report) {
    const routes: AssistantRoute[] = [];
    for (const file of tree.files) {
      if (file.kind !== 'ts' || file.isTest || file.origin === 'template') continue;
      routes.push(...assistantRoutes(file));
    }
    if (routes.length === 0) return;
    for (const file of tree.files) {
      if (file.kind !== 'ejs' || file.origin === 'template') continue;
      for (const form of postForms(file)) {
        if (form.working) continue;
        const route = routes.find((r) => sameRoute(r.path, form.action));
        if (!route) continue;
        report(file.relPath, {
          line: form.line,
          column: form.column,
          snippet: form.snippet,
          evidence: `The form at line ${form.line} posts to ${route.path}, which asks the assistant (${route.file}), and has no data-working`,
          fingerprintExtra: form.action,
        });
      }
    }
  },
});

export const workingStateRules = [assistantFormNoWorkingState];
