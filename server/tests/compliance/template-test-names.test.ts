/**
 * Holds SecureVibe's *own* template tests to the rule it holds generated apps to: a test named after a
 * requirement must say something that requirement says.
 *
 * The checker already exists and already runs, but only against a built app — so the first sight of a bad name
 * is a golden-app regression twenty-five minutes into an evaluation, attributed to whatever else changed in the
 * same commit. That is exactly how it went on 20 September 2026: eight newly written template tests were named
 * after V1.2.4 and V8.2.2, all five golden apps regressed by eight medium findings each, and the obvious
 * suspect was the SQL the new code was building rather than the names on its tests.
 *
 * This runs the same function over the same text in about a second.
 *
 * `ACCEPTED` is the honest part. About a third of the checker's flags are tests that are real and simply
 * phrased in different words, and rewording an honest test to satisfy a word-overlap check would be gaming it.
 * So each accepted flag is listed here with the reason it is accepted, and anything not on the list fails. The
 * list is meant to be argued with and to shrink; adding to it is a decision, not a formality.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { matchesRequirement, testBody } from '../../src/compliance/test-name-match.js';
import { loadFrameworks, loadKnowledge } from '../../src/frameworks/index.js';

const TEMPLATE_TESTS = join(import.meta.dirname, '../../../templates/secure-web-app/tests/security');

/**
 * Flags we have looked at and accepted, each with why. The key is the exact test name.
 * Shrinking this list is always an improvement; growing it needs a reason a person would agree with.
 */
const ACCEPTED: Record<string, string> = {
  "C5.2.1 app data reaches the model only through user-scoped repositories: other users' records are filtered out":
    'C5.2.1 is written about training data and model inputs in the abstract; this test checks the concrete thing that matters for this app, that the assistant reads through the same owner-scoped repositories as everything else.',
  'V7.4.1 a refused key is reported without the key and marks the assistant unavailable':
    'V7.4.1 is worded about error handling and logging; the test is about exactly that, in the words an owner would use rather than the standard’s.',
  'V8.2.2 administrators bypass ownership checks only where the registry allows it':
    'V8.2.2 is worded around IDOR and object-level authorization; "ownership check" and "registry" are this template’s names for precisely that mechanism.',
  'V15.2.2 scheduler jobs are declared in code, never accept user input, and run under a lease that is always released':
    'V15.2.2 is worded about scheduled task configuration; the vocabulary differs but the test checks the declared-in-code property the requirement asks for.',
  'V8.2.2 downloads are owner-only (administrators may read, other users may not)':
    'The same V8.2.2 vocabulary gap: this is the object-level authorization check, written in the words the uploads feature uses.',
};

interface Flagged {
  file: string;
  name: string;
  id: string;
}

function requirementIdOf(name: string): string | undefined {
  return /^((?:V|C|AC\.)\d+\.\d+\.\d+)/.exec(name)?.[1];
}

/** Every `test('…')` name in a file. The template's own suite check already enforces that they are literals. */
function testNames(source: string): string[] {
  return [...source.matchAll(/\btest\(\s*'((?:[^'\\]|\\.)*)'/g)].map((m) => m[1]!.replace(/\\'/g, "'").replace(/\\\\/g, '\\'));
}

describe('the template’s own test names', () => {
  it('each test named after a requirement says something that requirement says', () => {
    const frameworks = loadFrameworks();
    const knowledge = loadKnowledge();
    const flagged: Flagged[] = [];
    let checked = 0;

    for (const file of readdirSync(TEMPLATE_TESTS).filter((f) => f.endsWith('.test.ts'))) {
      const source = readFileSync(join(TEMPLATE_TESTS, file), 'utf8');
      for (const name of testNames(source)) {
        const id = requirementIdOf(name);
        if (!id) continue;
        const description = frameworks.getRequirement(id)?.description;
        if (!description) continue;
        checked += 1;
        const plain = knowledge.requirementsPlain[id]?.plain;
        const text = `${name.slice(id.length)}\n${testBody(source, name)}`;
        const verdict = matchesRequirement(text, { description, ...(plain ? { plain } : {}) });
        if (verdict.match === 'unsupported' && !(name in ACCEPTED)) flagged.push({ file, name, id });
      }
    }

    // A silent pass because nothing was read would be worse than a failure.
    expect(checked).toBeGreaterThan(50);
    expect(
      flagged.map((f) => `${f.file}: "${f.name}" says nothing that ${f.id} says — rename it, move it out of tests/security/, or add it to ACCEPTED with a reason`),
    ).toEqual([]);
  });

  it('every accepted exception still names a test that exists', () => {
    // An entry left behind after its test was renamed is an exception nobody is checking any more.
    const names = new Set<string>();
    for (const file of readdirSync(TEMPLATE_TESTS).filter((f) => f.endsWith('.test.ts'))) {
      for (const name of testNames(readFileSync(join(TEMPLATE_TESTS, file), 'utf8'))) names.add(name);
    }
    expect(Object.keys(ACCEPTED).filter((name) => !names.has(name))).toEqual([]);
  });
});
