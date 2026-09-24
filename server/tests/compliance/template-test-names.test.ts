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
import { loadFrameworks, loadKnowledge, standardForId } from '../../src/frameworks/index.js';

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

/**
 * Tests in tests/security that cannot cite a requirement, named one at a time with why.
 *
 * Named rather than exempted by file, and the reason is this check's own history. `suite.test.ts` had been
 * enforcing that every test name *starts with* something id-shaped for weeks, which `UX-01` satisfied while
 * existing in no framework file — the shape was checked and the existence never was. Exempting the whole file
 * would re-open a door of exactly that kind one room along: anything added to it next month would be silently
 * uncited and nothing would say so. A list somebody has to add to deliberately, with a sentence per entry, is the
 * same mechanism as ACCEPTED below and for the same reason.
 */
const UNCITED_BY_DESIGN: Record<string, string> = {
  'security suite has at least one test file per security area and every test name starts with a requirement id':
    'The test asserting that the others cite requirements cannot cite one itself: its subject is the suite, not a control.',
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
  /*
   * A citation has to point at something.
   *
   * `UX-01` named four tests in the theme suite for weeks. It appears in no framework file, so it was credited to
   * nothing and screened by nothing — and the checker below could not see it either, because `requirementIdOf` only
   * recognizes the ASVS and AISVS shapes, so an unrecognised prefix is silently not-a-citation rather than a bad one.
   * A citation to nothing was indistinguishable from no citation at all, which is the zero-for-two-reasons failure
   * in the very check built to catch mislabelled tests.
   *
   * So this asserts the folder's own rule directly: a test in tests/security cites a requirement, and the
   * requirement exists. Secure by Design ids live in their own index, which is why this resolves through
   * standardForId rather than getRequirement alone — AS-07 and MT-07 are honest citations that getRequirement
   * cannot find.
   */
  it('every id a test cites resolves to a real requirement', () => {
    const frameworks = loadFrameworks();
    const unknown: string[] = [];
    const uncited: string[] = [];
    for (const file of readdirSync(TEMPLATE_TESTS).filter((f) => f.endsWith('.test.ts'))) {
      for (const name of testNames(readFileSync(join(TEMPLATE_TESTS, file), 'utf8'))) {
        if (UNCITED_BY_DESIGN[name] !== undefined) continue;
        const token = /^([A-Z]{1,3}[-.]?\d+(?:\.\d+)*)/.exec(name)?.[1];
        if (!token) {
          uncited.push(`${file}: ${name}`);
          continue;
        }
        const exists = standardForId(token) === 'sbd' ? frameworks.getSbdControl(token) !== undefined : frameworks.getRequirement(token) !== undefined;
        if (!exists) unknown.push(`${file}: ${token} — ${name}`);
      }
    }
    expect(unknown, 'these tests cite an id that exists in no framework file').toEqual([]);
    expect(uncited, 'a test in tests/security must cite a requirement, or belong in tests/ instead').toEqual([]);
  });

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
