/**
 * Does a test check the thing its name claims?
 *
 * A test whose name begins with a requirement id becomes strong evidence for that requirement. The name alone
 * decides it, which means a wrong name mints a verified requirement out of nothing. That is not hypothetical: a
 * generated test called "V2.3.3 the list never returns an unbounded result set" was the only passing evidence for
 * V2.3.3 in every app built to level 2, and V2.3.3 is about transactions being all-or-nothing. It checked the page
 * size. The requirement read as verified for months on the strength of a label.
 *
 * This compares the words of the test, its name and its own lines, with the words of the requirement it names,
 * taking both the standard's own wording and SecureVibe's plain-language rendering of it. Sharing nothing at all is
 * the signal: a test that never says anything the requirement says is probably about something else.
 *
 * It reports; it does not decide. Measured against the golden apps, about a third of what it flags are honest tests
 * whose wording simply differs from the standard's — "administrators bypass ownership checks" against "data-specific
 * access is restricted to consumers with explicit permissions" is the same subject in different words. Silently
 * dropping those would understate an app's coverage, which is its own kind of dishonesty. So the requirement keeps
 * its credit and a finding puts the comparison in front of a person, who can tell the two cases apart in seconds.
 *
 * It is a word comparison, not comprehension. It catches a test talking about something else entirely, which is the
 * failure that has actually happened. It cannot catch a swap between two neighbouring requirements that share
 * vocabulary, and it never claims to.
 */

/** Words that appear in nearly every requirement, so sharing one says nothing. */
const IGNORED = new Set([
  'verify', 'that', 'this', 'the', 'a', 'an', 'is', 'are', 'be', 'been', 'being', 'and', 'or', 'not', 'no',
  'in', 'on', 'to', 'of', 'for', 'from', 'with', 'by', 'at', 'as', 'it', 'its', 'they', 'them', 'their',
  'application', 'app', 'apps', 'system', 'user', 'users', 'level', 'levels', 'such', 'only', 'all', 'any',
  'must', 'should', 'can', 'may', 'will', 'when', 'where', 'which', 'who', 'what', 'how', 'if', 'then', 'than',
  'so', 'but', 'also', 'more', 'most', 'other', 'others', 'each', 'every', 'one', 'two', 'used', 'use', 'uses',
  'using', 'make', 'makes', 'made', 'does', 'do', 'done', 'has', 'have', 'had', 'was', 'were', 'test', 'tests',
  'security', 'secure', 'check', 'checks', 'checked', 'ensure', 'ensures', 'place', 'against', 'into', 'out',
  'over', 'after', 'before', 'while', 'never', 'always', 'own', 'same', 'new', 'old', 'up', 'down', 'off',
]);

/** Words worth comparing: letters only, four or more characters, not boilerplate. Hyphens split. */
export function distinctiveWords(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.toLowerCase().split(/[^a-z]+/)) {
    const word = raw.trim();
    if (word.length < 4 || IGNORED.has(word)) continue;
    // Crude singular: "transactions" and "transaction" are the same word for this purpose.
    out.add(word.endsWith('s') && word.length > 4 ? word.slice(0, -1) : word);
  }
  return out;
}

/**
 * The lines of a test, for comparison. A name alone is often too thin: "login is limited per account" shares no
 * word with "credential stuffing and password brute force", though it plainly checks it. The body usually contains
 * the vocabulary the name leaves out.
 */
export function testBody(source: string, testName: string): string {
  // The runner reports "suite > test"; only the last part is the name written in the file.
  const own = testName.split(' > ').at(-1) ?? testName;
  const escaped = own.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // The name as it appears in the file: node:test takes it as the first argument, in quotes or backticks.
  const start = new RegExp(`(?:it|test)\\(\\s*['"\`]${escaped}['"\`]`).exec(source);
  if (!start) return '';
  const from = start.index;
  // Up to the end of that call, judged by the closing "});" at the same indentation, or 60 lines, whichever first.
  const lines = source.slice(from).split(/\r?\n/).slice(0, 60);
  const end = lines.findIndex((line, i) => i > 0 && /^\s{0,4}\}\)/.test(line));
  return (end === -1 ? lines : lines.slice(0, end + 1)).join('\n');
}

export interface RequirementWording {
  /** The standard's own wording. */
  description: string;
  /** SecureVibe's plain-language rendering, when it has one: it widens the vocabulary and cuts false alarms. */
  plain?: string;
}

export type NameMatch = 'supported' | 'unsupported';

export interface NameMatchResult {
  match: NameMatch;
  /** The words the test and the requirement have in common, for the finding's evidence line. */
  shared: string[];
}

/**
 * Whether `testText` (the test's name, and its body when available) says anything the requirement says.
 * A requirement SecureVibe has no wording for is never judged: it comes back supported.
 *
 * Callers must pass the same things the unit-tests stage passes, or the answer means nothing. Two mistakes cost
 * another session an afternoon of chasing names that were fine:
 *
 *  - Strip the requirement id off the front of the test name. Left on, it is just a token neither side shares,
 *    and it dilutes an already short name.
 *  - Pass both the standard's wording and SecureVibe's plain-language rendering of it. The standard's phrasing
 *    alone fails honest tests written in the plain words the reports use, which is most of them.
 *
 * `screenTestEvidence` in pipeline/stages/unit-tests.ts is the reference caller; copy what it does rather than
 * the shape of this signature.
 */
export function matchesRequirement(testText: string, wording: RequirementWording | undefined): NameMatchResult {
  if (!wording?.description) return { match: 'supported', shared: [] };
  const requirementWords = new Set([...distinctiveWords(wording.description), ...distinctiveWords(wording.plain ?? '')]);
  if (requirementWords.size === 0) return { match: 'supported', shared: [] };
  const shared = [...distinctiveWords(testText)].filter((w) => requirementWords.has(w));
  return { match: shared.length > 0 ? 'supported' : 'unsupported', shared };
}
