/**
 * The check that a test does what its name claims. The case that prompted it is first: a test called
 * "V2.3.3 the list never returns an unbounded result set" that never went near a transaction.
 */
import { describe, expect, it } from 'vitest';
import { distinctiveWords, matchesRequirement, testBody } from '../../src/compliance/test-name-match.js';

const V2_3_3 = {
  description:
    'Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state.',
  plain: 'A change either happens completely or not at all: if part of it fails, the app puts everything back the way it was.',
};

const V6_2_1 = {
  description: 'Verify that user set passwords are at least 8 characters in length.',
  plain: 'Passwords must be at least 12 characters long. Longer passphrases are easier to remember and harder to guess.',
};

describe('does a test check what its name claims', () => {
  it('withholds credit from the test that started this: page size is not transactions', () => {
    const result = matchesRequirement('the list never returns an unbounded result set limit page records capped', V2_3_3);
    expect(result.match).toBe('unsupported');
    expect(result.shared).toEqual([]);
  });

  it('keeps credit for a test that really is about the requirement', () => {
    const rollback = matchesRequirement('a failed booking is rolled back and the record is unchanged afterwards', V2_3_3);
    expect(rollback.match).toBe('supported');
    expect(rollback.shared).toContain('rolled');

    const password = matchesRequirement('a password of 11 characters is refused', V6_2_1);
    expect(password.match).toBe('supported');
    expect(password.shared).toEqual(expect.arrayContaining(['password']));
  });

  it('accepts the plain-language wording too, so an honest test is not punished for different words', () => {
    // Nothing here appears in the standard's own sentence; it all appears in the plain rendering.
    const result = matchesRequirement('when part of the change fails the app puts everything back', V2_3_3);
    expect(result.match).toBe('supported');
  });

  it('judges nothing when SecureVibe has no wording for the requirement', () => {
    expect(matchesRequirement('anything at all', undefined).match).toBe('supported');
    expect(matchesRequirement('anything at all', { description: '' }).match).toBe('supported');
  });

  it('ignores the words that appear in every requirement', () => {
    const words = distinctiveWords('Verify that the application uses a secure transaction for every user');
    expect(words.has('verify')).toBe(false);
    expect(words.has('application')).toBe(false);
    expect(words.has('transaction')).toBe(true);
  });

  it('finds the lines of a test, even though the runner reports it with its suite in front', () => {
    const source = [
      "describe('db', () => {",
      "  test('V16.4.2 the database and data directory are private to the app user', async () => {",
      "    const mode = statSync(dataDir).mode;",
      "    assert.equal(mode & 0o077, 0, 'no other user may read the log');",
      '  });',
      '});',
    ].join('\n');
    // The runner calls it "db > V16.4.2 ..."; the file only ever holds the name itself.
    const body = testBody(source, 'db > V16.4.2 the database and data directory are private to the app user');
    expect(body).toContain('no other user may read the log');
    expect(testBody(source, 'db > a test that is not in this file')).toBe('');
  });
});
