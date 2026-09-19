/**
 * The live activity lines on the build page. An owner watching a slow, paid build had nothing to tell them it was
 * still working: the stage list moves every few minutes, so a build in progress looked exactly like a stuck one.
 * The messages were already arriving and being thrown away.
 */
import { describe, expect, it } from 'vitest';
import { plainActivity } from './BuildPage';

describe('what the build page says the agent is doing', () => {
  it('says it in words an owner can read', () => {
    expect(plainActivity('Claude is using write_file…')).toBe('Claude is writing a file…');
    expect(plainActivity('Claude is using run_checks…')).toBe('Claude is running the checks…');
  });

  it('degrades to the tool name rather than hiding a tool it does not know', () => {
    // A tool added later must still show something: silence is what this line exists to prevent.
    expect(plainActivity('Claude is using some_new_tool…')).toBe('Claude is using some new tool…');
  });

  it('drops the stage tag from a check message but keeps the message', () => {
    expect(plainActivity('[tests] Ran 227 tests from your app: 164 passed, 4 failed, 59 skipped.')).toBe(
      'Ran 227 tests from your app: 164 passed, 4 failed, 59 skipped.',
    );
  });
});
