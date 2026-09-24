/**
 * A theme name goes into an HTML attribute, so an unknown one must be refused rather than written into the page.
 *
 * This is the only part of the theme work that cites a requirement: AS-07 in the Secure by Design checklist. The
 * rest — that every theme is defined, that every pair of colors is readable, that no color escapes a theme — was
 * named `UX-01`, which exists in no framework file and no knowledge file. Those tests are worth keeping and are now
 * in `tests/theme.test.ts` under names that say what they show. A test in this folder must cite a requirement, and
 * a citation to nothing is worse than no citation: it reads as verified and indexes nothing.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { expectStartupRefusal } from '../helpers/app.ts';

describe('themes', () => {
  test('AS-07 unknown theme: the app refuses to start instead of writing the value into the page', async () => {
    const failure = await expectStartupRefusal({ APP_THEME: 'orange"><script>' });
    assert.match(failure.stderr, /APP_THEME/);
    assert.ok(!failure.stderr.includes('<script>'), 'the refusal must not echo the value back');
  });
});
