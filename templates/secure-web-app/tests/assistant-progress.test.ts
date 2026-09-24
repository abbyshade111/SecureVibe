/**
 * A form that takes a while says so.
 *
 * The first person other than the owner to use SecureVibe pressed "Run research" and got nothing back until the
 * answer arrived — no progress, no acknowledgement, no way to tell a slow answer from a broken button. The first
 * thing anybody does about that is press it again, and when the button spends the owner's money, pressing twice
 * pays twice for one answer.
 *
 * No requirement id on these names, deliberately. This is not an access-control or an encoding property; it is the
 * page being honest about what it is doing. `tests/secrets.test.ts` set the precedent, and a name carrying an id
 * would credit some requirement with evidence from a button's label.
 *
 * What is asserted here is the half that works for everybody: the sentence in the page, and the attribute the
 * script reads. The disabling itself is JavaScript, which this suite does not run — so the test checks that the
 * page tells the truth without it, which is the more important half anyway.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { startApp, type RunningApp } from './helpers/app.ts';
import { featureFromFile, skipReason, templateRoot } from './helpers/features.ts';
import { users } from './helpers/conventions.ts';

describe('a form that takes a while', () => {
  let app: RunningApp;

  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  test('the assistant page says how long an answer can take, without needing JavaScript', async (t) => {
    if (!featureFromFile('ai')) return t.skip(skipReason('ai'));
    const jar = await app.login(users.member);
    const { res, html } = await app.page('/ai', jar);
    assert.equal(res.status, 200, 'the assistant page must be readable');

    // The sentence, not the behavior: this is what somebody with no JavaScript has to go on.
    assert.match(html, /can take up to a minute/i, 'the page must say that an answer takes a while');
    assert.match(html, /do not need to press Ask again/i, 'and that pressing again is not required');

    // The button is not disabled in what the server sends, or nobody could ask anything without JavaScript.
    const form = html.slice(html.indexOf('action="/ai"'), html.indexOf('</form>', html.indexOf('action="/ai"')));
    assert.ok(form.length > 0, 'the ask form must be on the page');
    assert.doesNotMatch(form, /<button[^>]*\sdisabled/i, 'the ask button must work without JavaScript');
  });

  test('the form tells the script what to say while it waits', async (t) => {
    if (!featureFromFile('ai')) return t.skip(skipReason('ai'));
    const jar = await app.login(users.member);
    const { html } = await app.page('/ai', jar);
    assert.match(html, /data-working="Asking the assistant/, 'the ask form must carry the message the script shows');
    // A live region, so the change is announced rather than only drawn.
    assert.match(html, /data-working-status/, 'and somewhere to announce it');
    assert.match(html, /aria-live="polite"/, 'which must be a live region');
  });

  test('the shared script reads the attribute, disables the button once and changes nothing else', () => {
    // Read rather than executed: this suite has no browser. What matters is that the behavior is declarative —
    // any form, including one the generation agent writes, gets it by carrying the attribute — and that it never
    // calls preventDefault, because a form that stops submitting is a broken button rather than a slow one.
    const script = readFileSync(join(templateRoot, 'public', 'js', 'app.js'), 'utf8');
    assert.match(script, /getAttribute\('data-working'\)/, 'the behavior must be driven by the attribute');
    assert.match(script, /button\.disabled = true/, 'and must stop a second press');
    const working = script.slice(script.indexOf("data-working'"));
    assert.doesNotMatch(working, /preventDefault/, 'it must not stop the form submitting');
  });
});
