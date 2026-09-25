/**
 * Output encoding and template safety (contract §1.4, TPL-VALIDATE-01): what a person types is stored as typed and
 * only made safe at the moment it is written into a page, and no page is ever built from it.
 *
 * The account name is the free-text value every signed-in person can set that the app writes back into HTML (the
 * account page and the "Signed in as" line on every page). It allows every printable character, so it is the
 * hostile input these tests use.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { startApp, type RunningApp } from '../helpers/app.ts';
import { paths, users } from '../helpers/conventions.ts';

describe('output encoding', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  /** Sets the signed-in member's name, then returns what the account page and the profile form render. */
  async function renderWithName(name: string): Promise<{ account: string; form: string; stored: string | null }> {
    const jar = await app.login(users.member);
    const save = await app.submitForm(paths.profile, { name }, jar);
    await save.text();
    assert.ok(save.status < 400, `the name was not accepted (status ${save.status}), so the test would prove nothing`);
    const account = await app.page(paths.account, jar);
    const form = await app.page(paths.profile, jar);
    assert.equal(account.res.status, 200);
    const stored = (app.userByEmail(users.member)?.name as string | null | undefined) ?? null;
    return { account: account.html, form: form.html, stored };
  }

  test('V1.1.2 output is encoded as the final step before it reaches the browser: stored as typed, escaped when written into the page', async () => {
    const typed = `<b onclick=alert(1)>7 & 8</b> "quoted" 'single'`;
    const { account, form, stored } = await renderWithName(typed);
    // Not encoded on the way in: the database holds exactly what was typed, so it can be encoded for any output later.
    assert.equal(stored, typed, 'the value must be stored as typed, not pre-encoded');
    // Encoded on the way out, for the HTML text position (account page) and the attribute position (profile form).
    assert.ok(account.includes('&lt;b onclick=alert(1)&gt;7 &amp; 8&lt;/b&gt;'), 'the account page must HTML-encode the value');
    assert.equal(account.includes('<b onclick'), false, 'the raw markup must never reach the page');
    assert.ok(/value="[^"]*&lt;b onclick=alert\(1\)&gt;[^"]*&#34;quoted&#34;/.test(form) || /value="[^"]*&lt;b onclick=alert\(1\)&gt;[^"]*&quot;quoted&quot;/.test(form), 'inside an attribute the quotes must be encoded too, or the value could close the attribute');
    assert.equal(/value="[^"]*"quoted"/.test(form), false, 'an unencoded double quote would end the attribute early');
  });

  test('V1.3.7 templates are never built from untrusted input: template syntax in a value is shown as text and never evaluated', async () => {
    // 7*191 = 1337 is not a number that appears on these pages, so its presence would mean something evaluated it.
    const payloads = ['<%= 7*191 %>', '<%- 7*191 %>', '<% throw new Error("x") %>', '{{7*191}}', '${7*191}', '#{7*191}'];
    const { account, form } = await renderWithName(payloads.join(' '));
    for (const html of [account, form]) {
      assert.equal(html.includes('1337'), false, 'a template expression in the value was evaluated');
      assert.equal(html.includes('Error: x'), false, 'template code in the value was executed');
    }
    assert.ok(account.includes('&lt;%= 7*191 %&gt;'), 'EJS syntax must be shown as escaped text');
    assert.ok(account.includes('{{7*191}}') && account.includes('${7*191}'), 'other template syntaxes must be shown literally, not interpreted');
    // And the page still works for the next request: nothing was left broken by the value.
    const again = await app.page(paths.account, await app.login(users.member));
    assert.equal(again.res.status, 200);
  });

  test('V1.2.3 a value can neither break out of a script element nor become JavaScript or JSON: no user value is written into script content', async () => {
    // (An end tag may carry whitespace or even attributes, and browsers still accept it, so the patterns below allow both.)
    // The pages build no JavaScript from data, so the proof is that even a value written to close a script element
    // and start another, or to break a JavaScript string or a JSON document, is inert: it appears only as escaped
    // text, and no <script> element carries any part of it.
    const hostile = `</script><script>window.__pwned=1</script>";alert(1);//\\u2028'}]}`;
    const { account, form } = await renderWithName(hostile);
    for (const html of [account, form]) {
      const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script[^>]*>/gi)];
      for (const s of scripts) {
        assert.equal(/__pwned|alert\(1\)|\\u2028/.test(s[1] ?? ''), false, `user text reached a <script> element: ${(s[1] ?? '').slice(0, 80)}`);
      }
      assert.equal(html.includes('<script>window.__pwned'), false, 'an injected script element must not exist');
      assert.equal(/<script\b(?![^>]*\bsrc=)[^>]*>(?!\s*<\/script[^>]*>)/i.test(html), false, 'no page may carry an inline script that could hold data');
    }
    assert.ok(account.includes('&lt;/script&gt;&lt;script&gt;window.__pwned=1&lt;/script&gt;'), 'the value must appear as escaped text');
  });
});
