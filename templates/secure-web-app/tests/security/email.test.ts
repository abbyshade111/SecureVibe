/**
 * Mail delivery (contract "Mailer", TPL-EMAIL-01). `V1.3.11` (header injection through the outbox) is exercised
 * end-to-end in outbound.test.ts via the app's own forgot-password flow; this file tests src/lib/mailer.ts
 * directly — the file-mode outbox writer, SMTP_URL parsing, the SMTP-unreachable fallback, and the
 * templates-only-from-disk rule for the optional email templating helper — without needing a network listener.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateEnv, moduleUrl, runSnippet } from '../helpers/app.ts';
import { featureFromFile, skipReason } from '../helpers/features.ts';

// With email switched off the scaffolder removes src/lib/mailer.ts, so these tests have nothing to exercise.
const emailEnabled = featureFromFile('email') !== false;

interface SnippetRun {
  dataDir: string;
  /** The last JSON line the snippet printed with console.log(JSON.stringify(...)), if any. */
  json: unknown;
}

async function run(code: string, extraEnv: Record<string, string> = {}): Promise<SnippetRun> {
  const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-mailer-'));
  const result = await runSnippet(code, { ...generateEnv(dataDir), ...extraEnv }, 20_000);
  if (result.code !== 0) {
    rmSync(dataDir, { recursive: true, force: true });
    throw new Error(`snippet failed (exit ${result.code}):\n${result.stdout}\n${result.stderr}`);
  }
  const line = result.stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1);
  return { dataDir, json: line ? JSON.parse(line) : undefined };
}

describe('email', () => {
  test('V1.3.11 the file mailer writes a well-formed, header-safe .eml when no SMTP server is configured', async (t) => {
    if (!emailEnabled) return t.skip(skipReason('email'));
    const { dataDir } = await run(`
      import { sendMail } from ${JSON.stringify(moduleUrl('src/lib/mailer.ts'))};
      await sendMail({ to: 'user@example.com', subject: 'Hi\\r\\nBcc: evil@example.com', text: 'Body.' });
      console.log('done');
    `);
    try {
      const dir = join(dataDir, 'outbox');
      const files = readdirSync(dir);
      assert.equal(files.length, 1);
      const content = readFileSync(join(dir, files[0]!), 'utf8');
      const header = content.split(/\r?\n\r?\n/)[0] ?? '';
      assert.doesNotMatch(header, /^bcc:/im, 'a CR/LF in the subject must not inject a Bcc header');
      assert.equal((header.match(/^subject:/gim) ?? []).length, 1);
      for (const line of header.split(/\r?\n/)) assert.doesNotMatch(line, /[\r\n]/);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  test('V1.3.11 SMTP_URL is parsed into host/port/credentials and rejects a non-SMTP scheme', async (t) => {
    if (!emailEnabled) return t.skip(skipReason('email'));
    const { dataDir, json } = await run(`
      import { parseSmtpUrl } from ${JSON.stringify(moduleUrl('src/lib/mailer.ts'))};
      const plain = parseSmtpUrl('smtp://user:pass@mail.example.com:2525');
      const secure = parseSmtpUrl('smtps://mail.example.com');
      let rejected = false;
      try { parseSmtpUrl('http://mail.example.com'); } catch { rejected = true; }
      console.log(JSON.stringify({ plain, secure, rejected }));
    `);
    rmSync(dataDir, { recursive: true, force: true });
    const result = json as { plain: { host: string; port: number; secure: boolean; user?: string; pass?: string }; secure: { host: string; port: number; secure: boolean }; rejected: boolean };
    assert.equal(result.plain.host, 'mail.example.com');
    assert.equal(result.plain.port, 2525);
    assert.equal(result.plain.secure, false);
    assert.equal(result.plain.user, 'user');
    assert.equal(result.plain.pass, 'pass');
    assert.equal(result.secure.port, 465, 'smtps:// without an explicit port must default to 465');
    assert.equal(result.secure.secure, true);
    assert.equal(result.rejected, true, 'a non smtp(s):// URL must be rejected');
  });

  test('V1.3.11 when the configured (and allow-listed) SMTP server cannot be reached, the message still reaches the outbox', async (t) => {
    if (!emailEnabled) return t.skip(skipReason('email'));
    const { dataDir } = await run(
      `
      import { sendMail } from ${JSON.stringify(moduleUrl('src/lib/mailer.ts'))};
      await sendMail({ to: 'user@example.com', subject: 'Unreachable SMTP', text: 'Body.' });
      console.log('{"done":true}');
    `,
      { SMTP_URL: 'smtp://127.0.0.1:1', OUTBOUND_ALLOWED_HOSTS: '127.0.0.1:1' },
    );
    const dir = join(dataDir, 'outbox');
    const ok = existsSync(dir) && readdirSync(dir).length === 1;
    rmSync(dataDir, { recursive: true, force: true });
    assert.ok(ok, 'delivery must fall back to the outbox rather than lose the message');
  });

  test('V13.2.4 an SMTP host not on OUTBOUND_ALLOWED_HOSTS is refused, exactly like any other outbound destination', async (t) => {
    if (!emailEnabled) return t.skip(skipReason('email'));
    const { dataDir } = await run(
      `
      import { sendMail } from ${JSON.stringify(moduleUrl('src/lib/mailer.ts'))};
      await sendMail({ to: 'user@example.com', subject: 'Not allow-listed', text: 'Body.' });
      console.log('{"done":true}');
    `,
      { SMTP_URL: 'smtp://mail.example.com:587', OUTBOUND_ALLOWED_HOSTS: '' },
    );
    const dir = join(dataDir, 'outbox');
    const ok = existsSync(dir) && readdirSync(dir).length === 1;
    rmSync(dataDir, { recursive: true, force: true });
    assert.ok(ok, 'a blocked SMTP host must still fall back to the outbox rather than lose the message');
  });

  test('V1.3.11 email templates are only ever read from src/views/email/*.ejs, HTML-escaped, never built from string concatenation', async (t) => {
    if (!emailEnabled) return t.skip(skipReason('email'));
    const { dataDir, json } = await run(`
      import { renderEmailTemplate } from ${JSON.stringify(moduleUrl('src/lib/mailer.ts'))};
      const rendered = renderEmailTemplate('example', { name: '<script>alert(1)</script>', body: 'a & b' });
      let pathRejected = false;
      try { renderEmailTemplate('../../../etc/passwd', {}); } catch { pathRejected = true; }
      console.log(JSON.stringify({ rendered, pathRejected }));
    `);
    rmSync(dataDir, { recursive: true, force: true });
    const result = json as { rendered: string; pathRejected: boolean };
    assert.match(result.rendered, /Hello &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(result.rendered, /a &amp; b/);
    assert.equal(result.pathRejected, true, 'a template name that is not a plain identifier must be refused, not read from an arbitrary path');
  });
});
