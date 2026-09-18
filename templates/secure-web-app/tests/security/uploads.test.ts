/** File uploads (contract §1.10, TPL-UPLOAD-01..05). Skips when the uploads feature is off. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { CookieJar, extractCsrfToken, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';
import { skipReason } from '../helpers/features.ts';

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG_MAGIC = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00]);
const GIF_MAGIC = Buffer.from('GIF89a');

function png(size = 2048): Buffer {
  return Buffer.concat([PNG_MAGIC, Buffer.alloc(Math.max(0, size - PNG_MAGIC.length), 7)]);
}

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

describe('uploads', () => {
  let app: RunningApp;
  let enabled = false;
  let member: CookieJar;

  before(async () => {
    app = await startApp({ env: { UPLOAD_MAX_BYTES: '4096' } });
    enabled = await app.featureEnabled('uploads');
    if (enabled) member = await app.login(users.member);
  });
  after(async () => {
    await app?.stop();
  });

  /** Uploads one file and returns the response plus the record id when the upload was accepted. */
  async function upload(
    jar: CookieJar,
    file: { name: string; type: string; bytes: Buffer },
    opts: { app?: RunningApp } = {},
  ): Promise<{ res: Response; id?: string; text: string }> {
    const target = opts.app ?? app;
    const { html } = await target.page(paths.uploads, jar);
    const token = extractCsrfToken(html) ?? (await target.csrfToken(paths.account, jar));
    const form = new FormData();
    form.append(fields.csrf, token);
    form.append(fields.file, new Blob([new Uint8Array(file.bytes)], { type: file.type }), file.name);
    const res = await target.fetch(paths.uploads, { method: 'POST', jar, body: form, headers: { Accept: 'application/json, text/html' } });
    const text = await res.text();
    let id: string | undefined;
    if (/application\/json/.test(res.headers.get('content-type') ?? '')) {
      const body = JSON.parse(text) as Record<string, unknown>;
      id = String(body.id ?? (body.upload as Record<string, unknown> | undefined)?.id ?? (body.data as Record<string, unknown> | undefined)?.id ?? '') || undefined;
    }
    if (!id && isRedirect(res)) id = locationOf(res).match(/\/uploads\/([^/?#]+)/)?.[1];
    if (!id && res.status < 300) id = text.match(/\/uploads\/([0-9a-f-]{36})/)?.[1];
    return { res, id, text };
  }

  test('V5.2.1 uploads larger than UPLOAD_MAX_BYTES are aborted with 413', async (t) => {
    if (!enabled) return t.skip(skipReason('uploads'));
    const big = await upload(member, { name: 'big.png', type: 'image/png', bytes: png(64 * 1024) });
    assert.equal(big.res.status, 413, `oversized upload answered ${big.res.status}: ${big.text.slice(0, 200)}`);
    const ok = await upload(member, { name: 'small.png', type: 'image/png', bytes: png(2048) });
    assert.ok(ok.res.status < 400, `a small valid upload must be accepted: ${ok.res.status} ${ok.text.slice(0, 200)}`);
    assert.ok(ok.id, 'the accepted upload must yield an id');
    const stored = await app.waitForEvent('upload.stored');
    assert.ok(stored.length >= 1, 'upload.stored must be logged');
  });

  test('V5.2.2 the file type is checked by magic bytes, extension and declared type; dangerous types are refused', async (t) => {
    if (!enabled) return t.skip(skipReason('uploads'));
    const cases: { name: string; type: string; bytes: Buffer; why: string }[] = [
      { name: 'notes.txt', type: 'text/plain', bytes: png(), why: 'extension does not match the content' },
      { name: 'photo.png', type: 'image/png', bytes: Buffer.from('this is not a png at all, just text'), why: 'content does not match the extension' },
      { name: 'photo.png', type: 'image/jpeg', bytes: png(), why: 'declared type does not match the content' },
      { name: 'photo.jpg', type: 'image/jpeg', bytes: png(), why: 'jpg extension with png content' },
      { name: 'image.svg', type: 'image/svg+xml', bytes: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), why: 'svg is never allowed' },
      { name: 'page.html', type: 'text/html', bytes: Buffer.from('<html><script>alert(1)</script></html>'), why: 'html is never allowed' },
      { name: 'data.xml', type: 'application/xml', bytes: Buffer.from('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'), why: 'xml is never allowed' },
      { name: 'archive.zip', type: 'application/zip', bytes: Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(64)]), why: 'zip is never allowed' },
      { name: 'photo.png.html', type: 'image/png', bytes: png(), why: 'double extension' },
      { name: 'script.js', type: 'application/javascript', bytes: Buffer.from('alert(1)'), why: 'scripts are never allowed' },
      { name: 'photo', type: 'image/png', bytes: png(), why: 'missing extension' },
    ];
    for (const c of cases) {
      const r = await upload(member, c);
      assert.ok([400, 415, 422].includes(r.res.status), `${c.name} (${c.type}) was accepted with ${r.res.status} although ${c.why}`);
    }
    const rejected = await app.waitForEvent('upload.rejected');
    assert.ok(rejected.length >= 1 && rejected.every((e) => typeof e.reason === 'string'), 'upload.rejected must be logged with a reason');
    for (const good of [
      { name: 'ok.png', type: 'image/png', bytes: png() },
      { name: 'ok.jpg', type: 'image/jpeg', bytes: Buffer.concat([JPEG_MAGIC, Buffer.alloc(512)]) },
      { name: 'ok.gif', type: 'image/gif', bytes: Buffer.concat([GIF_MAGIC, Buffer.alloc(512)]) },
    ]) {
      const r = await upload(member, good);
      assert.ok(r.res.status < 400, `${good.name} must be accepted: ${r.res.status} ${r.text.slice(0, 200)}`);
    }
  });

  test('V5.3.2 stored files get random names outside the web root with mode 0600; the user-supplied name is never a path', async (t) => {
    if (!enabled) return t.skip(skipReason('uploads'));
    const hostile = '../../../evil<script>.png';
    const r = await upload(member, { name: hostile, type: 'image/png', bytes: png() });
    assert.ok(r.res.status < 400, `upload with a hostile name must still be accepted (sanitised): ${r.res.status} ${r.text.slice(0, 200)}`);
    assert.ok(r.id);
    const files = walk(join(app.dataDir, 'uploads'));
    assert.ok(files.length >= 1, 'files must be stored under DATA_DIR/uploads');
    for (const f of files) {
      assert.match(f.split('/').pop()!, /^[0-9a-f-]{36}(\.[a-z0-9]{1,5})?$/i, `stored name must be a random id, got ${f}`);
      assert.equal(statSync(f).mode & 0o777, 0o600, `${f} must be mode 0600`);
    }
    assert.ok(!walk(app.dataDir).some((f) => /evil/.test(f)), 'the original file name must not be used on disk');
    const publicDir = join(app.dataDir, '..', 'public');
    assert.ok(!walk(publicDir).some((f) => /uploads/.test(f)), 'uploads must not be written into the web root');
    const row = app.dbAll<{ original_name: string; mime: string; size: number; sha256: string }>('SELECT original_name, mime, size, sha256 FROM uploads WHERE id = ?', r.id)[0];
    assert.ok(row, 'a database row must describe the upload');
    assert.ok(!row.original_name.includes('/') && !row.original_name.includes('\\') && !row.original_name.includes('..'), `original_name must be sanitised: ${row.original_name}`);
    assert.ok(row.original_name.length <= 120);
    assert.equal(row.mime, 'image/png');
    assert.match(row.sha256, /^[0-9a-f]{64}$/);
    const served = await app.fetch(`/uploads/${files[0]!.split('/').pop()}`);
    await served.text();
    assert.ok(served.status !== 200 || (served.headers.get('content-disposition') ?? '').startsWith('attachment'), 'raw stored files must not be served as static assets');
  });

  test('V5.4.2 downloads are attachments with RFC 6266 encoded names, nosniff, a sandboxed CSP and no caching', async (t) => {
    if (!enabled) return t.skip(skipReason('uploads'));
    const name = 'we"ird ünïcode\r\nname.png';
    const r = await upload(member, { name, type: 'image/png', bytes: png() });
    assert.ok(r.id, `upload failed: ${r.res.status} ${r.text.slice(0, 200)}`);
    const dl = await app.fetch(paths.upload(r.id), { jar: member });
    const bytes = Buffer.from(await dl.arrayBuffer());
    assert.equal(dl.status, 200);
    assert.equal(dl.headers.get('content-type'), 'image/png', 'Content-Type must come from the stored record');
    const cd = dl.headers.get('content-disposition') ?? '';
    assert.match(cd, /^attachment;/, 'downloads must be attachments');
    const ascii = cd.match(/filename="([^"]*)"/)?.[1];
    assert.ok(ascii !== undefined, `Content-Disposition must carry an ASCII filename: ${cd}`);
    assert.match(ascii, /^[\x20-\x7e]*$/, 'the ASCII filename must be printable ASCII');
    assert.ok(!ascii.includes('"') && !ascii.includes('\\'), 'quotes and backslashes must be stripped from the ASCII filename');
    const extended = cd.match(/filename\*=UTF-8''([^;]+)/)?.[1];
    assert.ok(extended, `Content-Disposition must carry filename*=UTF-8'': ${cd}`);
    assert.ok(decodeURIComponent(extended).includes('ünïcode'), 'the extended filename must preserve Unicode via percent-encoding');
    assert.doesNotMatch(cd, /[\r\n]/, 'header injection through the file name');
    assert.equal(dl.headers.get('x-content-type-options'), 'nosniff');
    assert.match(dl.headers.get('content-security-policy') ?? '', /sandbox/, 'downloads must carry a sandbox CSP');
    const cc = (dl.headers.get('cache-control') ?? '').toLowerCase();
    assert.ok(cc.includes('no-store') && cc.includes('private'), `download Cache-Control must be private, no-store: ${cc}`);
    assert.ok(bytes.subarray(0, 8).equals(PNG_MAGIC), 'the downloaded bytes must be the stored file');
  });

  test('V8.2.2 downloads are owner-only (administrators may read, other users may not)', async (t) => {
    if (!enabled) return t.skip(skipReason('uploads'));
    const r = await upload(member, { name: 'private.png', type: 'image/png', bytes: png() });
    assert.ok(r.id);
    const other = await app.login(users.member2);
    const denied = await app.fetch(paths.upload(r.id), { jar: other });
    await denied.text();
    assert.ok([403, 404].includes(denied.status), `another user could download the file (${denied.status})`);
    const anon = await app.fetch(paths.upload(r.id));
    await anon.text();
    assert.ok([401, 403, 404].includes(anon.status) || isRedirect(anon), `anonymous download answered ${anon.status}`);
    const events = await app.waitForEvent('download.denied');
    assert.ok(events.length >= 1, 'download.denied must be logged');
  });

  test('V2.3.2 upload quota: per-user byte and count limits are enforced', async (t) => {
    if (!enabled) return t.skip(skipReason('uploads'));
    const quotaApp = await startApp({ env: { UPLOAD_MAX_BYTES: '4096', UPLOAD_USER_QUOTA_BYTES: '3000' } });
    try {
      const jar = await quotaApp.login(users.member);
      // Test mode seeds one sample file per user, so the quota is measured from that baseline.
      const baselineRows = quotaApp.dbAll<{ n: number }>('SELECT count(*) AS n FROM uploads')[0]?.n ?? 0;
      const baselineFiles = walk(join(quotaApp.dataDir, 'uploads')).length;
      const first = await upload(jar, { name: 'a.png', type: 'image/png', bytes: png(2048) }, { app: quotaApp });
      assert.ok(first.res.status < 400, `first upload within the quota must succeed: ${first.res.status} ${first.text.slice(0, 200)}`);
      const second = await upload(jar, { name: 'b.png', type: 'image/png', bytes: png(2048) }, { app: quotaApp });
      assert.ok([400, 403, 409, 413, 422, 429].includes(second.res.status), `an upload beyond the quota must be refused, got ${second.res.status}`);
      const rows = quotaApp.dbAll<{ n: number }>('SELECT count(*) AS n FROM uploads')[0]?.n ?? 0;
      assert.equal(Number(rows), Number(baselineRows) + 1, 'the refused upload must not be recorded');
      assert.equal(walk(join(quotaApp.dataDir, 'uploads')).length, baselineFiles + 1, 'the refused upload must not be kept on disk');
      const events = await quotaApp.waitForEvent('upload.rejected');
      assert.ok(events.some((e) => /quota/i.test(String(e.reason))), 'upload.rejected must state the quota as the reason');
    } finally {
      await quotaApp.stop();
    }
  });
});
