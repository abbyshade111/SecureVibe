/**
 * Upload probes (only when the uploads feature is on): size cap, type checks, storage outside the web root,
 * download headers, ownership and quota. The harness sets small UPLOAD_MAX_BYTES / UPLOAD_USER_QUOTA_BYTES so
 * these stay fast.
 */
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { extractCsrfToken, multipart, PNG_1X1, type HttpResponse } from '../http.js';
import { PROBE_UPLOAD_MAX_BYTES, PROBE_UPLOAD_QUOTA_BYTES } from '../harness.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule, type Session } from '../types.js';
import { fail, findRoute, hasParams, pass } from './util.js';

interface UploadResult {
  res: HttpResponse;
  id?: string;
}

function uploadRoute(ctx: ProbeContext): string | undefined {
  return ctx.paths.uploads ?? findRoute(ctx, (r) => r.method === 'POST' && /uploads?$/.test(r.path) && !hasParams(r))?.path;
}

function downloadPath(ctx: ProbeContext, id: string): string {
  const route = findRoute(ctx, (r) => r.method === 'GET' && /uploads?\/:/.test(r.path));
  return route ? route.path.replace(/:[A-Za-z0-9_]+\??/, id) : `${uploadRoute(ctx) ?? '/uploads'}/${id}`;
}

/** A PNG of about 1 KB (valid header, padding after the image data; only the first bytes are sniffed). */
function pngOfSize(bytes: number): Uint8Array {
  const out = new Uint8Array(Math.max(bytes, PNG_1X1.length));
  out.set(PNG_1X1);
  return out;
}

async function upload(ctx: ProbeContext, session: Session, file: { name: string; type: string; bytes: Uint8Array }): Promise<UploadResult> {
  const path = uploadRoute(ctx)!;
  const page = await ctx.http.get(path, { jar: session.jar });
  const token = extractCsrfToken(page.body) ?? (await ctx.csrf(session)) ?? '';
  const { body, contentType } = multipart({ _csrf: token }, { field: 'file', ...file });
  const res = await ctx.http.request(path, { method: 'POST', jar: session.jar, headers: { 'Content-Type': contentType, Accept: 'application/json, text/html' }, body });
  let id: string | undefined;
  const json = res.json<{ id?: string; upload?: { id?: string } }>();
  if (json) id = json.id ?? json.upload?.id;
  if (!id && res.status < 400) {
    const source = `${res.location()}\n${res.body}`;
    id = /uploads?\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i.exec(source)?.[1];
    if (!id && res.isRedirect()) {
      const list = await ctx.http.get(res.location() || path, { jar: session.jar });
      id = /uploads?\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i.exec(list.body)?.[1];
    }
  }
  return { res, id };
}

function ready(ctx: ProbeContext): { session: Session } | { reason: string } {
  if (!ctx.features.uploads) return { reason: 'the uploads feature is not enabled in this design' };
  if (!uploadRoute(ctx)) return { reason: 'no upload route is registered' };
  const session = ctx.sessions.get('member');
  if (!session) return { reason: 'the member account could not sign in' };
  return { session };
}

export const uploadOversize413: ProbeModule = {
  id: 'dast.upload.oversize-413',
  group: 'uploads',
  requirementIds: ['V5.2.1'],
  fallback: { title: 'Oversized uploads accepted', severity: 'medium', cwe: ['CWE-400'], description: 'A file larger than UPLOAD_MAX_BYTES was not refused with 413.', impact: 'Large uploads fill the disk and stall the app.', fix: 'Stream uploads through busboy with limits.fileSize and abort with 413.' },
  async run(ctx) {
    const r = ready(ctx);
    if ('reason' in r) return NOT_ATTEMPTED(r.reason);
    const expected = `a ${Math.round((PROBE_UPLOAD_MAX_BYTES * 1.5) / 1024)} KB file is refused with 413`;
    const { res } = await upload(ctx, r.session, { name: 'big.png', type: 'image/png', bytes: pngOfSize(Math.round(PROBE_UPLOAD_MAX_BYTES * 1.5)) });
    return res.status === 413 ? pass(expected, 'status 413', res) : fail(expected, `status ${res.status}`, res);
  },
};

export const uploadTypeMismatch415: ProbeModule = {
  id: 'dast.upload.type-mismatch-415',
  group: 'uploads',
  requirementIds: ['V5.2.2'],
  fallback: { title: 'File type not checked by content', severity: 'high', cwe: ['CWE-434'], description: 'A text file named .png with an image/png content type was accepted.', impact: 'Attackers upload scripts or HTML disguised as images.', fix: 'Sniff magic bytes and require them to match the extension and the declared type.' },
  async run(ctx) {
    const r = ready(ctx);
    if ('reason' in r) return NOT_ATTEMPTED(r.reason);
    const expected = 'a text file named .png declared as image/png is refused with 415 (or 400/422)';
    const { res } = await upload(ctx, r.session, { name: 'notreally.png', type: 'image/png', bytes: new TextEncoder().encode('this is not a png file at all, just text') });
    return [400, 415, 422].includes(res.status) ? pass(expected, `status ${res.status}`, res) : fail(expected, `status ${res.status}`, res);
  },
};

export const uploadSvgRefused: ProbeModule = {
  id: 'dast.upload.svg-refused',
  group: 'uploads',
  requirementIds: ['V5.2.2', 'V1.3.4'],
  fallback: { title: 'SVG uploads accepted', severity: 'high', cwe: ['CWE-434', 'CWE-79'], description: 'An SVG file was accepted although SVG can contain scripts.', impact: 'A stored SVG can run script in the viewer’s browser.', fix: 'Never accept svg, html, xml or zip uploads.' },
  async run(ctx) {
    const r = ready(ctx);
    if ('reason' in r) return NOT_ATTEMPTED(r.reason);
    const expected = 'an SVG upload is refused with 415 (or 400/422)';
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
    const { res } = await upload(ctx, r.session, { name: 'image.svg', type: 'image/svg+xml', bytes: new TextEncoder().encode(svg) });
    return [400, 415, 422].includes(res.status) ? pass(expected, `status ${res.status}`, res) : fail(expected, `status ${res.status}`, res);
  },
};

let stored: { id: string; session: Session } | undefined;

async function storedUpload(ctx: ProbeContext, session: Session): Promise<UploadResult> {
  if (stored && stored.session === session) return { res: undefined as unknown as HttpResponse, id: stored.id };
  const result = await upload(ctx, session, { name: 'ok.png', type: 'image/png', bytes: pngOfSize(1024) });
  if (result.id) stored = { id: result.id, session };
  return result;
}

export const uploadNotServedFromPublic: ProbeModule = {
  id: 'dast.upload.not-served-from-public',
  group: 'uploads',
  requirementIds: ['V5.3.1', 'V5.3.2'],
  fallback: { title: 'Uploaded files stored under the web root', severity: 'high', cwe: ['CWE-434'], description: 'An uploaded file was written under public/ or is reachable as a static file.', impact: 'Uploaded content is served directly, bypassing ownership checks and content-type rules.', fix: 'Store uploads under DATA_DIR/uploads with random names and serve them only through the download route.' },
  async run(ctx) {
    const r = ready(ctx);
    if ('reason' in r) return NOT_ATTEMPTED(r.reason);
    const expected = 'uploads are stored under DATA_DIR/uploads (mode 0600), never under public/, and are not served as static files';
    const { res, id } = await storedUpload(ctx, r.session);
    if (!id) return NOT_ATTEMPTED(`a valid upload was not accepted (status ${res?.status})`, expected);
    const publicDir = join(ctx.appDir, 'public');
    const inPublic = existsSync(publicDir) && walk(publicDir).some((f) => /uploads?/i.test(f) && statSync(f).mtimeMs > Date.now() - 60_000);
    if (inPublic) return fail(expected, 'a recently written file under public/ mentions uploads');
    const uploadsDir = join(ctx.app.dataDir, 'uploads');
    const files = existsSync(uploadsDir) ? readdirSync(uploadsDir) : [];
    if (files.length === 0) return fail(expected, `no file appeared under ${uploadsDir}`);
    const badMode = files.find((f) => process.platform !== 'win32' && (statSync(join(uploadsDir, f)).mode & 0o077) !== 0);
    if (badMode) return fail(expected, `${badMode} is readable by other users (mode ${(statSync(join(uploadsDir, badMode)).mode & 0o777).toString(8)})`);
    const named = files.find((f) => /ok\.png/i.test(f));
    if (named) return fail(expected, 'the original file name is used on disk');
    const stat = await ctx.http.get(`/uploads/${files[0]}`);
    if (stat.status === 200 && !/attachment/i.test(stat.header('content-disposition') ?? '')) return fail(expected, 'the stored file is served as a static asset', stat);
    return pass(expected, `stored as ${files.length} random-named file(s) under DATA_DIR/uploads, not served statically`);
  },
};

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

export const uploadDownloadHeaders: ProbeModule = {
  id: 'dast.upload.download-headers',
  group: 'uploads',
  requirementIds: ['V5.4.1', 'V5.4.2', 'V3.2.1'],
  fallback: { title: 'Download headers missing', severity: 'medium', cwe: ['CWE-79'], description: 'A download response lacked Content-Disposition: attachment, nosniff, the sandbox CSP or private no-store caching.', impact: 'Browsers may render the file inline, letting a crafted file run script in the app’s origin.', fix: 'Send Content-Disposition: attachment, X-Content-Type-Options: nosniff, Content-Security-Policy: sandbox and Cache-Control: private, no-store.' },
  async run(ctx) {
    const r = ready(ctx);
    if ('reason' in r) return NOT_ATTEMPTED(r.reason);
    const expected = 'download answers with Content-Disposition: attachment, nosniff, Content-Security-Policy: sandbox and Cache-Control containing no-store';
    const { res, id } = await storedUpload(ctx, r.session);
    if (!id) return NOT_ATTEMPTED(`a valid upload was not accepted (status ${res?.status})`, expected);
    const dl = await ctx.http.get(downloadPath(ctx, id), { jar: r.session.jar });
    if (dl.status !== 200) return NOT_ATTEMPTED(`the owner’s download answered ${dl.status}`, expected);
    const problems: string[] = [];
    if (!/^attachment/i.test(dl.header('content-disposition') ?? '')) problems.push('Content-Disposition is not attachment');
    if ((dl.header('x-content-type-options') ?? '').toLowerCase() !== 'nosniff') problems.push('nosniff missing');
    if (!/sandbox/i.test(dl.header('content-security-policy') ?? '')) problems.push('CSP sandbox missing');
    if (!/no-store/i.test(dl.header('cache-control') ?? '')) problems.push('Cache-Control no-store missing');
    return problems.length === 0 ? pass(expected, 'all download headers present', dl) : fail(expected, problems.join('; '), dl);
  },
};

export const uploadNonOwnerDenied: ProbeModule = {
  id: 'dast.upload.non-owner-denied',
  group: 'uploads',
  requirementIds: ['V8.2.2'],
  fallback: { title: "Another user's file can be downloaded", severity: 'high', cwe: ['CWE-639'], description: 'A signed-in user could download a file uploaded by someone else.', impact: 'Private documents leak between customers.', fix: 'Declare owner: { entity: "upload", param: "id" } on the download route.' },
  async run(ctx) {
    const r = ready(ctx);
    if ('reason' in r) return NOT_ATTEMPTED(r.reason);
    const other = ctx.sessions.get('member2');
    if (!other) return NOT_ATTEMPTED('the second member account could not sign in');
    const expected = 'another user’s download answers 403/404 and an anonymous download is refused';
    const { res, id } = await storedUpload(ctx, r.session);
    if (!id) return NOT_ATTEMPTED(`a valid upload was not accepted (status ${res?.status})`, expected);
    const path = downloadPath(ctx, id);
    const denied = await ctx.http.get(path, { jar: other.jar });
    if (![403, 404].includes(denied.status)) return fail(expected, `another user got ${denied.status}`, denied);
    const anon = await ctx.http.get(path);
    if (anon.status === 200) return fail(expected, 'an anonymous request downloaded the file', anon);
    return pass(expected, `other user ${denied.status}; anonymous ${anon.status}`, denied);
  },
};

export const uploadQuotaEnforced: ProbeModule = {
  id: 'dast.upload.quota-enforced',
  group: 'uploads',
  requirementIds: ['V2.3.2'],
  fallback: { title: 'Per-user upload quota not enforced', severity: 'medium', cwe: ['CWE-770'], description: 'A user could keep uploading beyond UPLOAD_USER_QUOTA_BYTES.', impact: 'One account can fill the disk for everyone.', fix: 'Check the user’s total bytes and count inside a transaction before storing a file.' },
  async run(ctx) {
    const r = ready(ctx);
    if ('reason' in r) return NOT_ATTEMPTED(r.reason);
    const expected = `uploads beyond ${PROBE_UPLOAD_QUOTA_BYTES} bytes per user are refused (409/413/422/403)`;
    const size = 1024;
    const maxAttempts = Math.ceil(PROBE_UPLOAD_QUOTA_BYTES / size) + 2;
    let last: HttpResponse | undefined;
    for (let i = 0; i < maxAttempts; i++) {
      const { res } = await upload(ctx, r.session, { name: `q${i}.png`, type: 'image/png', bytes: pngOfSize(size) });
      last = res;
      if ([400, 403, 409, 413, 422].includes(res.status)) return pass(expected, `upload ${i + 1} refused with ${res.status}`, res);
      if (res.status === 429) return NOT_ATTEMPTED('the upload rate limit triggered before the quota', expected);
      if (res.status >= 500) return fail(expected, `upload ${i + 1} crashed with ${res.status}`, res);
    }
    return fail(expected, `${maxAttempts} uploads of ${size} bytes were all accepted`, last);
  },
};

export function resetUploadState(): void {
  stored = undefined;
}

export const uploadProbes: ProbeModule[] = [uploadOversize413, uploadTypeMismatch415, uploadSvgRefused, uploadNotServedFromPublic, uploadDownloadHeaders, uploadNonOwnerDenied, uploadQuotaEnforced];
