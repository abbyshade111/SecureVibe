/**
 * File uploads (contract §1.10, TPL-UPLOAD-01..06). Files are streamed through busboy with a byte cap that
 * aborts the request before the body finishes, sniffed against a fixed magic-byte table, checked against the
 * declared type and the extension, stored under a random name outside the web root, and served back only to
 * their owner (or an administrator) as an attachment with hardened headers.
 *
 * The upload form is a real multipart body, so Express's body parser never touches it and the registry's
 * session-cookie CSRF check (which reads a parsed `req.body`) cannot run before busboy has read the stream. The
 * route therefore declares `csrf: false` and this module checks the same two things — the Origin/Sec-Fetch-Site
 * headers and the `_csrf` field, compared in constant time against the token already issued to this session — by
 * hand, as soon as busboy delivers the field (which arrives before the file field in every client this template
 * ships, since the hidden `_csrf` input is always written before the file input).
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import type { Request, Response, Router } from 'express';
import busboy from 'busboy';
import { z } from 'zod';
import { config } from '../../config.ts';
import { clampLimit } from '../../db/index.ts';
import { errors, HttpError, type ErrorCode } from '../../lib/errors.ts';
import { renderPage } from '../../lib/views.ts';
import { CSRF_FIELD, passesOriginCheck } from '../../security/csrf.ts';
import { emit, onSecurityEvent } from '../../security/events.ts';
import { defineRoute } from '../../security/routes.ts';
import { scanForMalware, scannerDescription, uploadsArePossible } from '../../security/malware.ts';
import { schemas } from '../../security/validate.ts';
import {
  checkFileType,
  commitTempFile,
  safeUnlink,
  extensionOf,
  getUpload,
  listUploadsForOwner,
  randomId,
  recordUpload,
  registerUploadsEntity,
  sanitiseOriginalName,
  sniffMagicBytes,
  storedUploadPath,
  tempUploadPath,
  toOwnerDto,
} from './repo.ts';

const UploadParams = z.strictObject({ id: schemas.id });
const ListQuery = z.strictObject({ page: schemas.page });
const OWNER = { entity: 'upload', param: 'id' } as const;
const SNIFF_BYTES = 16;

/** How many bytes of ASCII-safe text survive in a Content-Disposition `filename=` value. */
function asciiFallback(name: string): string {
  const ascii = name
    .replace(/[^\x20-\x7e]/g, '_')
    .replace(/["\\]/g, '_')
    .trim();
  return ascii.length > 0 ? ascii : 'download';
}

function contentDispositionFor(name: string): string {
  const safe = name.replace(/[\r\n]+/g, ' ');
  const ascii = asciiFallback(safe);
  const encoded = encodeURIComponent(safe);
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

/** What `receiveUpload` settles to: the stored file, or the reason it was refused. */
export interface UploadOutcome {
  status: number;
  body?: { id: string; originalName: string; mime: string; size: number };
  error?: { status: number; code: ErrorCode; message: string };
}

function codeForStatus(status: number): ErrorCode {
  switch (status) {
    case 403:
      return 'csrf_rejected';
    case 409:
      return 'quota_exceeded';
    case 413:
      return 'payload_too_large';
    case 415:
      return 'unsupported_media_type';
    case 500:
      return 'internal_error';
    default:
      return 'bad_request';
  }
}

function errOutcome(status: number, message: string): UploadOutcome {
  return { status, error: { status, code: codeForStatus(status), message } };
}

/**
 * Streams one multipart upload to disk, checking the CSRF field, the byte cap and the file type as it goes.
 *
 * Exported because a generated feature that attaches a file to one of its records must do it through this module
 * and nowhere else (SC-12): the route it adds calls this, so the Origin check, the form token, the byte cap, the
 * magic-byte sniff, the storage location and the per-person storage limit are the same ones the `/uploads` page
 * uses. Such a route must declare `csrf: false` and `rateLimit: 'uploads'`, for the reason described at the top of
 * this file, and the file is recorded as owned by the signed-in person, never by the record's owner.
 */
export function receiveUpload(req: Request): Promise<UploadOutcome> {
  return new Promise((resolvePromise) => {
    let settled = false;
    const finish = (outcome: UploadOutcome) => {
      if (settled) return;
      settled = true;
      resolvePromise(outcome);
    };

    const origin = passesOriginCheck(req);
    if (!origin.ok) {
      emit('csrf.rejected', { req, reason: origin.reason });
      return finish(errOutcome(403, 'Your form session expired or the request did not come from this site. Please try again.'));
    }

    let bb: ReturnType<typeof busboy>;
    try {
      // Browsers send multipart parameters as UTF-8; busboy defaults to latin1, which would turn an accented
      // file name into mojibake and lose it from the download header.
      bb = busboy({ headers: req.headers, defParamCharset: 'utf8', limits: { fileSize: config.UPLOAD_MAX_BYTES, files: 1, fields: 20, fieldSize: 4096 } });
    } catch {
      return finish(errOutcome(400, 'The upload could not be read.'));
    }

    let csrfOk = false;
    let fileSeen = false;
    let tempPath: string | undefined;

    const cleanupAndFinish = (outcome: UploadOutcome) => {
      if (tempPath) safeUnlink(tempPath);
      req.unpipe(bb);
      bb.removeAllListeners();
      req.resume();
      finish(outcome);
    };

    bb.on('field', (name, value) => {
      if (name !== CSRF_FIELD || csrfOk) return;
      const expected = req.session.get<string>('csrf');
      if (expected && value.length === expected.length && timingSafeEqual(Buffer.from(value), Buffer.from(expected))) csrfOk = true;
    });

    bb.on('file', (name, stream, info) => {
      if (name !== 'file' || fileSeen) {
        stream.resume();
        return;
      }
      fileSeen = true;
      if (!csrfOk) {
        stream.resume();
        emit('csrf.rejected', { req, reason: 'token-missing' });
        return cleanupAndFinish(errOutcome(403, 'Your form session expired or the request did not come from this site. Please try again.'));
      }

      const originalName = sanitiseOriginalName(info.filename || 'file');
      const extension = extensionOf(originalName);
      const declaredType = info.mimeType || '';
      const id = randomId();
      const tmp = tempUploadPath(id);
      tempPath = tmp;

      const head: Buffer[] = [];
      let headBytes = 0;
      let sniffed: ReturnType<typeof sniffMagicBytes>;
      let decided = false;
      let rejected = false;
      let out: ReturnType<typeof createWriteStream> | undefined;
      let bytes = 0;
      const hash = createHash('sha256');

      const rejectFile = (status: number, reason: string) => {
        if (rejected) return;
        rejected = true;
        stream.unpipe();
        stream.resume();
        out?.destroy();
        emit('upload.rejected', { req, reason });
        cleanupAndFinish(errOutcome(status, 'This file could not be accepted.'));
      };

      stream.on('limit', () => rejectFile(413, 'file-too-large'));

      stream.on('data', (chunk: Buffer) => {
        if (rejected) return;
        bytes += chunk.length;
        hash.update(chunk);
        if (!decided) {
          head.push(chunk);
          headBytes += chunk.length;
          if (headBytes < SNIFF_BYTES) return;
          decided = true;
          sniffed = sniffMagicBytes(Buffer.concat(head));
          const check = checkFileType({ sniffed, declaredType, extension });
          if (!check.ok) return rejectFile(415, check.reason ?? 'file-type-not-allowed');
          out = createWriteStream(tmp, { mode: 0o600 });
          out.on('error', () => rejectFile(500, 'storage-error'));
          out.write(Buffer.concat(head));
        } else {
          out?.write(chunk);
        }
      });

      stream.on('close', () => {
        if (rejected) return;
        if (!decided) {
          // Fewer than SNIFF_BYTES bytes arrived in total: sniff whatever we got.
          decided = true;
          sniffed = sniffMagicBytes(Buffer.concat(head));
          const check = checkFileType({ sniffed, declaredType, extension });
          if (!check.ok) return rejectFile(415, check.reason ?? 'file-type-not-allowed');
          out = createWriteStream(tmp, { mode: 0o600 });
          out.write(Buffer.concat(head));
        }
        out?.end(() => {
          if (rejected) return;
          // ADR-011. The file is checked before it is recorded and before it can be read back, and anything
          // that is not a clean verdict is deleted and refused — including a verdict we could not obtain. The
          // two refusals are deliberately different: "this is a virus" and "we could not check this" are not
          // the same thing to tell somebody about their own file.
          void (async () => {
            const verdict = await scanForMalware(tmp);
            if (verdict.kind !== 'clean') {
              safeUnlink(tmp);
              tempPath = undefined;
              if (verdict.kind === 'infected') {
                emit('upload.rejected', { req, reason: 'malware' });
                return cleanupAndFinish(errOutcome(422, 'This file was recognised as a known virus, so it has not been kept.'));
              }
              emit('upload.rejected', { req, reason: 'unscannable' });
              return cleanupAndFinish(errOutcome(503, `${verdict.reason} Your file has not been kept.`));
            }
            const result = recordUpload(id, {
              ownerId: req.user!.id,
              originalName,
              mime: sniffed!,
              size: bytes,
              sha256: hash.digest('hex'),
            });
            if (!result.ok) {
              safeUnlink(tmp);
              tempPath = undefined;
              emit('upload.rejected', { req, reason: 'quota-bytes' });
              return cleanupAndFinish(errOutcome(409, 'You have reached your storage limit. Delete a file to make room.'));
            }
            commitTempFile(tmp, id);
            tempPath = undefined;
            emit('upload.stored', { req, uploadId: id, size: bytes, mime: sniffed });
            finish({ status: 201, body: { id, originalName, mime: sniffed!, size: bytes } });
          })();
        });
      });
    });

    bb.on('error', () => cleanupAndFinish(errOutcome(400, 'The upload could not be read.')));
    bb.on('close', () => {
      if (!fileSeen) cleanupAndFinish(errOutcome(400, 'No file was included in the upload.'));
    });

    req.pipe(bb);
  });
}

export function register(router: Router): void {
  registerUploadsEntity();

  // The registry's owner check on the download route below emits `authz.denied`, not the upload-specific
  // `download.denied` security event the contract calls for; bridge the two without touching src/security/authz.ts.
  onSecurityEvent((record) => {
    if (record.event === 'authz.denied' && record.route === 'GET /uploads/:id') {
      emit('download.denied', { userId: record.userId, resourceId: record.fields['resourceId'] as string | undefined, reason: record.fields['reason'] as string | undefined });
    }
  });

  defineRoute(router, { method: 'GET', path: '/uploads', auth: 'user', entity: 'upload', schema: { query: ListQuery }, summary: 'Your files' }, (req, res) => {
    const { page } = req.valid.query;
    const size = clampLimit(25);
    const uploads = listUploadsForOwner(req.user!.id, size, (page - 1) * size);
    renderPage(req, res, 'uploads/list', {
      title: 'Your files',
      uploads: uploads.map(toOwnerDto),
      page,
      hasMore: uploads.length === size,
      maxBytes: config.UPLOAD_MAX_BYTES,
      allowedTypes: config.UPLOAD_ALLOWED_TYPES.split(',').map((t) => t.trim()),
      quotaBytes: config.UPLOAD_USER_QUOTA_BYTES,
      // Said before somebody picks a file, not after they have waited for an upload to fail. An app whose
      // scanner is not running has uploads that do not work, and that has to read as something to set up.
      scannerNote: scannerDescription(),
      uploadsPossible: uploadsArePossible(),
    });
  });

  defineRoute(
    router,
    { method: 'POST', path: '/uploads', auth: 'user', entity: 'upload', rateLimit: 'uploads', csrf: false, kind: 'page', summary: 'Upload a file' },
    async (req: Request, res: Response) => {
      const outcome = await receiveUpload(req);
      if (outcome.error) throw new HttpError(outcome.error.status, outcome.error.code, outcome.error.message);
      res.status(outcome.status);
      if (req.accepts(['html', 'json']) === 'json') {
        res.json(outcome.body);
        return;
      }
      req.session.flash('success', 'File uploaded.');
      res.redirect(303, '/uploads');
    },
  );

  defineRoute(router, { method: 'GET', path: '/uploads/:id', auth: 'user', owner: OWNER, entity: 'upload', schema: { params: UploadParams }, kind: 'page', summary: 'Download a file' }, (req, res) => {
    const row = getUpload(req.valid.params.id);
    if (!row) throw errors.notFound();
    res.setHeader('Content-Disposition', contentDispositionFor(row.original_name));
    res.setHeader('Content-Security-Policy', 'sandbox');
    res.setHeader('Cache-Control', 'private, no-store');
    res.type(row.mime);
    const stream = createReadStream(storedUploadPath(row.id));
    stream.on('error', () => {
      if (!res.headersSent) res.status(404);
      res.end();
    });
    stream.pipe(res);
  });
}
