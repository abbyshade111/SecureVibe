/**
 * Uploading an app the owner already has, so SecureVibe can check it (`origin.kind === 'uploaded'`).
 *
 *   POST /api/projects/:id/upload/begin   → starts a fresh upload (an empty staging folder)
 *   PUT  /api/projects/:id/upload/file?path=<relative path>   (raw bytes, one file per request)
 *   PUT  /api/projects/:id/upload/archive                      (a whole .zip, unpacked here: see zip.ts)
 *   POST /api/projects/:id/upload/finish  → the staged files become the app folder (the previous one is kept as app-vN)
 *   POST /api/projects/:id/upload/cancel
 *
 * Files are only ever written as plain files inside the staging folder: every path is checked (no `..`, no absolute
 * paths, no symlinks followed), and dependencies, build output and secrets files are left out on purpose.
 */
import { existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import express, { Router } from 'express';
import { TemplateManifestSchema, type TemplateManifest } from '@shared/knowledge.js';
import { isUploadedApp } from '@shared/project.js';
import { runIsLive } from '../pipeline/job.js';
import { removeDir } from '../pipeline/process.js';
import { conflict, validationError } from '../security/errors.js';
import { confinePath, safeRelative } from '../store/index.js';
import type { ApiDeps } from './types.js';
import { unpackZip, ZipError } from './zip.js';

export const UPLOAD_LIMITS = { maxFiles: 5_000, maxTotalBytes: 50 * 1024 * 1024, maxFileBytes: 2 * 1024 * 1024 } as const;

/** Folders that are never part of the code to check (dependencies, build output, tool caches, version control). */
export const SKIPPED_FOLDERS = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.cache',
  '.turbo',
  'coverage',
  '.venv',
  'venv',
  '__pycache__',
  '.idea',
  '.vscode',
  'vendor',
  'target',
]);

/** ".env" and ".env.<anything>", except the example files that are meant to be shared. */
function isSecretsEnvFile(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower !== '.env' && !lower.startsWith('.env.')) return false;
  return !['.env.example', '.env.sample', '.env.template'].includes(lower);
}

/** Why a file is left out, or undefined when it is uploaded. Kept in step with web/src/lib/upload.ts. */
export function skipReason(relPath: string, size: number): string | undefined {
  const parts = relPath.split('/');
  if (parts.some((p) => SKIPPED_FOLDERS.has(p))) return 'dependencies or build output';
  const name = parts.at(-1) ?? '';
  if (isSecretsEnvFile(name)) return 'a secrets file (.env)';
  if (/\.(pem|key|p12|pfx|jks|keystore)$/i.test(name) || /^id_(rsa|dsa|ecdsa|ed25519)$/.test(name)) return 'a private key';
  if (/\.(sqlite3?|db)$/i.test(name)) return 'a database file';
  if (name === '.DS_Store' || name === 'Thumbs.db') return 'a system file';
  if (size > UPLOAD_LIMITS.maxFileBytes) return 'larger than 2 MB';
  return undefined;
}

/** Steps that would run the uploaded code: SecureVibe only runs code it wrote itself. */
export const UPLOADED_SKIPPED_STAGES = {
  install: 'SecureVibe does not install or run code it did not build, so this check was not done for an uploaded app.',
  typecheck: 'SecureVibe does not install or run code it did not build, so the code was not compiled.',
  'unit-tests': "SecureVibe does not run an uploaded app's own tests (running unknown code is not safe here).",
  dast: 'SecureVibe does not start an uploaded app, so it was not tested while running.',
} as const;

export const UPLOADED_IGNORE = [...SKIPPED_FOLDERS];

/**
 * Checks that test SecureVibe's own template conventions (its route registry, database wrapper, HTTP client, .env
 * names, protected files, provenance record). They say nothing about an app built another way, so they are not run.
 */
export const UPLOADED_EXCLUDED_CHECKS = [
  'sast.route-outside-registry',
  'sast.missing-authz-declaration',
  'sast.db-raw-outside-wrapper',
  'sast.fetch-outside-http-client',
  'sast.http-request-outside-client',
  'sast.disallowed-import',
  'sast.protected-file-modified',
  'config.secrets-strength',
  'config.no-default-admin',
  'config.no-debug-flags',
  'config.example-feature-disabled',
  'config.test-mode-not-in-env',
  'config.tls-mode-consistent',
  'config.trust-proxy-hops',
  'config.session-policy',
  'config.protected-files-unchanged',
  'config.provenance-present',
  'config.bind-loopback-default',
  'config.security-md-present',
  'config.package-json-unmodified',
];

/** An uploaded app has no SecureVibe template: no template controls apply, only the general checks. */
export function uploadedManifest(): TemplateManifest {
  return TemplateManifestSchema.parse({
    name: 'uploaded-app',
    version: '0.0.0',
    description: 'An app the owner uploaded to be checked. It was not built from the SecureVibe template, so no template controls apply.',
    stack: [],
    engines: { node: 'unknown' },
    features: [],
    protectedPaths: [],
    writablePaths: [],
    allowedImports: [],
    controls: [],
    conventions: [],
    testMode: { envFlag: 'SECUREVIBE_TEST_MODE', readyLinePrefix: '{"securevibe":"listening"', routesEndpoint: '/__securevibe/routes', seededUsers: [] },
  });
}

/** Files a person should read for an uploaded app's code review: the ones whose names suggest security work. */
export const UPLOADED_REVIEW_GLOBS = [
  '**/*auth*',
  '**/*login*',
  '**/*session*',
  '**/*secur*',
  '**/*permission*',
  '**/*access*',
  '**/*middleware*',
  '**/*crypt*',
  '**/*password*',
  '**/*token*',
  '**/*csrf*',
  '**/*upload*',
];

interface UploadSession {
  files: number;
  bytes: number;
  skipped: number;
}

const SESSIONS = new Map<string, UploadSession>();
const FILE_ROUTE = /^\/projects\/[^/]+\/upload\/(file|archive)$/;

/** Raw uploads are the one place /api accepts a non-JSON body. */
export function isRawUploadRequest(method: string, path: string): boolean {
  return method === 'PUT' && FILE_ROUTE.test(path);
}

export function uploadsRouter(deps: ApiDeps): Router {
  const router = Router();

  const uploadedProject = (id: string) => {
    const project = deps.store.mustGet(id);
    if (!isUploadedApp(project)) throw validationError('Only apps added with "Check an app you already have" take uploads.');
    if (project.lastRunId && runIsLive(deps.store, project.lastRunId)) throw conflict('The app is being checked right now. Upload a new version when that has finished.');
    return project;
  };
  const stagingDir = (id: string) => join(deps.store.paths(id).dir, 'upload-staging');

  router.post('/projects/:id/upload/begin', (req, res) => {
    const project = uploadedProject(req.params['id']!);
    const dir = stagingDir(project.id);
    removeDir(dir);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    SESSIONS.set(project.id, { files: 0, bytes: 0, skipped: 0 });
    res.json({ limits: UPLOAD_LIMITS });
  });

  router.put(
    '/projects/:id/upload/file',
    express.raw({ type: 'application/octet-stream', limit: UPLOAD_LIMITS.maxFileBytes }),
    (req, res) => {
      const project = uploadedProject(req.params['id']!);
      const session = SESSIONS.get(project.id);
      if (!session) throw conflict('Start the upload again: it was not started or SecureVibe restarted.');
      // A repeated ?path= arrives as an array; only a single string is a file name. (CodeQL reads the raw body
      // below as "parameter tampering"; it is a Buffer by construction and the length checks are on that Buffer.)
      const raw = typeof req.query['path'] === 'string' ? req.query['path'] : '';
      const rel = raw.startsWith('/') ? undefined : safeRelative(raw);
      if (!rel || rel.length > 512 || rel.split('/').some((p) => p.length > 255 || p.startsWith('..'))) {
        throw validationError('That file name cannot be used.');
      }
      // Checked on the header: an empty file has no body, and the body-type helpers ignore requests without one.
      if (!/^application\/octet-stream\b/i.test(req.headers['content-type'] ?? '')) throw validationError('Send the file as raw bytes (application/octet-stream).');
      const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      const reason = skipReason(rel, body.length);
      if (reason) {
        session.skipped++;
        res.json({ stored: false, reason });
        return;
      }
      if (session.files + 1 > UPLOAD_LIMITS.maxFiles) throw validationError(`An app can have at most ${UPLOAD_LIMITS.maxFiles} files.`);
      if (session.bytes + body.length > UPLOAD_LIMITS.maxTotalBytes) throw validationError('The app is larger than 50 MB without its dependencies.');
      const target = confinePath(stagingDir(project.id), ...rel.split('/'));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, body, { flag: 'w' });
      session.files++;
      session.bytes += body.length;
      res.json({ stored: true });
    },
  );

  /**
   * A whole app as one .zip, since that is what people have. Unpacked here rather than by the person: every
   * path checked before it is written, links left out, the size capped from the declaration before inflating,
   * and the same skip list as the file route. Bigger than a single file may be, because it holds the whole app.
   */
  router.put(
    '/projects/:id/upload/archive',
    // Raw bytes, like the file route: the JSON-only guard in security/middleware.ts lets exactly that type through.
    express.raw({ type: 'application/octet-stream', limit: UPLOAD_LIMITS.maxTotalBytes }),
    (req, res) => {
      const project = uploadedProject(req.params['id']!);
      const session = SESSIONS.get(project.id);
      if (!session) throw conflict('Start the upload again: it was not started or SecureVibe restarted.');
      // A Buffer by construction: express.raw parsed the octet-stream body above. Copied once so what unpackZip
      // reads is a plain Buffer of ours rather than the request object's own body (CodeQL otherwise follows the
      // request body into every byte read and reports "parameter tampering" three times over).
      const body = Buffer.isBuffer(req.body) ? Buffer.from(req.body) : Buffer.alloc(0);
      if (body.length === 0) throw validationError('Send the zip file as raw bytes.');
      let unpacked;
      try {
        unpacked = unpackZip(body, UPLOAD_LIMITS, skipReason);
      } catch (err) {
        if (err instanceof ZipError) throw validationError(err.message);
        throw err;
      }
      if (session.files + unpacked.files.length > UPLOAD_LIMITS.maxFiles) throw validationError(`An app can have at most ${UPLOAD_LIMITS.maxFiles} files.`);
      const bytes = unpacked.files.reduce((n, f) => n + f.data.length, 0);
      if (session.bytes + bytes > UPLOAD_LIMITS.maxTotalBytes) throw validationError('The app is larger than 50 MB without its dependencies.');
      const root = stagingDir(project.id);
      for (const file of unpacked.files) {
        const target = confinePath(root, ...file.path.split('/'));
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, file.data, { flag: 'w' });
      }
      session.files += unpacked.files.length;
      session.bytes += bytes;
      session.skipped += unpacked.skipped.length;
      res.json({ stored: unpacked.files.length, skipped: unpacked.skipped });
    },
  );

  router.post('/projects/:id/upload/finish', (req, res) => {
    const project = uploadedProject(req.params['id']!);
    const session = SESSIONS.get(project.id);
    const dir = stagingDir(project.id);
    if (!session || !existsSync(dir)) throw conflict('Start the upload again: it was not started or SecureVibe restarted.');
    if (session.files === 0) throw validationError('No files were uploaded. Choose the folder that holds your app’s code.');

    deps.previews.stop(project.id);
    const { appDir } = deps.store.paths(project.id);
    const { version } = deps.store.archiveApp(project.id);
    renameSync(dir, appDir);
    SESSIONS.delete(project.id);
    const saved = deps.store.update(project.id, (p) => {
      p.origin = {
        kind: 'uploaded',
        ...(p.origin?.aiAssisted !== undefined ? { aiAssisted: p.origin.aiAssisted } : {}),
        upload: { uploadedAt: new Date().toISOString(), files: session.files, bytes: session.bytes, skipped: session.skipped, version: version + 1 },
      };
      // Results from an earlier upload describe other code.
      if (p.lastRunId) p.buildStale = true;
    });
    deps.logger.info({ event: 'upload.finished', projectId: project.id, files: session.files, bytes: session.bytes }, 'app uploaded for checking');
    res.json({ project: saved });
  });

  router.post('/projects/:id/upload/cancel', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    SESSIONS.delete(project.id);
    removeDir(stagingDir(project.id));
    res.status(204).end();
  });

  return router;
}
