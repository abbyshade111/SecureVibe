/**
 * `GET /api/projects/:id/artifacts` (list) and `GET /api/projects/:id/artifacts/:name` (download, confined to the
 * project folder). `app.zip`, `handoff.zip` and `scan-data.zip` are not files on disk — they are built on demand
 * with `archiver`: the app itself, the pack to hand to a developer, and the raw scan output for a security reviewer.
 */
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs';
import { basename, extname, join } from 'node:path';
import { ZipArchive } from 'archiver';
import { Router, type Response } from 'express';
import { REPORT_CSS } from '../reports/page.js';
import { handoffMarkdown } from '../reports/handoff.js';
import { buildScanData, scanDataFileName } from '../reports/scan-data.js';
import { isRunId } from '../store/index.js';
import { PathConfinementError } from '../store/paths.js';
import { forbidden, notFound } from '../security/errors.js';
import type { ApiDeps } from './types.js';

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.sarif': 'application/sarif+json',
  '.zip': 'application/zip',
};

/** CSP for a generated report page: its inline <style> blocks by hash, images only from itself or data URLs. */
export function reportCsp(html: string): string {
  const hashes = [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map((m) => `'sha256-${createHash('sha256').update(m[1] ?? '', 'utf8').digest('base64')}'`);
  return [
    "default-src 'none'",
    `style-src ${hashes.length > 0 ? hashes.join(' ') : "'none'"}`,
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'self'", // SecureVibe's own page loads a report in a hidden frame to print it (Save as PDF)
  ].join('; ');
}

/** Never packed into app.zip: installed packages, runtime data, and anything holding a secret. */
export const ZIP_EXCLUDE = ['node_modules/**', 'data/**', 'home/**', 'tmp/**', '.git/**', '.claude/**', '.env', '.env.*', 'FIRST-LOGIN.txt'] as const;

export function artifactsRouter(deps: ApiDeps): Router {
  const router = Router();

  /** The run whose reports are asked for: `?run=<id>` (one of this project's runs) or the latest run. */
  const runFor = (projectId: string, lastRunId: string | undefined, query: unknown) => {
    const requested = typeof query === 'string' && query !== '' ? query : undefined;
    const runId = requested ?? lastRunId;
    if (!runId || !isRunId(runId)) return undefined;
    return deps.store.readRun(projectId, runId);
  };

  // Every run of this project that produced reports, newest first, so earlier reports stay reachable.
  router.get('/projects/:id/report-runs', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const runs = deps.store
      .listRunIds(project.id)
      .map((runId) => deps.store.readRun(project.id, runId))
      .filter((run): run is NonNullable<typeof run> => run !== undefined && run.artifacts.length > 0)
      .reverse()
      .map((run) => ({
        id: run.id,
        mode: run.mode,
        status: run.status,
        startedAt: run.startedAt,
        ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
        reportCount: run.artifacts.length,
        ...(run.compliance ? { headline: run.compliance.overall.headline } : {}),
      }));
    res.json({ runs });
  });

  router.get('/projects/:id/artifacts', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const run = runFor(project.id, project.lastRunId, req.query['run']);
    res.json({ artifacts: run?.artifacts ?? [] });
  });

  // /projects/:id/reports/:runId/:name keeps a report's relative links (overview → compliance report) in its run.
  router.get('/projects/:id/reports/:runId/:name', (req, res) => {
    serveArtifact(req.params['id']!, req.params['name']!, req.params['runId']!, res);
  });

  router.get('/projects/:id/artifacts/:name', (req, res) => {
    serveArtifact(req.params['id']!, req.params['name']!, req.query['run'], res);
  });

  function serveArtifact(projectId: string, name: string, runQuery: unknown, res: Response): void {
    const project = deps.store.mustGet(projectId);

    if (name === 'app.zip') {
      const { appDir } = deps.store.paths(project.id);
      if (!existsSync(appDir)) throw notFound('This project has not been built yet.');
      res.status(200);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="app.zip"');
      const archive = new ZipArchive({ zlib: { level: 9 } });
      archive.on('error', (err: Error) => res.destroy(err));
      archive.pipe(res);
      // Secrets and the one-time admin password never leave this computer: whoever unpacks the zip runs
      // `npm run setup`, which generates fresh secrets and a new first administrator.
      archive.glob('**/*', { cwd: appDir, ignore: [...ZIP_EXCLUDE], dot: true });
      if (existsSync(join(appDir, '.env.example'))) archive.file(join(appDir, '.env.example'), { name: '.env.example' });
      void archive.finalize();
      return;
    }

    if (name === 'handoff.zip') {
      // The hand-off pack: the app (as app.zip), the latest reports, the human-check answers and HANDOFF.md.
      const { appDir } = deps.store.paths(project.id);
      if (!existsSync(appDir)) throw notFound('This project has not been built yet.');
      const run = runFor(project.id, project.lastRunId, runQuery);
      if (!run) throw notFound('This project has no finished build to hand off yet.');
      const reportsDir = deps.store.reportsDir(project.id, run.id);
      const contents = [
        { path: 'HANDOFF.md', what: 'this document' },
        { path: 'app/', what: 'the application (no secrets, no installed packages, no data)' },
        { path: 'app/.env.example', what: 'every setting, with its default and what it does' },
        { path: 'reports/', what: `every report from build ${run.id}: compliance, security findings, design, provenance, SBOM, run log` },
        { path: 'human-checks.json', what: 'the human checks people answered, with who and when' },
      ];
      const md = handoffMarkdown({ project, run, securevibeVersion: deps.config.version, contents });
      const safeName = `${project.name.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'app'}-handoff.zip`;
      res.status(200);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
      const archive = new ZipArchive({ zlib: { level: 9 } });
      archive.on('error', (err: Error) => res.destroy(err));
      archive.pipe(res);
      archive.append(md, { name: 'HANDOFF.md' });
      archive.append(`${JSON.stringify({ project: project.name, attestations: project.attestations ?? [], humanCodeReview: project.humanCodeReview ?? null }, null, 2)}\n`, { name: 'human-checks.json' });
      archive.glob('**/*', { cwd: appDir, ignore: [...ZIP_EXCLUDE], dot: true }, { prefix: 'app' });
      if (existsSync(join(appDir, '.env.example'))) archive.file(join(appDir, '.env.example'), { name: 'app/.env.example' });
      if (existsSync(reportsDir)) archive.directory(reportsDir, 'reports');
      void archive.finalize();
      return;
    }

    if (name === 'scan-data.zip') {
      // The raw output of every check, for a security reviewer or a tool. Built on demand from the run record and
      // the machine-readable report files, so it always matches what the results page shows.
      const run = runFor(project.id, project.lastRunId, runQuery);
      if (!run) throw notFound('This project has no finished check to download the scan data from.');
      const findings = run.findings.map((f) => {
        const decision = project.findingDecisions.find((d) => d.fingerprint === f.fingerprint);
        return decision ? { ...f, status: decision.status, ...(decision.triage ? { triage: decision.triage } : {}) } : f;
      });
      const bundle = buildScanData({
        project: { id: project.id, name: project.name },
        run,
        findings,
        reportsDir: deps.store.reportsDir(project.id, run.id),
        runDir: deps.store.runDir(project.id, run.id),
        securevibeVersion: deps.config.version,
      });
      res.status(200);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${scanDataFileName(project.name, run.id)}"`);
      const archive = new ZipArchive({ zlib: { level: 9 } });
      archive.on('error', (err: Error) => res.destroy(err));
      archive.pipe(res);
      for (const entry of bundle.entries) archive.append(entry.content, { name: entry.name });
      for (const file of bundle.files) archive.file(file.absolutePath, { name: file.name });
      void archive.finalize();
      return;
    }

    const run = runFor(project.id, project.lastRunId, runQuery);
    if (!run) throw notFound('That file could not be found.');
    const ref = run?.artifacts.find((a) => a.name === name);
    if (!ref) throw notFound('That file could not be found.');

    let absolute: string;
    try {
      // Runs saved before paths were made project-relative list only the file name of the report.
      absolute = ref.path.includes('/')
        ? deps.store.projectPath(project.id, ...ref.path.split('/'))
        : join(deps.store.reportsDir(project.id, run.id), basename(ref.path));
    } catch (err) {
      if (err instanceof PathConfinementError) throw forbidden('That path is not allowed.');
      throw err;
    }
    if (!existsSync(absolute)) throw notFound('That file could not be found.');

    const type = CONTENT_TYPES[extname(absolute)] ?? 'application/octet-stream';
    if (extname(absolute) === '.html') {
      // Reports carry their own <style> block. They get a policy of their own that allows exactly those blocks
      // (by hash) and nothing else: no scripts, no outside requests.
      // Reports saved by an older SecureVibe get today's stylesheet (readable in dark mode); the file is unchanged.
      const saved = readFileSync(absolute, 'utf8');
      const html = /class="report-header"/.test(saved) ? saved.replace(/<style>[\s\S]*?<\/style>/, () => `<style>${REPORT_CSS}</style>`) : saved;
      res.setHeader('Content-Security-Policy', reportCsp(html));
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.type(type).send(html);
      return;
    }
    res.setHeader('Content-Type', type);
    res.setHeader('Content-Length', String(statSync(absolute).size));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    createReadStream(absolute).pipe(res);
  }

  return router;
}
