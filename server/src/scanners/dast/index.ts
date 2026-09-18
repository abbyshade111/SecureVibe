/**
 * The runtime scanner (`dast` stage): starts the generated app privately on 127.0.0.1 with throw-away secrets and
 * a throw-away database, probes it the way an attacker would, and turns the results into evidence and findings.
 *
 * Three starts, in this order (CONTRACTS §2):
 *  1. test mode — seeded accounts per role, the route registry export, the security-event feed;
 *  2. production mode behind a pretend TLS proxy — the checks that must NOT hold in test mode
 *     (test endpoints gone, readiness endpoint, Secure cookies and HSTS);
 *  3. self-signed TLS — only when the app ships certificates, for the TLS version check.
 *
 * Every probe that could not run is recorded with its reason instead of being counted as a pass.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import type { ToolCoverage } from '@shared/pipeline.js';
import type { ScanContext, ScanResult, ScanStatus } from '../types.js';
import type { DastAuthBootstrap } from './auth.js';
import type { HttpClient } from './http.js';
import { evidenceForResult, findingsForResult, type DastBuildContext } from './findings.js';
import { AppStartError, startApp, type StartAppOptions } from './harness.js';
import { ALL_PROBES, probeById } from './probes/index.js';
import { buildProbeContext, notAttemptedForPhase, runProbes } from './runner.js';
import type { AppInstance, ProbePhase, ProbeResult, RoutesExport } from './types.js';

export const DAST_COVERS =
  'Starts your app privately on this computer and checks how it behaves: security headers, sign-in, permissions, forms, error pages and rate limits.';

export interface DastOptions {
  /** Probe ids that do not apply to this app, with the reason shown in the report. */
  notApplicable?: Record<string, string>;
  /** The app's routes when it has no test-mode route export (SecureVibe's self-assessment). */
  routes?: RoutesExport;
  /** How the probes sign in. Default: the template's sign-in forms. SecureVibe's self-assessment plugs in its own. */
  auth?: DastAuthBootstrap;
  /** Skip the Node permission model (used by the harness's own tests). */
  sandbox?: boolean;
  /** Extra read-only paths for the permission model (a node_modules folder outside the app, for example). */
  extraReadPaths?: string[];
  readyTimeoutMs?: number;
  /** Node arguments that start the app; derived from the app folder when omitted. */
  entry?: string[];
  /**
   * Replaces starting the app as a child process. SecureVibe's own self-assessment probes a server that is
   * already running, and the scanner's tests drive an app inside the test process.
   */
  start?(phase: ProbePhase, ctx: ScanContext): Promise<AppInstance>;
  /** Replaces the loopback HTTP client used to talk to a started app. */
  client?(app: AppInstance): HttpClient;
}

export interface DastDetails {
  probes: ProbeResult[];
  /** Roles whose seeded account was signed in for the authorization probes. */
  seededRoles: string[];
  /** How many registered routes the authorization probes walked. */
  routesProbed: number;
  phases: { phase: ProbePhase; started: boolean; reason?: string; sandboxMode?: string }[];
  counts: { passed: number; failed: number; notAttempted: number };
}

function countOf(results: ProbeResult[]): DastDetails['counts'] {
  return {
    passed: results.filter((r) => r.passed === true).length,
    failed: results.filter((r) => r.passed === false).length,
    notAttempted: results.filter((r) => r.passed === null).length,
  };
}

function statusFor(findings: Finding[], anyPhaseStarted: boolean): ScanStatus {
  if (!anyPhaseStarted) return 'skipped';
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 'failed';
  if (findings.length > 0) return 'warning';
  return 'passed';
}

function startFailureReason(err: unknown): string {
  if (err instanceof AppStartError) {
    const detail = (err.stderr || err.stdout).trim().split('\n').slice(-3).join(' ').slice(0, 300);
    return detail ? `${err.message} Last output: ${detail}` : err.message;
  }
  return `the app could not be started: ${(err as Error).message}`;
}

/** Runs the probes of one phase; on a start failure every probe of that phase is recorded as not attempted. */
async function runPhase(
  ctx: ScanContext,
  phase: ProbePhase,
  opts: DastOptions,
  extraEnv: Record<string, string> = {},
): Promise<{ results: ProbeResult[]; started: boolean; reason?: string; sandboxMode?: string; seededRoles: string[]; routesProbed: number }> {
  const startOptions: StartAppOptions = {
    appDir: ctx.appDir,
    projectDir: ctx.projectDir,
    runId: ctx.runId,
    phase,
    buildSpec: ctx.buildSpec,
    testMode: ctx.manifest?.testMode,
    entry: opts.entry,
    extraEnv,
    extraReadPaths: opts.extraReadPaths,
    sandbox: opts.sandbox,
    readyTimeoutMs: opts.readyTimeoutMs,
    log: ctx.log,
    abort: ctx.abort,
  };

  let app: AppInstance;
  try {
    app = opts.start ? await opts.start(phase, ctx) : await startApp(startOptions);
  } catch (err) {
    const reason = startFailureReason(err);
    ctx.log(`[dast] ${phase} start failed: ${reason}`);
    return { results: notAttemptedForPhase(phase, reason), started: false, reason, seededRoles: [], routesProbed: 0 };
  }

  try {
    const built = await buildProbeContext({
      app,
      appDir: ctx.appDir,
      buildSpec: ctx.buildSpec,
      testMode: ctx.manifest?.testMode,
      auth: opts.auth,
      http: opts.client?.(app),
      ...(opts.routes ? { routes: opts.routes } : {}),
      log: ctx.log,
    });
    if (built.routesProblem && phase === 'test') ctx.log(`[dast] ${built.routesProblem}`);
    const results = await runProbes(built.ctx, {
      abort: ctx.abort,
      ...(opts.notApplicable ? { notApplicable: opts.notApplicable } : {}),
      onResult: (r) => ctx.log(`[dast] ${r.id}: ${r.passed === null ? `not attempted (${r.reason ?? 'no reason recorded'})` : r.passed ? 'ok' : `failed — ${r.observed}`}`),
    });
    return {
      results,
      started: true,
      sandboxMode: app.sandboxMode,
      seededRoles: [...built.ctx.sessions.values()].map((s) => s.role),
      routesProbed: built.ctx.routes?.routes.length ?? 0,
    };
  } finally {
    await app.stop();
  }
}

/** True when the app ships its own certificate, so the self-signed TLS start makes sense. */
export function hasCertificates(appDir: string): boolean {
  return existsSync(join(appDir, 'certs', 'cert.pem')) || existsSync(join(appDir, 'certs', 'server.crt'));
}

export async function runDast(ctx: ScanContext, opts: DastOptions = {}): Promise<ScanResult> {
  const build: DastBuildContext = { knowledge: ctx.knowledge, runId: ctx.runId, artifactPath: `pipeline/${ctx.runId}/dast/probes.json` };
  const phases: DastDetails['phases'] = [];
  const results: ProbeResult[] = [];
  let seededRoles: string[] = [];
  let routesProbed = 0;
  let sandboxMode: string | undefined;

  const test = await runPhase(ctx, 'test', opts);
  results.push(...test.results);
  phases.push({ phase: 'test', started: test.started, reason: test.reason, sandboxMode: test.sandboxMode });
  seededRoles = [...new Set(test.seededRoles)];
  routesProbed = test.routesProbed;
  sandboxMode = test.sandboxMode;

  if (!ctx.abort.aborted) {
    // Production mode behind a pretend TLS proxy: the second start the contract requires.
    const production = await runPhase(ctx, 'production', opts, { TRUST_PROXY_HOPS: '1' });
    results.push(...production.results);
    phases.push({ phase: 'production', started: production.started, reason: production.reason, sandboxMode: production.sandboxMode });
    sandboxMode ??= production.sandboxMode;
  } else {
    results.push(...notAttemptedForPhase('production', 'the run was cancelled before the production-mode checks'));
    phases.push({ phase: 'production', started: false, reason: 'the run was cancelled' });
  }

  if (ctx.buildSpec.features.tlsMode === 'selfsigned' && hasCertificates(ctx.appDir) && !ctx.abort.aborted) {
    const tls = await runPhase(ctx, 'selfsigned', opts);
    results.push(...tls.results);
    phases.push({ phase: 'selfsigned', started: tls.started, reason: tls.reason, sandboxMode: tls.sandboxMode });
  } else {
    const reason =
      ctx.buildSpec.features.tlsMode === 'selfsigned'
        ? 'the app has no certificate in certs/, so it could not be started with its own HTTPS'
        : 'this app is not configured to serve HTTPS itself (TLS is handled by loopback-only running or a reverse proxy)';
    results.push(...notAttemptedForPhase('selfsigned', reason));
    phases.push({ phase: 'selfsigned', started: false, reason });
  }

  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  for (const result of results) {
    const probe = probeById(result.id);
    evidence.push(...evidenceForResult(result, probe, build));
    findings.push(...findingsForResult(result, probe, build));
  }

  const counts = countOf(results);
  const anyStarted = phases.some((p) => p.started);
  const status = statusFor(findings, anyStarted);
  const details: DastDetails = { probes: results, seededRoles, routesProbed, phases, counts };

  const coverage: ToolCoverage = {
    tool: 'dast',
    ran: anyStarted,
    version: sandboxMode ? `securevibe-dast (${sandboxMode})` : 'securevibe-dast',
    reason: anyStarted ? undefined : `skipped: ${phases.find((p) => p.reason)?.reason ?? 'the app could not be started'}`,
    covers: DAST_COVERS,
  };

  const summary = anyStarted
    ? `Ran ${ALL_PROBES.length} runtime checks against your app: ${counts.passed} passed, ${counts.failed} found a problem, ${counts.notAttempted} could not be run.`
    : `Your app could not be started, so no runtime checks were run. ${phases.find((p) => p.reason)?.reason ?? ''}`.trim();

  return { findings, evidence, coverage, details, status, summary };
}

export type { DastAuthBootstrap } from './auth.js';
export { formAuthBootstrap } from './auth.js';
export { ALL_PROBES, probeById, probesForPhase } from './probes/index.js';
export { buildProbeContext, derivePaths, runProbes } from './runner.js';
export { startApp, AppStartError, generateAppEnv, resolveEntry, freePort, READY_TIMEOUT_MS } from './harness.js';
export { evidenceForResult, findingsForResult } from './findings.js';
export type { ProbeContext, ProbeModule, ProbeResult, ProbeOutcome, RoutesExport, SeededUser, Session } from './types.js';
