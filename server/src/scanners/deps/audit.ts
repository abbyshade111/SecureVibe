/**
 * `npm audit --json` against the generated app, plus the on-disk cache that keeps the last successful answer per
 * lockfile so an offline run can still say something useful — clearly labelled with the date the advisory data
 * was fetched (`vulnDbAsOf`).
 *
 * npm exits non-zero when it finds vulnerabilities, so the exit code is ignored: only whether the output parses
 * as an audit report decides between "ran" and "skipped (offline)".
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Severity } from '@shared/findings.js';
import { runNpm } from '../../pipeline/process.js';

export const AUDIT_TIMEOUT_MS = 90_000;

export type NpmSeverity = 'info' | 'low' | 'moderate' | 'high' | 'critical';

export const SEVERITY_FROM_NPM: Record<NpmSeverity, Severity> = {
  info: 'info',
  low: 'low',
  moderate: 'medium',
  high: 'high',
  critical: 'critical',
};

export interface Advisory {
  /** Package the advisory is about. */
  package: string;
  title: string;
  severity: Severity;
  /** GHSA-…/CVE-… ids extracted from the advisory urls plus npm's own numeric ids. */
  ids: string[];
  url?: string;
  cwe: string[];
  cvss?: number;
  vulnerableRange?: string;
  /** Version that fixes it, when npm knows one. */
  fixedVersion?: string;
  fixIsMajor?: boolean;
  isDirect: boolean;
  /** Packages that depend on the vulnerable one (npm's `effects`). */
  effects: string[];
}

export interface AuditReport {
  advisories: Advisory[];
  /** npm's own count by severity. */
  metadata?: Record<string, number>;
  /** ISO date the advisory data was fetched (now for a live run, the cached date for a reused one). */
  vulnDbAsOf: string;
  fromCache: boolean;
}

export type AuditOutcome =
  | { ok: true; report: AuditReport }
  | { ok: false; reason: string; stderrExcerpt?: string };

interface RawVia {
  source?: number;
  name?: string;
  dependency?: string;
  title?: string;
  url?: string;
  severity?: NpmSeverity;
  cwe?: string[];
  cvss?: { score?: number; vectorString?: string };
  range?: string;
}

interface RawVulnerability {
  name?: string;
  severity?: NpmSeverity;
  isDirect?: boolean;
  via?: (RawVia | string)[];
  effects?: string[];
  range?: string;
  fixAvailable?: boolean | { name?: string; version?: string; isSemVerMajor?: boolean };
}

interface RawAuditReport {
  auditReportVersion?: number;
  vulnerabilities?: Record<string, RawVulnerability>;
  metadata?: { vulnerabilities?: Record<string, number> };
  error?: unknown;
}

function idsFromUrl(url: string | undefined): string[] {
  if (!url) return [];
  const ghsa = /GHSA-[a-z0-9-]+/i.exec(url)?.[0];
  const cve = /CVE-\d{4}-\d+/i.exec(url)?.[0];
  return [ghsa, cve].filter((v): v is string => Boolean(v));
}

/** Turns npm's nested `vulnerabilities` map into one flat advisory per (package, advisory) pair. */
export function parseAuditJson(text: string): AuditReport | undefined {
  let raw: RawAuditReport;
  try {
    raw = JSON.parse(text) as RawAuditReport;
  } catch {
    return undefined;
  }
  if (!raw || typeof raw !== 'object' || raw.vulnerabilities === undefined) return undefined;

  const advisories: Advisory[] = [];
  const seen = new Set<string>();
  for (const [pkg, vuln] of Object.entries(raw.vulnerabilities)) {
    const fix = vuln.fixAvailable;
    const fixedVersion = typeof fix === 'object' && fix ? fix.version : undefined;
    const fixIsMajor = typeof fix === 'object' && fix ? fix.isSemVerMajor : undefined;
    const vias = (vuln.via ?? []).filter((v): v is RawVia => typeof v === 'object' && v !== null);
    const indirect = (vuln.via ?? []).filter((v): v is string => typeof v === 'string');

    for (const via of vias) {
      const ids = [...idsFromUrl(via.url), ...(via.source !== undefined ? [`npm-${via.source}`] : [])];
      const key = `${pkg}|${ids.join(',') || via.title || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      advisories.push({
        package: via.name ?? vuln.name ?? pkg,
        title: via.title ?? `Known vulnerability in ${pkg}`,
        severity: SEVERITY_FROM_NPM[via.severity ?? vuln.severity ?? 'moderate'] ?? 'medium',
        ids,
        url: via.url,
        cwe: via.cwe ?? [],
        cvss: via.cvss?.score,
        vulnerableRange: via.range ?? vuln.range,
        fixedVersion,
        fixIsMajor,
        isDirect: vuln.isDirect === true,
        effects: vuln.effects ?? [],
      });
    }

    // A package that is only vulnerable through a dependency still deserves one row.
    if (vias.length === 0 && indirect.length > 0) {
      const key = `${pkg}|via:${indirect.join(',')}`;
      if (!seen.has(key)) {
        seen.add(key);
        advisories.push({
          package: vuln.name ?? pkg,
          title: `${pkg} depends on a vulnerable package (${indirect.join(', ')})`,
          severity: SEVERITY_FROM_NPM[vuln.severity ?? 'moderate'] ?? 'medium',
          ids: [],
          cwe: [],
          vulnerableRange: vuln.range,
          fixedVersion,
          fixIsMajor,
          isDirect: vuln.isDirect === true,
          effects: vuln.effects ?? [],
        });
      }
    }
  }

  return { advisories, metadata: raw.metadata?.vulnerabilities, vulnDbAsOf: new Date().toISOString(), fromCache: false };
}

export function cacheDir(projectDir: string): string {
  return join(projectDir, 'pipeline', 'cache');
}

function cacheFile(projectDir: string, lockfileHash: string): string {
  return join(cacheDir(projectDir), `audit-${lockfileHash.slice(0, 32)}.json`);
}

export function readAuditCache(projectDir: string, lockfileHash: string): AuditReport | undefined {
  const file = cacheFile(projectDir, lockfileHash);
  if (!existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { lockfileHash?: string; report?: AuditReport };
    if (parsed.lockfileHash !== lockfileHash || !parsed.report) return undefined;
    return { ...parsed.report, fromCache: true };
  } catch {
    return undefined;
  }
}

export function writeAuditCache(projectDir: string, lockfileHash: string, report: AuditReport): void {
  try {
    mkdirSync(cacheDir(projectDir), { recursive: true });
    writeFileSync(cacheFile(projectDir, lockfileHash), JSON.stringify({ lockfileHash, report }, null, 2));
  } catch {
    // The cache is an optimisation; failing to write it must never fail the scan.
  }
}

export interface RunAuditOptions {
  appDir: string;
  projectDir: string;
  runId?: string;
  lockfileHash?: string;
  timeoutMs?: number;
  abort?: AbortSignal;
  /** Extra environment for npm (the offline test points npm_config_registry at a dead port). */
  env?: Record<string, string>;
  log?(msg: string): void;
}

/**
 * Runs `npm audit --json`. Any exit code is accepted; only unparsable output means the check did not run.
 * On failure the cached report for the same lockfile is reused and marked as coming from cache.
 */
export async function runAudit(opts: RunAuditOptions): Promise<AuditOutcome> {
  const log = opts.log ?? (() => {});
  const result = await runNpm(['audit', '--json', '--no-fund', '--no-update-notifier'], {
    cwd: opts.appDir,
    projectDir: opts.projectDir,
    runId: opts.runId,
    timeoutMs: opts.timeoutMs ?? AUDIT_TIMEOUT_MS,
    abort: opts.abort,
    env: { npm_config_audit: 'true', ...(opts.env ?? {}) },
    passThroughEnv: ['npm_config_registry', 'npm_config_proxy', 'npm_config_https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'],
  });

  const report = parseAuditJson(result.stdout);
  if (report) {
    if (opts.lockfileHash) writeAuditCache(opts.projectDir, opts.lockfileHash, report);
    return { ok: true, report };
  }

  const cached = opts.lockfileHash ? readAuditCache(opts.projectDir, opts.lockfileHash) : undefined;
  if (cached) {
    log(`[deps] npm audit could not reach the advisory service; reusing the result from ${cached.vulnDbAsOf}`);
    return { ok: true, report: cached };
  }
  const reason = result.timedOut
    ? 'npm audit took too long and was stopped'
    : 'npm audit could not reach the vulnerability database (this computer may be offline)';
  return { ok: false, reason, stderrExcerpt: (result.stderr || result.stdout).slice(0, 500) };
}
