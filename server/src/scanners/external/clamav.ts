/**
 * ClamAV: the one check that asks whether a *file* is known-bad, rather than whether *code* is weak.
 *
 * Everything else SecureVibe runs reads source and reasons about it. None of that notices a genuine JPEG that
 * carries a known exploit, or a document with a malicious macro: those files are not badly written, they are
 * hostile, and the only practical way to recognise them is a signature database somebody else maintains.
 *
 * Where it runs, and why the answer differs by case (ADR-011):
 *  - **An uploaded application** — code an owner handed us and which we will never run — is scanned as part of
 *    the ordinary check, not behind a switch. That is the clearest untrusted content SecureVibe ever holds.
 *  - **An application SecureVibe built** is scanned only when the owner asks. Source code is not where virus
 *    signatures earn their keep, and running it by default would spend minutes to say almost nothing.
 *
 * Two honesty rules this module exists to keep:
 *  1. **A scan that did not happen is never a clean result.** Not installed, daemon not running, timed out,
 *     refused — each is reported as its own reason, and `ran` stays false.
 *  2. **A clean result is reported with the age of the signatures that produced it.** ClamAV with a database
 *     six months old is close to worthless, and it looks exactly like ClamAV with a fresh one. The version
 *     string carries the database's own build date, so SecureVibe reads it and says so.
 */
import { existsSync } from 'node:fs';
import { relative, isAbsolute } from 'node:path';
import type { Severity } from '@shared/findings.js';
import type { ExternalFindingSeed } from './parse.js';

export const CLAMAV = 'clamav';

export const CLAMAV_COVERS = 'Checks the files themselves against a database of known viruses and malicious documents.';

/** The daemon is tried first: it holds the signatures in memory, so a scan takes seconds rather than minutes. */
export const CLAMAV_COMMANDS = ['clamdscan', 'clamscan'] as const;
export type ClamavCommand = (typeof CLAMAV_COMMANDS)[number];

/** Beyond this the signatures are old enough that a clean result deserves a caveat rather than a tick. */
export const SIGNATURES_STALE_AFTER_DAYS = 30;

export interface ClamavVersion {
  /** "1.0.3" */
  engine?: string;
  /** The signature database's own build number. */
  database?: string;
  /** When that database was built, if the version string carried a date. */
  databaseDate?: Date;
}

/**
 * `clamscan --version` prints "ClamAV 1.0.3/27263/Mon Sep 15 09:12:44 2026", which is the engine, the signature
 * database's build number, and the date that database was built. Older builds print the engine alone.
 */
export function parseClamavVersion(output: string): ClamavVersion {
  const line = output.split('\n').find((l) => /ClamAV/i.test(l))?.trim() ?? output.trim();
  const match = /ClamAV\s+([0-9][^/\s]*)(?:\/([0-9]+))?(?:\/(.+))?/i.exec(line);
  if (!match) return {};
  const [, engine, database, dateText] = match;
  const parsed = dateText ? new Date(dateText.trim()) : undefined;
  return {
    ...(engine ? { engine } : {}),
    ...(database ? { database } : {}),
    ...(parsed && !Number.isNaN(parsed.getTime()) ? { databaseDate: parsed } : {}),
  };
}

/** Whole days between the signature database being built and now; undefined when the date is unknown. */
export function signatureAgeInDays(version: ClamavVersion, now = new Date()): number | undefined {
  if (!version.databaseDate) return undefined;
  return Math.floor((now.getTime() - version.databaseDate.getTime()) / 86_400_000);
}

/**
 * What the report says about the signatures a result rests on. Always present on a scan that ran, because "we
 * found nothing" means nothing without it.
 */
export function signatureNote(version: ClamavVersion, now = new Date()): string {
  const age = signatureAgeInDays(version, now);
  if (age === undefined) {
    return 'The scanner did not report when its virus signatures were last updated, so how current they are is unknown.';
  }
  const when = age <= 0 ? 'today' : age === 1 ? 'yesterday' : `${age} days ago`;
  if (age > SIGNATURES_STALE_AFTER_DAYS) {
    return `The virus signatures were last updated ${when}, which is old enough that a clean result means less than it looks. Run "freshclam" to update them.`;
  }
  return `Checked against virus signatures last updated ${when}.`;
}

/** The arguments for a scan of one folder or file. */
export function clamavArgs(command: ClamavCommand, target: string, exclude: string[] = []): string[] {
  if (command === 'clamdscan') {
    // --fdpass hands the daemon an open file descriptor, which is what makes a scan work when clamd runs as its
    // own user and cannot read the owner's folders. Without it a perfectly ordinary setup reports "Access denied".
    return ['--fdpass', '--infected', '--no-summary', target];
  }
  return [
    '--recursive',
    '--infected',
    '--no-summary',
    ...exclude.map((pattern) => `--exclude-dir=${excludeRegex(pattern)}`),
    target,
  ];
}

/** `clamscan --exclude-dir` takes a regular expression, not a glob. "node_modules/**" → "(^|/)node_modules(/|$)". */
export function excludeRegex(pattern: string): string {
  const name = pattern.replace(/\/\*\*$/, '').replace(/^\//, '').replace(/\/$/, '');
  return `(^|/)${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(/|$)`;
}

export interface ClamavDetection {
  file: string;
  signature: string;
}

/**
 * Both commands print one line per infected file: "/path/to/file: Eicar-Test-Signature FOUND". Everything else —
 * "OK" lines, the summary, permission errors — is either suppressed by `--no-summary --infected` or is not a
 * detection, so only the FOUND lines are read.
 */
export function parseClamavOutput(stdout: string, appDir?: string): ClamavDetection[] {
  const detections: ClamavDetection[] = [];
  for (const raw of stdout.split('\n')) {
    const line = raw.trim();
    const match = /^(.*?):\s+(.+?)\s+FOUND$/.exec(line);
    if (!match) continue;
    const [, file, signature] = match;
    if (!file || !signature) continue;
    detections.push({ file: appDir ? toRelative(appDir, file) : file, signature });
  }
  return detections;
}

function toRelative(appDir: string, file: string): string {
  const clean = isAbsolute(file) ? relative(appDir, file) : file;
  return clean.replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * A detection is reported at the highest severity there is, deliberately and without a confidence score. ClamAV
 * does not guess: a signature matched a known sample. The right response to one of these in an app folder is to
 * stop and look, not to weigh it against the other findings.
 */
export function clamavSeverity(): Severity {
  return 'critical';
}

export function toClamavSeed(detection: ClamavDetection, version: ClamavVersion): ExternalFindingSeed {
  return {
    tool: CLAMAV as ExternalFindingSeed['tool'],
    ruleId: `external.clamav.${detection.signature.replace(/[^A-Za-z0-9._-]/g, '-')}`,
    title: `A file matches a known virus signature (${detection.signature})`,
    severity: clamavSeverity(),
    file: detection.file,
    description:
      `The virus scanner recognised this file as ${detection.signature}, which is a signature for content that is known to be malicious. ` +
      'This is not a guess about how the code is written: the file itself matched a known bad sample. ' +
      'Do not open it, and do not copy it anywhere else. ' +
      `${signatureNote(version)}`,
    evidence: `clamav reported: ${detection.file}: ${detection.signature} FOUND`,
    cwe: ['CWE-509'],
    references: ['https://docs.clamav.net/'],
  };
}

/** How a finished scan is read. ClamAV uses 0 for clean, 1 for "something was found", 2 for "it went wrong". */
export type ClamavOutcome =
  | { kind: 'clean' }
  | { kind: 'infected'; detections: ClamavDetection[] }
  | { kind: 'error'; reason: string };

export function readClamavExit(code: number, stdout: string, stderr: string, appDir?: string): ClamavOutcome {
  if (code === 0) return { kind: 'clean' };
  if (code === 1) {
    const detections = parseClamavOutput(stdout, appDir);
    // Exit 1 means a detection, so an empty parse is a parsing failure on our side and must not read as clean.
    if (detections.length === 0) {
      return { kind: 'error', reason: 'The scanner reported that it found something, but its output could not be read.' };
    }
    return { kind: 'infected', detections };
  }
  const text = `${stderr}\n${stdout}`;
  // Checked before everything else, because this is the case that lies. ClamAV with no signature database
  // prints "ERROR: Can't open file or directory" on the line after the real reason, so anything reading the
  // last line alone concludes the file was unreadable and moves on. The scanner is installed, it answers, and
  // it cannot check anything: the most dangerous of the three ways this can go wrong.
  if (/No supported database files|cli_loaddbdir|Can't open\/parse database/i.test(text)) {
    return {
      kind: 'error',
      reason: 'The virus scanner is installed but has not downloaded its virus signatures yet, so nothing was checked. Run "freshclam" once to fetch them.',
    };
  }
  if (/Can't connect to clamd|Could not connect|ERROR: Can't access|socket/i.test(text)) {
    return { kind: 'error', reason: 'The virus scanner\u2019s background service (clamd) is installed but not running, so nothing was scanned.' };
  }
  if (/Access denied|Permission denied|lstat\(\) failed/i.test(text)) {
    return { kind: 'error', reason: 'The virus scanner could not read the files it was asked to check, so nothing was scanned.' };
  }
  return { kind: 'error', reason: `The virus scanner stopped with an error, so nothing was scanned (exit code ${code}).` };
}

/** True when this project's files are ones SecureVibe was handed rather than ones it wrote (ADR-011). */
export function scanIsMandatory(originKind: string | undefined): boolean {
  return originKind === 'uploaded';
}

/** Somewhere to point the scanner: the app folder, or a subfolder of it that actually exists. */
export function scanTarget(appDir: string, subPath?: string): string {
  if (!subPath) return appDir;
  const full = `${appDir.replace(/\/$/, '')}/${subPath.replace(/^\//, '')}`;
  return existsSync(full) ? full : appDir;
}

// --- running it ----------------------------------------------------------------------------------

export interface ClamavRunOptions {
  /** Whether to run at all. Mandatory for an uploaded app; opt-in for one SecureVibe built (ADR-011). */
  enabled: boolean;
  appDir: string;
  exclude: string[];
  timeoutMs: number;
  log: (msg: string) => void;
  /** Supplied by the caller so this module never imports the process runner. */
  run: (file: string, args: string[], timeoutMs: number) => Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }>;
  /** Looks a command up on PATH. Injected for the same reason. */
  find: (name: string) => string | undefined;
}

export interface ClamavRunResult {
  ran: boolean;
  installed: boolean;
  seeds: ExternalFindingSeed[];
  version?: string;
  /** Present whenever `ran` is false, and always a sentence saying what was not checked. */
  reason?: string;
  /** The signature-age sentence, when a scan actually happened. */
  note?: string;
}

const NOT_ENABLED = 'skipped: not switched on for this project (it runs by itself only for an app you uploaded)';

/**
 * Runs the scanner over the app folder and turns what it said into findings.
 *
 * Never throws and never returns `ran: true` without having read a real answer. The three unhappy endings —
 * not installed, no signatures, could not run — each come back as their own sentence, because a report that
 * says "did not run" without saying why invites the reader to assume it was nothing important.
 */
export async function runClamavScan(opts: ClamavRunOptions): Promise<ClamavRunResult> {
  if (!opts.enabled) return { ran: false, installed: false, seeds: [], reason: NOT_ENABLED };

  const command = CLAMAV_COMMANDS.find((c) => opts.find(c));
  const file = command ? opts.find(command) : undefined;
  if (!command || !file) {
    return { ran: false, installed: false, seeds: [], reason: 'skipped: not installed (ClamAV is an optional extra)' };
  }

  let version: ClamavVersion = {};
  try {
    const v = await opts.run(file, ['--version'], 20_000);
    version = parseClamavVersion(`${v.stdout}\n${v.stderr}`);
  } catch {
    // A version we could not read is not a reason to skip the scan; it is a reason to say so afterwards.
  }

  opts.log(`[external] running ${command}${version.engine ? ` ${version.engine}` : ''}`);
  let result: Awaited<ReturnType<ClamavRunOptions['run']>>;
  try {
    result = await opts.run(file, clamavArgs(command, opts.appDir, opts.exclude), opts.timeoutMs);
  } catch (err) {
    return { ran: false, installed: true, seeds: [], reason: `skipped: ${command} could not be run (${err instanceof Error ? err.message : String(err)})` };
  }
  if (result.timedOut) {
    return { ran: false, installed: true, seeds: [], reason: 'skipped: the virus scanner was stopped at the time limit, so the files were not checked' };
  }

  const outcome = readClamavExit(result.code ?? 2, result.stdout, result.stderr, opts.appDir);
  if (outcome.kind === 'error') {
    return { ran: false, installed: true, seeds: [], version: version.engine, reason: `skipped: ${outcome.reason}` };
  }
  const detections = outcome.kind === 'infected' ? outcome.detections : [];
  return {
    ran: true,
    installed: true,
    seeds: detections.map((d) => toClamavSeed(d, version)),
    version: version.engine,
    note: signatureNote(version),
  };
}
