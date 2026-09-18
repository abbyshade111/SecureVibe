/**
 * The `external` stage: optional security scanners that may or may not be installed on this computer
 * (semgrep, gitleaks, trivy, osv-scanner). Whatever is on PATH is run against the app folder with JSON output
 * and mapped into ordinary findings; whatever is missing gets a coverage row saying "skipped: not installed",
 * so the report never implies coverage the run did not have.
 *
 * Nothing is downloaded and nothing is installed. The tools run through the same process sandbox as everything
 * else: no shell, an allow-listed environment, a time limit and an output cap.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import type { ToolCoverage } from '@shared/pipeline.js';
import { removeDir, runCommand } from '../../pipeline/process.js';
import { DEFAULT_IGNORE, ignorePatternToRegex } from '../sast/files.js';
import type { ScanContext, ScanResult, ScanStatus } from '../types.js';
import { PARSERS, toFinding, type ExternalFindingSeed, type ExternalToolName } from './parse.js';
import { NANO_ANALYZER, NANO_COVERS, runNanoAnalyzer, type NanoAnalyzerOptions } from './nano-analyzer.js';

export * from './parse.js';
export * from './nano-analyzer.js';

export const EXTERNAL_TOOL_TIMEOUT_MS = 5 * 60_000;

export const EXTERNAL_TOOLS: { name: ExternalToolName; covers: string }[] = [
  { name: 'semgrep', covers: 'Extra static analysis with community security rules.' },
  { name: 'gitleaks', covers: 'Extra search for passwords, keys and tokens written into files.' },
  { name: 'trivy', covers: 'Extra checks on packages, configuration files and secrets.' },
  { name: 'osv-scanner', covers: 'Extra check of your packages against the Open Source Vulnerabilities database.' },
];

/** Listed apart from the tools above: it is never run just because it is installed (see nano-analyzer.ts). */
export const OPT_IN_TOOLS: { name: ExternalToolName; covers: string }[] = [{ name: NANO_ANALYZER, covers: NANO_COVERS }];

export interface DetectedTool {
  name: ExternalToolName;
  path: string;
  version?: string;
}

export function findOnPath(name: string, pathValue = process.env['PATH'] ?? ''): string | undefined {
  const names = process.platform === 'win32' ? [`${name}.exe`, `${name}.cmd`, `${name}.bat`, name] : [name];
  for (const dir of pathValue.split(delimiter).filter(Boolean)) {
    for (const candidate of names) {
      const full = join(dir, candidate);
      if (existsSync(full)) return full;
    }
  }
  return undefined;
}

/** First version-looking token in a `--version` output ("semgrep 1.2.3", "v8.18.2", "Version: 0.49.0"). */
export function parseVersion(output: string): string | undefined {
  return /\bv?(\d+\.\d+(?:\.\d+)?)\b/.exec(output)?.[1];
}

export async function detectTool(name: ExternalToolName, _cwd?: string): Promise<DetectedTool | undefined> {
  const file = findOnPath(name);
  if (!file) return undefined;
  // A throw-away folder: tools write caches and logs into HOME, which must not land in the app being checked.
  const scratch = mkdtempSync(join(tmpdir(), 'securevibe-detect-'));
  try {
    const result = await runCommand(file, ['--version'], { cwd: scratch, projectDir: scratch, timeoutMs: 20_000, maxOutputBytes: 64 * 1024 });
    return { name, path: file, version: parseVersion(`${result.stdout}\n${result.stderr}`) };
  } catch {
    return { name, path: file };
  } finally {
    removeDir(scratch);
  }
}

export interface ToolRunContext {
  appDir: string;
  reportFile: string;
  /** A scratch folder for files the tool needs (gitleaks' config). */
  workDir: string;
  version?: string;
  /** SecureVibe's ignore patterns (gitignore style): the same folders its own scanners leave out. */
  exclude: string[];
}

interface ToolRun {
  args: (run: ToolRunContext) => string[];
  /** Where the JSON ends up: the tool's stdout, or a file it was told to write. */
  output: 'stdout' | 'file';
}

function majorVersion(version: string | undefined): number {
  return Number.parseInt(version?.split('.')[0] ?? '', 10);
}

const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];

/** "templates/**" → "templates"; bare names stay as they are. */
function excludeDir(pattern: string): string {
  return pattern.replace(/\/\*\*$/, '').replace(/^\//, '');
}

/**
 * Files the secret scanners skip: `.env` and FIRST-LOGIN.txt hold an app's secrets by design (SecureVibe's own
 * configuration checks cover both), and provenance and lockfiles are full of hashes that look like keys.
 */
const SECRET_SCAN_SKIP_FILES = ['.env', 'FIRST-LOGIN.txt', 'securevibe.provenance.json', 'package-lock.json'];

/** A gitleaks config that keeps the default rules and skips the excluded folders and files. */
function gitleaksConfig(run: ToolRunContext): string {
  const paths = [...run.exclude, ...SECRET_SCAN_SKIP_FILES].map((p) => {
    const source = ignorePatternToRegex(p).source.replace(/^\^/, '(^|/)');
    return `  '''${source}''',`;
  });
  const file = join(run.workDir, 'gitleaks.toml');
  writeFileSync(file, ['[extend]', 'useDefault = true', '', '[[allowlists]]', 'description = "Folders SecureVibe does not scan"', 'paths = [', ...paths, ']', ''].join('\n'));
  return file;
}

/** The tools found on PATH and run the same way. nano-analyzer is not one of them: it has its own module. */
const RUNS: Record<Exclude<ExternalToolName, typeof NANO_ANALYZER>, ToolRun> = {
  // With metrics off, semgrep needs named rule sets (they are downloaded from the Semgrep registry).
  semgrep: {
    args: (run) => [
      'scan',
      '--config', 'p/owasp-top-ten',
      '--config', 'p/typescript',
      ...run.exclude.flatMap((p) => ['--exclude', excludeDir(p)]),
      '--json', '--quiet', '--disable-version-check', '--metrics=off',
      run.appDir,
    ],
    output: 'stdout',
  },
  gitleaks: {
    args: (run) => ['detect', '--no-git', '--redact', '--config', gitleaksConfig(run), '--source', run.appDir, '--report-format', 'json', '--report-path', run.reportFile],
    output: 'file',
  },
  // trivy downloads its vulnerability database on first use and refreshes it when it is out of date.
  trivy: {
    args: (run) => [
      'fs',
      '--scanners', 'vuln,secret,misconfig',
      ...run.exclude.flatMap((p) => ['--skip-dirs', p.includes('/') ? excludeDir(p) : `**/${p}`]),
      ...SECRET_SCAN_SKIP_FILES.filter((f) => f !== 'package-lock.json').flatMap((f) => ['--skip-files', `**/${f}`]),
      '--format', 'json', '--quiet',
      run.appDir,
    ],
    output: 'stdout',
  },
  // osv-scanner is given the app's lockfiles directly: its directory walk finds nothing in some versions.
  'osv-scanner': {
    args: (run) => {
      const lockfiles = LOCKFILES.map((f) => join(run.appDir, f)).filter((f) => existsSync(f));
      const flags = ['--format', 'json', ...lockfiles.flatMap((f) => ['--lockfile', f])];
      return majorVersion(run.version) >= 2 ? ['scan', 'source', ...flags] : flags;
    },
    output: 'stdout',
  },
};

/** The command-line arguments SecureVibe passes to a tool (exported for tests). */
export function externalArgs(name: Exclude<ExternalToolName, typeof NANO_ANALYZER>, run: ToolRunContext): string[] {
  return RUNS[name].args(run);
}

export interface ExternalToolResult {
  name: ExternalToolName;
  installed: boolean;
  ran: boolean;
  version?: string;
  reason?: string;
  findingCount: number;
  durationMs: number;
}

export interface ExternalDetails {
  tools: ExternalToolResult[];
  /** One coverage row per tool, for the report's tool-coverage table. */
  coverage: ToolCoverage[];
}

export interface RunExternalOptions {
  /** Restrict the run to these tools (tests use it). */
  only?: ExternalToolName[];
  timeoutMs?: number;
  /** nano-analyzer's settings. Left out, or switched off, means it does not run. */
  nano?: NanoAnalyzerOptions;
}

/**
 * Where the optional scanners keep what they download. Each project has its own HOME, so without this trivy fetches
 * its whole vulnerability database (about 1.3 GB) again for every app: four apps meant five gigabytes of the same
 * file. One folder for the workspace fixes that, and the tools still write nothing into the app being checked.
 */
export function toolCacheEnv(cacheDir: string): Record<string, string> {
  mkdirSync(cacheDir, { recursive: true });
  return {
    TRIVY_CACHE_DIR: join(cacheDir, 'trivy'),
    // semgrep and osv-scanner follow the usual cache and config variables.
    XDG_CACHE_HOME: join(cacheDir, 'xdg'),
    SEMGREP_SETTINGS_FILE: join(cacheDir, 'semgrep', 'settings.yml'),
  };
}

function coverageRow(tool: ExternalToolResult, covers: string): ToolCoverage {
  return {
    tool: tool.name,
    ran: tool.ran,
    version: tool.version,
    reason: tool.ran ? undefined : (tool.reason ?? 'skipped: not installed'),
    covers,
  };
}

function statusFor(findings: Finding[], anyRan: boolean): ScanStatus {
  if (!anyRan) return 'skipped';
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 'failed';
  if (findings.length > 0) return 'warning';
  return 'passed';
}

export async function runExternal(ctx: ScanContext, opts: RunExternalOptions = {}): Promise<ScanResult> {
  const wanted = EXTERNAL_TOOLS.filter((t) => !opts.only || opts.only.includes(t.name));
  const findings: Finding[] = [];
  const tools: ExternalToolResult[] = [];
  const coverageRows: ToolCoverage[] = [];

  for (const { name, covers } of wanted) {
    const started = Date.now();
    const detected = await detectTool(name, ctx.appDir);
    if (!detected) {
      const result: ExternalToolResult = { name, installed: false, ran: false, reason: 'skipped: not installed', findingCount: 0, durationMs: Date.now() - started };
      tools.push(result);
      coverageRows.push(coverageRow(result, covers));
      continue;
    }
    if (ctx.abort.aborted) {
      const result: ExternalToolResult = { name, installed: true, ran: false, version: detected.version, reason: 'skipped: the run was cancelled', findingCount: 0, durationMs: 0 };
      tools.push(result);
      coverageRows.push(coverageRow(result, covers));
      continue;
    }

    ctx.log(`[external] running ${name}${detected.version ? ` ${detected.version}` : ''}`);
    const spec = RUNS[name as Exclude<ExternalToolName, typeof NANO_ANALYZER>];
    const workDir = mkdtempSync(join(tmpdir(), 'securevibe-external-'));
    const reportFile = join(workDir, `${name}.json`);
    let seeds: ExternalFindingSeed[] = [];
    let reason: string | undefined;
    let ran = false;
    try {
      const exclude = [...DEFAULT_IGNORE, ...ctx.ignore];
      const run = await runCommand(detected.path, spec.args({ appDir: ctx.appDir, reportFile, workDir, version: detected.version, exclude }), {
        cwd: ctx.appDir,
        projectDir: ctx.projectDir,
        runId: ctx.runId,
        timeoutMs: opts.timeoutMs ?? EXTERNAL_TOOL_TIMEOUT_MS,
        maxOutputBytes: 16 * 1024 * 1024,
        abort: ctx.abort,
        env: toolCacheEnv(ctx.toolCacheDir),
      });
      const text = spec.output === 'file' ? (existsSync(reportFile) ? readFileSync(reportFile, 'utf8') : '') : run.stdout;
      if (run.timedOut) {
        reason = 'skipped: the tool was stopped at the time limit';
      } else if (text.trim() === '') {
        // gitleaks writes nothing when it finds nothing; a zero exit code means it ran fine.
        if (run.code === 0) {
          ran = true;
        } else {
          reason = `skipped: ${name} produced no output (exit code ${run.code ?? 'unknown'})`;
        }
      } else {
        seeds = PARSERS[name](text, ctx.appDir);
        // A parse that yields nothing from non-empty output usually means the tool reported an error object.
        ran = seeds.length > 0 || run.code === 0 || /^[[{]/.test(text.trim());
        if (!ran) reason = `skipped: ${name} did not return results SecureVibe could read (exit code ${run.code ?? 'unknown'})`;
      }
    } catch (err) {
      reason = `skipped: ${name} could not be run (${(err as Error).message})`;
    } finally {
      removeDir(workDir);
    }

    for (const seed of seeds) findings.push(toFinding(seed, detected.version));
    const result: ExternalToolResult = {
      name,
      installed: true,
      ran,
      version: detected.version,
      reason,
      findingCount: seeds.length,
      durationMs: Date.now() - started,
    };
    tools.push(result);
    coverageRows.push(coverageRow(result, covers));
  }

  // The opt-in AI scanner, last: it is the slowest and the only one that costs money.
  if (!opts.only || opts.only.includes(NANO_ANALYZER)) {
    const started = Date.now();
    const workDir = mkdtempSync(join(tmpdir(), 'securevibe-nano-'));
    try {
      const nano = await runNanoAnalyzer(
        {
          appDir: ctx.appDir,
          ignore: ctx.ignore,
          projectDir: ctx.projectDir,
          runId: ctx.runId,
          workDir,
          log: ctx.log,
          abort: ctx.abort,
          run: async (file, args, env, timeoutMs) => {
            const result = await runCommand(file, args, {
              cwd: ctx.appDir,
              projectDir: ctx.projectDir,
              runId: ctx.runId,
              timeoutMs,
              maxOutputBytes: 16 * 1024 * 1024,
              abort: ctx.abort,
              env,
            });
            return { code: result.code, timedOut: result.timedOut, stderr: result.stderr };
          },
        },
        opts.nano ?? { enabled: false, scriptPath: '', model: '', minConfidence: 1 },
      );
      for (const seed of nano.seeds) findings.push(toFinding(seed));
      const result: ExternalToolResult = {
        name: NANO_ANALYZER,
        installed: nano.ran || !nano.reason?.includes('not switched on'),
        ran: nano.ran,
        reason: nano.reason ?? (nano.leftOut ? `read ${nano.filesScanned ?? 0} of your source files; ${nano.leftOut} more were left out to keep the cost down` : undefined),
        findingCount: nano.seeds.length,
        durationMs: Date.now() - started,
      };
      tools.push(result);
      coverageRows.push(coverageRow(result, NANO_COVERS));
    } finally {
      removeDir(workDir);
    }
  }

  const ranTools = tools.filter((t) => t.ran);
  const details: ExternalDetails = { tools, coverage: coverageRows };
  const installedNotRun = tools.filter((t) => t.installed && !t.ran);

  const summary =
    ranTools.length === 0
      ? 'No extra security scanners are installed on this computer, so none were run. This is normal — the built-in checks still ran.'
      : `Ran ${ranTools.length} extra scanner${ranTools.length === 1 ? '' : 's'} (${ranTools.map((t) => t.name).join(', ')}) and found ${findings.length} thing${findings.length === 1 ? '' : 's'} to look at.`;

  const coverage: ToolCoverage = {
    tool: 'external',
    ran: ranTools.length > 0,
    version: ranTools.map((t) => `${t.name}${t.version ? ` ${t.version}` : ''}`).join(', ') || undefined,
    reason:
      ranTools.length > 0
        ? installedNotRun.length > 0
          ? `${installedNotRun.map((t) => `${t.name}: ${t.reason ?? 'did not run'}`).join('; ')}`
          : undefined
        : 'skipped: not installed (semgrep, gitleaks, trivy and osv-scanner are optional extras)',
    covers: 'Optional extra scanners installed on this computer; they add coverage when present.',
  };

  const evidence: Evidence[] = [];
  return { findings, evidence, coverage, details, status: statusFor(findings, ranTools.length > 0), summary };
}

/** The per-tool coverage rows of an external scan, for the report's tool-coverage table. */
export function externalCoverageRows(result: ScanResult): ToolCoverage[] {
  const details = result.details as ExternalDetails | undefined;
  return details?.coverage ?? [];
}
