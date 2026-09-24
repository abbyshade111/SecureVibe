/**
 * nano-analyzer (https://github.com/weareaisle/nano-analyzer): an optional, experimental scanner that reads the
 * app's source code with a language model and reports what it thinks could be a vulnerability.
 *
 * It is treated differently from the other optional scanners, for three honest reasons:
 *
 *  1. It costs money. Every file is sent to OpenAI (or OpenRouter) and read several times over, so a scan of a
 *     whole app is a real bill on the owner's own key. It therefore never runs unless it has been switched on in
 *     Settings, and SecureVibe says what it will do before it does it.
 *  2. It sends the app's code to that service. That is a decision only the owner can make.
 *  3. Its own authors call it a research prototype: it was built for C and C++ memory-safety bugs, "will scan
 *     other languages but is much less effective there", and it reports things that are not real. Its findings are
 *     therefore recorded as suggestions to look at — low confidence, never evidence — so nothing in a compliance
 *     report can ever rest on them. They are extra eyes, not a verdict.
 *
 * SecureVibe reads the tool's own triage output: nano-analyzer scans each file, then argues with itself over
 * several rounds about whether each finding is real, and writes the survivors to `findings/VULN-*.md` with the
 * share of rounds that thought so. Only survivors at or above the confidence the owner set are brought in.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import type { Severity } from '@shared/findings.js';
import { DEFAULT_IGNORE, listAppFiles } from '../sast/files.js';
import type { ExternalFindingSeed } from './parse.js';

export const NANO_ANALYZER = 'nano-analyzer';

/**
 * nano-analyzer walks whatever folder it is given with no exclusions at all, so pointing it at an app folder would
 * read `node_modules` as well — thousands of files, every one of them paid for at the owner's AI service. SecureVibe
 * therefore never gives it the app folder. It copies the app's own source files into a scratch folder first, using
 * the same ignore list as SecureVibe's own code scanner, and gives it that.
 */
const NANO_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.rb', '.go', '.rs', '.java', '.php', '.sh']);

/** A hard stop on the size of one scan, so a large app cannot turn into a large bill without warning. */
export const NANO_MAX_FILES = 300;
export const NANO_MAX_FILE_BYTES = 200 * 1024;

export interface NanoStaging {
  dir: string;
  copied: number;
  /** Files that matched but were left out because the limit was reached; the report says so. */
  leftOut: number;
}

/** Copies the app's own source files into `stagingDir`, keeping their paths, and reports what was left out. */
export function stageSources(appDir: string, stagingDir: string, extraIgnore: string[] = []): NanoStaging {
  const files = listAppFiles(appDir, [...DEFAULT_IGNORE, ...extraIgnore]).filter(
    (f) => NANO_EXTENSIONS.has(f.relPath.slice(f.relPath.lastIndexOf('.')).toLowerCase()) && f.size <= NANO_MAX_FILE_BYTES,
  );
  let copied = 0;
  for (const file of files) {
    if (copied >= NANO_MAX_FILES) break;
    const target = join(stagingDir, file.relPath);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(file.absPath, target);
    copied += 1;
  }
  return { dir: stagingDir, copied, leftOut: Math.max(0, files.length - copied) };
}

/** What Settings holds for this tool. Off, with no script, is the state of a machine that never opted in. */
export interface NanoAnalyzerOptions {
  enabled: boolean;
  /** The `scan.py` of a nano-analyzer checkout, or the folder holding it. */
  scriptPath: string;
  model: string;
  /** Only findings this share of triage rounds agreed on are brought in (0.7 = at least 70% of the rounds). */
  minConfidence: number;
  /** OPENAI_API_KEY or OPENROUTER_API_KEY. Never logged, never written to a report. */
  apiKey?: string;
  /** Set when the key is an OpenRouter one, which the tool selects by the model name containing a slash. */
  keyName?: 'OPENAI_API_KEY' | 'OPENROUTER_API_KEY';
}

/** Why a scan will not happen, in the words the coverage table shows. */
export type NanoSkip = { reason: string };

export interface NanoCommand {
  /** The Python interpreter. */
  file: string;
  script: string;
}

export function findPython(pathValue = process.env['PATH'] ?? ''): string | undefined {
  const names = process.platform === 'win32' ? ['python.exe', 'python3.exe'] : ['python3', 'python'];
  for (const dir of pathValue.split(process.platform === 'win32' ? ';' : ':').filter(Boolean)) {
    for (const name of names) {
      const full = join(dir, name);
      if (existsSync(full)) return full;
    }
  }
  return undefined;
}

/** Turns what the owner typed in Settings into a command to run, or the reason there is none. */
export function resolveNanoAnalyzer(opts: NanoAnalyzerOptions, pathValue?: string): NanoCommand | NanoSkip {
  if (!opts.enabled) return { reason: 'skipped: not switched on in Settings (it costs money and sends your code to an AI service)' };
  if (!opts.scriptPath.trim()) return { reason: 'skipped: no nano-analyzer folder is set in Settings' };
  if (!opts.apiKey) return { reason: 'skipped: no OpenAI or OpenRouter key is set, and nano-analyzer needs one' };
  const given = opts.scriptPath.trim();
  if (!isAbsolute(given)) return { reason: 'skipped: the nano-analyzer path in Settings must be a full path' };
  let script = given;
  try {
    if (statSync(given).isDirectory()) script = join(given, 'scan.py');
  } catch {
    return { reason: 'skipped: the nano-analyzer path in Settings does not exist' };
  }
  if (basename(script) !== 'scan.py' || !existsSync(script)) return { reason: "skipped: that folder does not contain nano-analyzer's scan.py" };
  const python = findPython(pathValue);
  if (!python) return { reason: 'skipped: Python 3 is not installed on this computer, and nano-analyzer is a Python program' };
  return { file: python, script: resolve(script) };
}

/** The command line. `--output-dir` keeps the results inside the run's own scratch folder. */
export function nanoArgs(cmd: NanoCommand, opts: NanoAnalyzerOptions, appDir: string, outputDir: string): string[] {
  return [
    cmd.script,
    appDir,
    '--model', opts.model,
    '--output-dir', outputDir,
    '--min-confidence', String(opts.minConfidence),
    '--repo-dir', appDir,
  ];
}

const SEVERITY_IN_TEXT = /\[(critical|high|medium|low)\]/i;

/** One `findings/VULN-*.md` file: a finding that survived the tool's own triage. */
export function parseNanoFinding(markdown: string, fileName: string): ExternalFindingSeed | undefined {
  const title = /^#\s*(VULN-\d+):\s*(.+)$/m.exec(markdown);
  if (!title) return undefined;
  const file = /^-\s+\*\*File\*\*:\s*`([^`]+)`/m.exec(markdown)?.[1];
  const confidence = Number(/^-\s+\*\*Confidence\*\*:\s*(\d+)%/m.exec(markdown)?.[1] ?? '0') / 100;
  const body = markdown.split(/^##\s+Scanner finding\s*$/m)[1]?.trim() ?? '';
  const severity = (SEVERITY_IN_TEXT.exec(body)?.[1]?.toLowerCase() ?? 'medium') as Severity;
  const rounds = /^-\s+\*\*Confidence\*\*:\s*\d+%\s*\[([A-Z→]+)\]/m.exec(markdown)?.[1];
  return {
    tool: NANO_ANALYZER,
    ruleId: title[1]!,
    title: `nano-analyzer: ${title[2]!.trim()}`,
    severity,
    file,
    description:
      `An AI scanner read this file and believes it found a problem. Its own words:\n\n${body.slice(0, 4000)}`,
    evidence:
      `nano-analyzer checked this finding ${rounds ? `over ${rounds.replace(/→/g, '').length} rounds` : 'several times'} and ` +
      `${Math.round(confidence * 100)}% of those rounds said it is real. This is the tool's own opinion of itself, not a test: ` +
      'nothing was run and nothing was proved. Treat it as a suggestion to look at the file.',
    cwe: [],
    references: ['https://github.com/weareaisle/nano-analyzer'],
    source: fileName,
    confidence,
  } as ExternalFindingSeed & { source: string; confidence: number };
}

/** Every surviving finding in a finished output folder, in file order. */
export function readNanoFindings(outputDir: string, minConfidence: number): ExternalFindingSeed[] {
  const dir = join(outputDir, 'findings');
  if (!existsSync(dir)) return [];
  const seeds: ExternalFindingSeed[] = [];
  for (const name of readdirSync(dir).sort()) {
    if (!name.endsWith('.md')) continue;
    const parsed = parseNanoFinding(readFileSync(join(dir, name), 'utf8'), name);
    if (!parsed) continue;
    const confidence = (parsed as ExternalFindingSeed & { confidence?: number }).confidence ?? 0;
    if (confidence + 1e-9 < minConfidence) continue;
    seeds.push(parsed);
  }
  return seeds;
}

/**
 * What the run did, and what it cost, when the tool says so.
 *
 * Files and seconds are not a cost. This scan spends the owner's own money, against their own key, outside
 * SecureVibe's accounting of its AI spending — so what it cost is the one number they cannot find anywhere else,
 * and SecureVibe was describing files and seconds as "what the run cost". Tokens and money are read when the
 * tool reports them and left out when it does not, because an invented zero would be worse than silence.
 */
export function readNanoSummary(outputDir: string): { filesScanned: number; wallSeconds: number; tokens?: number; costUsd?: number } | undefined {
  const file = join(outputDir, 'summary.json');
  if (!existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as {
      files_scanned?: number;
      wall_time_seconds?: number;
      total_tokens?: number;
      tokens?: number;
      total_cost_usd?: number;
      cost_usd?: number;
    };
    const tokens = parsed.total_tokens ?? parsed.tokens;
    const costUsd = parsed.total_cost_usd ?? parsed.cost_usd;
    return {
      filesScanned: parsed.files_scanned ?? 0,
      wallSeconds: parsed.wall_time_seconds ?? 0,
      ...(typeof tokens === 'number' ? { tokens } : {}),
      ...(typeof costUsd === 'number' ? { costUsd } : {}),
    };
  } catch {
    return undefined;
  }
}

/** The part of the log line that says what the owner was charged, or nothing when the tool did not say. */
export function nanoCostText(summary: { tokens?: number; costUsd?: number }): string {
  if (typeof summary.costUsd === 'number') {
    return `; your AI service was charged about $${summary.costUsd.toFixed(summary.costUsd < 0.01 ? 4 : 2)}${typeof summary.tokens === 'number' ? ` (${summary.tokens.toLocaleString()} tokens)` : ''}`;
  }
  if (typeof summary.tokens === 'number') return `; ${summary.tokens.toLocaleString()} tokens were sent to your AI service and charged to your key`;
  return '';
}

export const NANO_COVERS =
  'An experimental AI scanner that reads your code and suggests what to look at. Off unless you switch it on: it costs money and sends your code to an AI service.';

/**
 * The settings for one run: what the owner chose, plus the key from the environment. A missing key is a reason to
 * skip, never a reason to ask the AI service without one.
 */
export function nanoOptionsFor(
  settings: { nanoAnalyzer: { enabled: boolean; scriptPath: string; model: string; minConfidence: number } },
  env: NodeJS.ProcessEnv = process.env,
): NanoAnalyzerOptions {
  const chosen = settings.nanoAnalyzer;
  // The tool sends a model name containing a slash to OpenRouter, so the key has to match the model.
  const wantsOpenRouter = chosen.model.includes('/');
  const keyName = wantsOpenRouter ? 'OPENROUTER_API_KEY' : 'OPENAI_API_KEY';
  const apiKey = env[keyName]?.trim();
  return {
    enabled: chosen.enabled,
    scriptPath: chosen.scriptPath,
    model: chosen.model,
    minConfidence: chosen.minConfidence,
    keyName,
    ...(apiKey ? { apiKey } : {}),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Running it
// ---------------------------------------------------------------------------------------------------------------

/** Long: the tool reads every file with a language model and then argues with itself about each finding. */
export const NANO_TIMEOUT_MS = 30 * 60_000;

export interface NanoRunResult {
  ran: boolean;
  reason?: string;
  seeds: ExternalFindingSeed[];
  filesScanned?: number;
  /** Files that were left out at the limit; the coverage row says so rather than implying the whole app was read. */
  leftOut?: number;
}

export interface NanoRunContext {
  appDir: string;
  /** SecureVibe's extra ignore patterns, on top of the built-in ones. */
  ignore?: string[];
  projectDir: string;
  runId: string;
  workDir: string;
  log(msg: string): void;
  abort: AbortSignal;
  run(file: string, args: string[], env: Record<string, string>, timeoutMs: number): Promise<{ code: number | null; timedOut: boolean; stderr: string }>;
}

/**
 * Runs the tool and reads its output folder. The key is handed to the child process and nowhere else: it is not
 * logged, not written to the report and not kept in the result.
 */
export async function runNanoAnalyzer(ctx: NanoRunContext, opts: NanoAnalyzerOptions): Promise<NanoRunResult> {
  const resolved = resolveNanoAnalyzer(opts);
  if ('reason' in resolved) return { ran: false, reason: resolved.reason, seeds: [] };
  if (ctx.abort.aborted) return { ran: false, reason: 'skipped: the run was canceled', seeds: [] };

  const outputDir = join(ctx.workDir, 'nano-analyzer');
  const staging = stageSources(ctx.appDir, join(ctx.workDir, 'sources'), ctx.ignore ?? []);
  if (staging.copied === 0) return { ran: false, reason: 'skipped: there was no application source code for it to read', seeds: [] };
  ctx.log(
    `[external] running nano-analyzer (${opts.model}) on ${staging.copied} of your own source file(s)` +
      `${staging.leftOut > 0 ? `, leaving out ${staging.leftOut} to keep the cost down` : ''} — it reads them with an AI service and costs money on your own key`,
  );
  const env: Record<string, string> = { [opts.keyName ?? 'OPENAI_API_KEY']: opts.apiKey! };
  let result: { code: number | null; timedOut: boolean; stderr: string };
  try {
    result = await ctx.run(resolved.file, nanoArgs(resolved, opts, staging.dir, outputDir), env, NANO_TIMEOUT_MS);
  } catch (err) {
    return { ran: false, reason: `skipped: nano-analyzer could not be run (${(err as Error).message})`, seeds: [] };
  }
  // Not "skipped". By this point the tool has sent files to the AI service and the owner's key has been charged;
  // the failure above this line is free because nothing ran, but these two are not. Calling a scan that spent
  // money "skipped" understates what it cost, and the owner has no other way to find out.
  if (result.timedOut) {
    return { ran: false, reason: 'stopped at the time limit after reading some of your files: your AI service was charged for what it had already read', seeds: [] };
  }

  const summary = readNanoSummary(outputDir);
  if (!summary) {
    const tail = result.stderr.trim().split(/\r?\n/).slice(-1)[0] ?? '';
    return {
      ran: false,
      reason: `wrote no results (exit code ${result.code ?? 'unknown'}); it may already have read some of your files, in which case your AI service was charged for them${tail ? `: ${tail.slice(0, 160)}` : ''}`,
      seeds: [],
    };
  }
  const seeds = readNanoFindings(outputDir, opts.minConfidence);
  ctx.log(`[external] nano-analyzer read ${summary.filesScanned} file(s) and suggests ${seeds.length} thing(s) to look at${nanoCostText(summary)}`);
  return { ran: true, seeds, filesScanned: summary.filesScanned, ...(staging.leftOut > 0 ? { leftOut: staging.leftOut } : {}) };
}
