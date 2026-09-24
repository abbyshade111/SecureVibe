/**
 * `typecheck`, and the `run_checks` tool the generation/fix agents call mid-loop (CONTRACTS §9.1: `run_checks`
 * input is `{ check: 'typecheck' | 'lint' | 'test' }` only — the model never supplies a command).
 *
 * `typecheck` has no scanner of its own (it is a pipeline stage, not a finding source): it just runs the app's
 * own `tsc --noEmit` in the sandbox. `lint` and `test` reuse the real scanners so the agent sees the same result
 * the pipeline will score it on later, reduced to a plain pass/fail with the readable output.
 */
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { runLint, runTests, type CheckName, type RunCheckOutcome } from '../integration.js';
import { runNode } from './process.js';
import { buildScanContext, type PipelineCtx } from './types.js';

export const TYPECHECK_TIMEOUT_MS = 3 * 60_000;

/**
 * The TypeScript projects to check: the app's own tsconfig.json, or, for a workspace repository without one
 * (SecureVibe's self-assessment), every first-level folder that has its own tsconfig.json.
 */
export function typecheckProjects(appDir: string): string[] {
  if (existsSync(join(appDir, 'tsconfig.json'))) return ['tsconfig.json'];
  let entries: string[] = [];
  try {
    entries = readdirSync(appDir).sort();
  } catch {
    return [];
  }
  return entries.filter((name) => !name.startsWith('.') && name !== 'node_modules' && existsSync(join(appDir, name, 'tsconfig.json'))).map((name) => `${name}/tsconfig.json`);
}

export async function runTypecheckCheck(ctx: PipelineCtx): Promise<RunCheckOutcome> {
  // The compiler is run directly: going through `npm run` would need a child process, which the sandbox refuses.
  const tsc = join(ctx.appDir, 'node_modules', 'typescript', 'bin', 'tsc');
  if (!existsSync(tsc)) return { ok: false, output: '', skippedReason: 'The TypeScript compiler is not installed in the app, so the code could not be type-checked.' };
  const projects = typecheckProjects(ctx.appDir);
  if (projects.length === 0) return { ok: false, output: '', skippedReason: 'No tsconfig.json was found, so the code could not be type-checked.' };
  const outputs: string[] = [];
  let ok = true;
  for (const project of projects) {
    const result = await runNode([tsc, '-p', project, '--noEmit'], {
      cwd: ctx.appDir,
      projectDir: ctx.paths.dir,
      runId: ctx.run.id,
      timeoutMs: TYPECHECK_TIMEOUT_MS,
      permission: { read: [ctx.appDir], write: [join(ctx.paths.dir, 'tmp')] },
      abort: ctx.abort.signal,
    });
    const output = `${result.stdout}\n${result.stderr}`.trim();
    if (projects.length > 1) outputs.push(`${project}: ${result.code === 0 ? 'no errors' : 'errors'}${output ? `\n${output}` : ''}`);
    else if (output) outputs.push(output);
    if (result.timedOut) return { ok: false, output: outputs.join('\n'), skippedReason: 'The type check took too long and was stopped.' };
    if (result.code !== 0) ok = false;
  }
  return { ok, output: outputs.join('\n').slice(-8000) };
}

async function runLintCheck(ctx: PipelineCtx): Promise<RunCheckOutcome> {
  const scan = await runLint(buildScanContext(ctx, 'lint'));
  const open = scan.findings.filter((f) => f.status === 'open');
  const output = open.length === 0 ? 'No lint findings.' : open.map((f) => `${f.location?.file ?? '?'}:${f.location?.line ?? '?'} ${f.title}`).join('\n');
  return { ok: scan.status !== 'failed', output: output.slice(-8000) };
}

export interface TestCheckDetails {
  failed?: number;
  total?: number;
  tests?: { name: string; ok: boolean; skipped?: boolean; file?: string; detail?: string }[];
}

/** Exported so the wording can be tested without standing an application up to fail a test on purpose. */
export function formatTestCheckOutput(summary: string, details: TestCheckDetails | undefined): string {
  // Name the failures. This used to hand the agent a count — "1 of 223 failing" — while the same result object
  // carried every test's name and outcome. On the first app built by someone new, the agent said so itself: it
  // could not isolate the failing test because the tool returned a summary rather than names, re-ran the suite
  // twice, spent the owner's budget, and ended by recommending she run it again herself. We knew and did not say.
  const failing = (details?.tests ?? []).filter((t) => !t.ok && !t.skipped);
  const line = (t: { name: string; file?: string; detail?: string }): string =>
    `  ${t.name}${t.file ? ` (${t.file})` : ''}${t.detail ? `\n    ${t.detail.replace(/\s+/g, ' ').slice(0, 200)}` : ''}`;
  const named = failing.length > 0 ? `\nFailing:\n${failing.slice(0, 20).map(line).join('\n')}${failing.length > 20 ? `\n  …and ${failing.length - 20} more` : ''}` : '';
  return `${summary}${details ? ` (${details.failed ?? 0} of ${details.total ?? 0} failing)` : ''}${named}`;
}

async function runTestCheck(ctx: PipelineCtx): Promise<RunCheckOutcome> {
  const scan = await runTests(buildScanContext(ctx, 'unit-tests'), { sandbox: true });
  const output = formatTestCheckOutput(scan.summary, scan.details as TestCheckDetails | undefined);
  return { ok: scan.status === 'passed', output: output.slice(-8000) };
}

/** Builds the `runCheck` callback handed to the generation/fix agent's tools (CONTRACTS §9.1). */
export function makeRunCheck(ctx: PipelineCtx): (check: CheckName) => Promise<RunCheckOutcome> {
  return async (check) => {
    if (ctx.abort.signal.aborted) return { ok: false, output: '', skippedReason: 'The build was canceled.' };
    switch (check) {
      case 'typecheck':
        return runTypecheckCheck(ctx);
      case 'lint':
        return runLintCheck(ctx);
      case 'test':
        return runTestCheck(ctx);
      default:
        return { ok: false, output: '', skippedReason: 'Unknown check.' };
    }
  };
}
