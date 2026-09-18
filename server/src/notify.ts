/**
 * Desktop notifications when a build ends (docs/CONTRACTS.md "Build-finished notifications").
 *
 * A build takes many minutes and runs in its own worker, so the owner is usually elsewhere when it finishes. The
 * worker posts one system notification through the platform's own tool (macOS: `osascript`, Linux:
 * `notify-send`); nothing is installed and nothing leaves the computer. Off with Settings → "Tell me when a build
 * finishes". Failures to notify are ignored: they must never affect the build.
 */
import { spawn } from 'node:child_process';
import type { PipelineRun } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';

export interface FinishMessage {
  title: string;
  body: string;
}

/** Plain-language summary of how a run ended, for a notification that has to fit in one glance. */
export function finishMessage(project: Pick<Project, 'name'>, run: Pick<PipelineRun, 'status' | 'mode' | 'compliance' | 'findings' | 'failure'>): FinishMessage {
  const what = run.mode === 'verify-only' ? 'check' : 'build';
  const title = `SecureVibe: ${project.name}`;
  switch (run.status) {
    case 'succeeded': {
      const rating = run.compliance?.overall.rating;
      const open = run.findings.filter((f) => f.status === 'open' || f.status === 'fix-attempted');
      const serious = open.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
      const verdict = rating ? ` Verdict: ${rating.replace('-', ' ')}.` : '';
      const problems = open.length === 0 ? ' No open problems.' : serious ? ` ${serious} serious problem(s) to look at.` : ` ${open.length} minor item(s) to look at.`;
      return { title, body: `The ${what} finished.${verdict}${problems}` };
    }
    case 'failed':
      return { title, body: `The ${what} did not finish: ${run.failure?.message ?? 'open SecureVibe for details.'}`.slice(0, 200) };
    case 'cancelled':
      return { title, body: `The ${what} was cancelled.` };
    case 'interrupted':
      return { title, body: `The ${what} was interrupted; start it again when you are ready.` };
    default:
      return { title, body: `The ${what} ended (${run.status}).` };
  }
}

type Spawner = (file: string, args: string[]) => void;

const defaultSpawner: Spawner = (file, args) => {
  try {
    const child = spawn(file, args, { stdio: 'ignore', detached: true, windowsHide: true });
    child.on('error', () => undefined);
    child.unref();
  } catch {
    // no notification tool on this computer: nothing to do
  }
};

/** AppleScript string literal: only backslashes and double quotes need escaping. */
function appleScriptString(text: string): string {
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Shows a system notification, or does nothing where no tool is available. Never throws. */
export function notifyDesktop(message: FinishMessage, opts: { platform?: NodeJS.Platform; spawner?: Spawner } = {}): boolean {
  const platform = opts.platform ?? process.platform;
  const run = opts.spawner ?? defaultSpawner;
  const title = message.title.slice(0, 80);
  const body = message.body.slice(0, 240);
  if (platform === 'darwin') {
    run('osascript', ['-e', `display notification ${appleScriptString(body)} with title ${appleScriptString(title)}`]);
    return true;
  }
  if (platform === 'linux') {
    run('notify-send', ['--app-name=SecureVibe', title, body]);
    return true;
  }
  return false;
}

/** The one call the pipeline makes when a run ends. */
export function notifyRunFinished(settings: { notifyOnFinish: boolean }, project: Pick<Project, 'name'>, run: Parameters<typeof finishMessage>[1]): boolean {
  if (!settings.notifyOnFinish) return false;
  return notifyDesktop(finishMessage(project, run));
}
