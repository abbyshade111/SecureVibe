/** Build-finished notifications: the message, the platform command, and the setting that switches them off. */
import { describe, expect, it } from 'vitest';
import { finishMessage, notifyDesktop, notifyRunFinished } from '../../src/notify.js';

const project = { name: 'Habit Log' };
const base = { mode: 'full' as const, findings: [], compliance: undefined, failure: undefined };

describe('finishMessage', () => {
  it('summarises a good build in one line', () => {
    const m = finishMessage(project, { ...base, status: 'succeeded', compliance: { overall: { rating: 'needs-attention' } } as never, findings: [{ status: 'open', severity: 'low' }, { status: 'fixed', severity: 'high' }] as never });
    expect(m.title).toBe('SecureVibe: Habit Log');
    expect(m.body).toBe('The build finished. Verdict: needs attention. 1 minor item(s) to look at.');
  });

  it('counts serious open problems and names a check as a check', () => {
    const m = finishMessage(project, { ...base, mode: 'verify-only', status: 'succeeded', findings: [{ status: 'open', severity: 'high' }, { status: 'fix-attempted', severity: 'critical' }] as never });
    expect(m.body).toBe('The check finished. 2 serious problem(s) to look at.');
  });

  it('explains a failure and a cancellation plainly', () => {
    expect(finishMessage(project, { ...base, status: 'failed', failure: { message: 'The packages could not be installed.', options: [] } }).body).toBe('The build did not finish: The packages could not be installed.');
    expect(finishMessage(project, { ...base, status: 'cancelled' }).body).toBe('The build was cancelled.');
  });
});

describe('notifyDesktop', () => {
  it('uses osascript on macOS with the text safely quoted', () => {
    const calls: [string, string[]][] = [];
    const ok = notifyDesktop({ title: 'SecureVibe: "Quotes" \\ app', body: 'Done' }, { platform: 'darwin', spawner: (f, a) => void calls.push([f, a]) });
    expect(ok).toBe(true);
    expect(calls[0]?.[0]).toBe('osascript');
    expect(calls[0]?.[1][1]).toBe('display notification "Done" with title "SecureVibe: \\"Quotes\\" \\\\ app"');
  });

  it('uses notify-send on Linux and does nothing elsewhere', () => {
    const calls: string[] = [];
    expect(notifyDesktop({ title: 't', body: 'b' }, { platform: 'linux', spawner: (f) => void calls.push(f) })).toBe(true);
    expect(calls).toEqual(['notify-send']);
    expect(notifyDesktop({ title: 't', body: 'b' }, { platform: 'win32', spawner: (f) => void calls.push(f) })).toBe(false);
    expect(calls).toEqual(['notify-send']);
  });
});

describe('notifyRunFinished', () => {
  it('is silent when the setting is off', () => {
    expect(notifyRunFinished({ notifyOnFinish: false }, project, { ...base, status: 'succeeded' })).toBe(false);
  });
});
