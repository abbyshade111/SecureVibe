import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import type { LlmProvider } from '../../src/llm/types.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

/** A provider whose second opinion never finishes on its own: it waits until the call is aborted. */
function waitingProvider(seen: { aborted: boolean; effort?: string }): LlmProvider {
  return {
    name: 'anthropic',
    model: 'claude-opus-5',
    structured: (req: { abort?: AbortSignal; effort?: string }) =>
      new Promise((resolve) => {
        seen.effort = req.effort;
        req.abort?.addEventListener('abort', () => {
          seen.aborted = true;
          resolve({ ok: false, reason: 'error', message: 'The step was cancelled.', usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, costUsd: 0, servedModel: 'claude-opus-5', fallbackUsed: false, refused: false } });
        });
      }),
  } as unknown as LlmProvider;
}

describe('skipping the second opinion', () => {
  let harness: TestHarness;
  afterEach(() => harness?.cleanup());

  it('stops the running review and records that the owner skipped it', async () => {
    const seen = { aborted: false } as { aborted: boolean; effort?: string };
    harness = await buildHarness({ provider: waitingProvider(seen) });
    harness.config.settings.update({ reviewEffort: 'low' });
    const { cookie, csrfToken } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };

    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const design = await request(harness.server).post(`/api/projects/${project.id}/design`).set(headers);
    expect(design.status).toBe(200);

    const running = request(harness.server).post(`/api/projects/${project.id}/design/peer-review`).set(headers).then((r) => r);
    await new Promise((r) => setTimeout(r, 200));
    const skip = await request(harness.server).post(`/api/projects/${project.id}/design/peer-review/skip`).set(headers);
    expect(skip.status).toBe(200);
    expect(skip.body.peerReview.performedBy).toBe('skipped');
    expect(skip.body.peerReview.skippedReason).toMatch(/at your request/);

    const finished = await running;
    expect(finished.status).toBe(200);
    expect(finished.body.peerReview.skippedReason).toMatch(/at your request/);
    expect(seen.aborted).toBe(true);
    expect(seen.effort).toBe('low');
    expect(harness.store.mustGet(project.id).design?.peerReview?.performedBy).toBe('skipped');
  });
});
