/**
 * The run tells the page what it has spent, as it spends it.
 *
 * The figure was always on the run object from the first AI call, and the file the page re-reads is only written
 * when a stage ends — and writing the app is one long stage. So an owner watching a paid build saw no number at
 * all until it finished, and had nothing to tell her it was working rather than stuck. She asked.
 */
import { describe, expect, it } from 'vitest';
import { RunBus } from '../../src/pipeline/bus.js';
import type { ProgressEvent } from '@shared/pipeline.js';

describe('the spend event', () => {
  it('carries the money and the call count, and nothing else', () => {
    const seen: ProgressEvent[] = [];
    const bus = new RunBus('r_20260919120000_aaaaaa', (buffered) => seen.push(buffered.event));
    bus.spend(1.7395, 33);

    expect(seen).toHaveLength(1);
    const event = seen[0]!;
    expect(event.type).toBe('spend');
    expect(event.data).toEqual({ estimatedCostUsd: 1.7395, calls: 33 });
    // This stream reaches the browser. Money and a count answer "is it working and what has it cost"; nothing
    // else on a paid call is anyone's business, least of all a prompt or a key.
    const text = JSON.stringify(event);
    expect(text).not.toMatch(/sk-|api[_-]?key|prompt|token/i);
  });

  it('says the amount in the message too, for anywhere that shows text rather than data', () => {
    const seen: ProgressEvent[] = [];
    const bus = new RunBus('r_20260919120000_aaaaaa', (buffered) => seen.push(buffered.event));
    bus.spend(0.5, 2);
    expect(seen[0]!.message).toContain('0.50');
    expect(seen[0]!.message).toContain('2 call');
  });
});
