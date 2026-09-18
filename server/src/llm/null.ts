/**
 * Preview mode: SecureVibe runs with no AI credential. Everything that needs the model is skipped and labelled
 * honestly — never silently faked, never counted as verified.
 */
import { emptyLlmUsage } from './budget.js';
import { emptyUsageDelta } from './types.js';
import type { AgentRunRequest, AgentRunResult, LlmProvider, ProviderName, StructuredRequest, StructuredResult } from './types.js';

export const PREVIEW_MESSAGE = 'AI is not configured (preview mode)';

export const PREVIEW_EXPLANATION =
  'SecureVibe is running without an Anthropic API key, so the parts that need AI are skipped. You still get the ' +
  'hardened starter application, the full security scan and the reports — the reports say clearly which parts were ' +
  'not done.';

export class NullProvider implements LlmProvider {
  readonly name: ProviderName = 'null';

  constructor(readonly model: string = 'none') {}

  async structured<T>(_req: StructuredRequest<T>): Promise<StructuredResult<T>> {
    return { ok: false, reason: 'error', message: PREVIEW_MESSAGE, usage: emptyUsageDelta(this.model) };
  }

  async agentRun(req: AgentRunRequest): Promise<AgentRunResult> {
    const message = `${PREVIEW_MESSAGE}. ${PREVIEW_EXPLANATION}`;
    req.onEvent({ type: 'stop', status: 'skipped', message });
    return {
      status: 'skipped',
      ok: false,
      message,
      usage: emptyLlmUsage(this.name, this.model),
      iterations: 0,
      servedModels: [],
      pathDenials: 0,
      injectionFlags: 0,
    };
  }
}
