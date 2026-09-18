#!/usr/bin/env node
/**
 * `tsx src/cli/smoke-api.ts`: one tiny structured call to the Anthropic API, so a person who just added a key
 * can confirm it works before starting a build (DESIGN §13 item 13: "the first thing to run once a key exists").
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { effectiveAiSettings, loadConfig } from '../config.js';
import { createProvider, hasCredentials } from '../integration.js';

const SmokeSchema = z.strictObject({ ok: z.boolean(), note: z.string().max(200) });

async function main(): Promise<void> {
  // Reads the key from .env the same way `npm start` does, and uses the model chosen in Settings.
  const config = loadConfig();
  if (!hasCredentials()) {
    process.stdout.write('No Anthropic API key was found (ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN). Nothing to test.\n');
    process.exitCode = 1;
    return;
  }

  const provider = createProvider({ model: effectiveAiSettings(config.settings.get()).model });
  process.stdout.write(`Calling ${provider.model} with a tiny request…\n`);
  const started = Date.now();
  const result = await provider.structured({
    purpose: 'summarize',
    system: [{ text: 'Reply with the requested structured output. Nothing else.' }],
    user: 'Set ok to true and note to a short greeting.',
    schema: SmokeSchema,
    effort: 'low',
    maxTokens: 200,
    correlationId: `smoke-${randomUUID().slice(0, 8)}`,
    projectId: 'smoke-test',
  });
  const ms = Date.now() - started;

  if (!result.ok) {
    process.stderr.write(`The call did not succeed: ${result.reason} — ${result.message}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    [
      `Success in ${ms}ms.`,
      `Served model: ${result.servedModel}${result.usage.fallbackUsed ? ' (fallback was used)' : ''}`,
      `Tokens: ${result.usage.inputTokens} in / ${result.usage.outputTokens} out (cache read ${result.usage.cacheReadTokens}, cache write ${result.usage.cacheWriteTokens})`,
      `Estimated cost: $${result.usage.costUsd.toFixed(4)}`,
      `Model replied: ${JSON.stringify(result.data)}`,
      '',
    ].join('\n'),
  );
}

main().catch((err) => {
  process.stderr.write(`smoke-api failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exitCode = 1;
});
