/** `GET /api/status`, `PUT /api/settings` (CONTRACTS §0). */
import { Router } from 'express';
import { AiKeyRequestSchema, StatusResponseSchema, UpdateSettingsRequestSchema, type StatusResponse } from '@shared/api.js';
import type { ToolCoverage } from '@shared/pipeline.js';
import { detectTool, EXTERNAL_TOOLS, hasCredentials, providerStatus } from '../integration.js';
import { effectiveAiSettings, readVersion } from '../config.js';
import { AI_SERVICE_INFO, ApiKeyError, keyStatuses, removeApiKey, setApiKey } from '../security/api-keys.js';
import { validationError } from '../security/errors.js';
import type { SessionRecord } from '../security/token.js';
import { nanoOptionsFor } from '../scanners/external/nano-analyzer.js';
import { runPreflight } from './preflight.js';
import type { ApiDeps } from './types.js';

export function statusRouter(deps: ApiDeps): Router {
  const router = Router();

  router.get('/status', async (req, res) => {
    const session = res.locals['session'] as SessionRecord;
    const settings = deps.config.settings.get();
    const provider = deps.getProvider();
    const status = providerStatus(provider);
    // A key is set but AI is off: say why, so the person knows how to turn it back on.
    const offBy: 'setting' | 'environment' | undefined =
      provider.name === 'null' && hasCredentials() ? (deps.config.aiDisabled ? 'environment' : !settings.aiEnabled ? 'setting' : undefined) : undefined;
    const switchedOff = offBy
      ? {
          switchedOff: offBy,
          message:
            offBy === 'setting'
              ? 'AI is switched off in Settings, so SecureVibe runs without AI: nothing is sent to Anthropic and nothing is spent.'
              : 'AI is switched off for this session (SECUREVIBE_AI=off), so SecureVibe runs without AI: nothing is sent to Anthropic and nothing is spent.',
        }
      : {};
    const preflight = await runPreflight(deps.config, { alreadyBound: true });
    const tools: ToolCoverage[] = await Promise.all(
      EXTERNAL_TOOLS.map(async (t) => {
        const found = await detectTool(t.name, deps.config.paths.repoRoot);
        return { tool: t.name, ran: false, covers: t.covers, ...(found?.version ? { version: found.version } : {}), ...(!found ? { reason: 'not installed on this computer' } : {}) };
      }),
    );

    const body: StatusResponse = {
      version: readVersion(deps.config.paths.repoRoot),
      nodeVersion: process.version,
      llm: { configured: hasCredentials(), provider: status.provider, model: status.model, previewMode: status.previewMode, message: status.message, ...switchedOff },
      preflight,
      tools,
      csrfToken: session.csrfToken,
      workspaceDir: deps.config.paths.home,
      aiServices: keyStatuses(deps.config.paths.repoRoot),
      settings: {
        model: settings.model,
        generationEffort: settings.generationEffort,
        reviewEffort: settings.reviewEffort,
        defaultSpendingCapUsd: settings.defaultSpendingCapUsd,
        maxFixRounds: settings.maxFixRounds,
        storeFullPrompts: settings.storeFullPrompts,
        aiEnabled: settings.aiEnabled,
        saveCredits: settings.saveCredits,
        notifyOnFinish: settings.notifyOnFinish,
        scanBuiltAppsForMalware: settings.scanBuiltAppsForMalware,
        pdfPageSize: settings.pdfPageSize,
        aiService: settings.aiService,
        aiServiceFor: settings.aiServiceFor,
        nanoAnalyzer: {
          enabled: settings.nanoAnalyzer.enabled,
          scriptPath: settings.nanoAnalyzer.scriptPath,
          model: settings.nanoAnalyzer.model,
          minConfidence: settings.nanoAnalyzer.minConfidence,
          // Only whether a key is there; the key itself never leaves the .env file.
          keyPresent: Boolean(nanoOptionsFor(settings).apiKey),
        },
        effectiveModel: effectiveAiSettings(settings).model,
      },
    };
    res.json(StatusResponseSchema.parse(body));
  });

  // The owner's own AI-service key: written to the .env file next to SecureVibe, never returned by any route.
  router.put('/settings/ai-key', (req, res) => {
    const body = AiKeyRequestSchema.parse(req.body);
    const root = deps.config.paths.repoRoot;
    try {
      const statuses = body.remove === true || (body.key ?? '').trim() === ''
        ? removeApiKey(root, body.service)
        : setApiKey(root, body.service, body.key!);
      deps.logger.info(
        { event: body.remove === true ? 'settings.ai_key_removed' : 'settings.ai_key_set', service: body.service, envVar: AI_SERVICE_INFO[body.service].envVar },
        'the owner changed an AI service key',
      );
      res.json({ aiServices: statuses });
    } catch (err) {
      if (err instanceof ApiKeyError) throw validationError(err.message);
      throw err;
    }
  });

  router.put('/settings', (req, res) => {
    const body = UpdateSettingsRequestSchema.parse(req.body);
    const settings = body.reset ? deps.config.settings.reset() : deps.config.settings.update(body);
    res.json({ settings });
  });

  return router;
}
