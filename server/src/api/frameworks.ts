/** `GET /api/frameworks/summary`. */
import { Router } from 'express';
import type { FrameworkSummary } from '@shared/api.js';
import type { ApiDeps } from './types.js';

export function frameworksRouter(deps: ApiDeps): Router {
  const router = Router();
  router.get('/frameworks/summary', (_req, res) => {
    const f = deps.frameworks;
    const critical = f.sbd.controls.filter((c) => c.critical).length;
    const summary: FrameworkSummary = {
      sbd: { version: f.sbd.version, controls: f.sbd.controls.length, critical },
      asvs: { version: f.asvs.version, requirements: f.asvs.requirements.length, chapters: f.asvs.chapters.length },
      aisvs: { version: f.aisvs.version, requirements: f.aisvs.requirements.length, chapters: f.aisvs.chapters.length },
      appendixC: { version: f.appendixC.version, requirements: f.appendixC.requirements.length, families: f.appendixC.chapters.length },
    };
    res.json(summary);
  });
  return router;
}
