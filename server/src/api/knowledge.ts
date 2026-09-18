/** `GET /api/knowledge/wizard-copy` and `GET /api/knowledge/glossary`: plain-language content for the wizard and reports. */
import { Router } from 'express';
import type { ApiDeps } from './types.js';

export function knowledgeRouter(deps: ApiDeps): Router {
  const router = Router();
  router.get('/knowledge/wizard-copy', (_req, res) => {
    res.json(deps.knowledge.wizardCopy);
  });
  router.get('/knowledge/glossary', (_req, res) => {
    res.json({ glossary: deps.knowledge.glossary });
  });
  return router;
}
