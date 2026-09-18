/** `GET /api/examples`: example projects from the knowledge base, for "start from an example". */
import { Router } from 'express';
import type { ApiDeps } from './types.js';

export function examplesRouter(deps: ApiDeps): Router {
  const router = Router();
  router.get('/examples', (_req, res) => {
    res.json({ examples: deps.knowledge.examples });
  });
  return router;
}
