/** Mounts every `/api` route (CONTRACTS §0). Zod validation happens per-route; errors reach `errorHandler` in app.ts. */
import { Router } from 'express';
import { BuildApprovals } from './approvals.js';
import { PreviewManager } from '../preview/index.js';
import { artifactsRouter } from './artifacts.js';
import { examplesRouter } from './examples.js';
import { frameworksRouter } from './frameworks.js';
import { knowledgeRouter } from './knowledge.js';
import { metricsRouter } from './metrics.js';
import { securityRouter } from './security.js';
import { planRouter } from './plan.js';
import { projectsRouter } from './projects.js';
import { runsRouter } from './runs.js';
import { uploadsRouter } from './uploads.js';
import { statusRouter } from './status.js';
import type { ApiDeps } from './types.js';

export type { ApiDeps } from './types.js';

export function buildApiRouter(input: Omit<ApiDeps, 'approvals' | 'previews'> & { approvals?: BuildApprovals; previews?: PreviewManager }): Router {
  const deps: ApiDeps = { ...input, approvals: input.approvals ?? new BuildApprovals(), previews: input.previews ?? new PreviewManager(input.store) };
  const router = Router();
  router.use(statusRouter(deps));
  router.use(examplesRouter(deps));
  router.use(frameworksRouter(deps));
  router.use(knowledgeRouter(deps));
  router.use(projectsRouter(deps));
  router.use(runsRouter(deps));
  router.use(artifactsRouter(deps));
  router.use(metricsRouter(deps));
  router.use(securityRouter(deps));
  router.use(uploadsRouter(deps));
  router.use(planRouter(deps));
  return router;
}
