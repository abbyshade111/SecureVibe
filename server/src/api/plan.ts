/**
 * The build plan: `POST /projects/:id/plan` asks Claude for it (a few cents), `POST /projects/:id/plan/approve`
 * records which features the owner wants. A full build with AI needs a plan approved for the current design.
 */
import { Router } from 'express';
import { PlanApproveRequestSchema, PlanResponseSchema } from '@shared/api.js';
import type { BuildPlan, Project } from '@shared/project.js';
import type { PartialDesignProfile } from '@shared/profile.js';
import { effectiveAiSettings } from '../config.js';
import { planBuild } from '../llm/flows/plan.js';
import { llmUnavailable, validationError } from '../security/errors.js';
import type { ApiDeps } from './types.js';

/** The plan that applies to the current design, or undefined when there is none or the design changed since. */
export function currentPlan(project: Project): BuildPlan | undefined {
  const plan = project.buildPlan;
  if (!plan || !project.design) return undefined;
  return plan.designHash === project.design.profileHash ? plan : undefined;
}

export function planRouter(deps: ApiDeps): Router {
  const router = Router();

  router.post('/projects/:id/plan', async (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (!project.design) throw validationError('Finish your design before planning the build.');
    const provider = deps.getProvider('plan');
    if (provider.name === 'null') throw llmUnavailable('Planning the build needs AI. Turn AI on in Settings, or build without AI (the starter app with your records, no plan needed).');
    const profile = project.profile as PartialDesignProfile;
    const outcome = await planBuild(
      provider,
      {
        design: project.design,
        ...(profile.app?.description ? { description: profile.app.description } : {}),
        records: (profile.app?.entities ?? []).map((e) => ({ name: e?.name ?? '', label: e?.label ?? e?.name ?? '' })).filter((e) => e.name),
      },
      { projectId: project.id, correlationId: `plan-${project.id}-${Date.now().toString(36)}`, effort: effectiveAiSettings(deps.config.settings.get()).generationEffort },
    );
    if (!outcome.plan) throw validationError(`The plan could not be prepared. ${outcome.failure?.message ?? ''}`.trim());
    const plan = outcome.plan;
    const saved = deps.store.update(project.id, (p) => {
      p.buildPlan = plan;
    });
    res.json(PlanResponseSchema.parse({ project: saved, plan }));
  });

  router.post('/projects/:id/plan/approve', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = PlanApproveRequestSchema.parse(req.body);
    const plan = currentPlan(project);
    if (!plan) throw validationError('There is no plan for the current design yet. Prepare one first.');
    const wanted = new Set(body.featureIds);
    const approved: BuildPlan = {
      ...plan,
      features: plan.features.map((f) => ({ ...f, wanted: wanted.has(f.id) })),
      approvedAt: new Date().toISOString(),
    };
    if (!approved.features.some((f) => f.wanted)) throw validationError('Keep at least one feature, or build without AI instead.');
    const saved = deps.store.update(project.id, (p) => {
      p.buildPlan = approved;
    });
    deps.logger.info({ event: 'plan.approved', projectId: project.id, features: approved.features.filter((f) => f.wanted).length }, 'build plan approved by the owner');
    res.json(PlanResponseSchema.parse({ project: saved, plan: approved }));
  });

  return router;
}
