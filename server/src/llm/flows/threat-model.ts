/**
 * Secure by Design step 7: the STRIDE threat model.
 *
 * The rules-based threat model produced by the design engine is always computed first and passed in here as
 * `fallback`. If the AI is not configured, declines, or answers with something that does not fit the architecture,
 * the rules-based model is what the report uses — the design never ends up without a threat model.
 */
import {
  StrideCategorySchema,
  ThreatModelSchema,
  type DesignArtifacts,
  type Threat,
  type ThreatModel,
} from '@shared/design.js';
import type { DesignProfile } from '@shared/profile.js';
import { z } from 'zod';
import { threatModelSystem, wrapUntrusted } from '../prompts/index.js';
import { emptyUsageDelta, type Effort, type LlmProvider, type StructuredFailureReason, type UsageDelta } from '../types.js';
import { renderArchitecture, renderControls, renderProfile } from './context.js';

const LevelSchema = z.enum(['low', 'medium', 'high']);

export const ThreatModelOutputSchema = z.strictObject({
  scope: z.string().max(600),
  assets: z.array(z.string().max(200)).max(30),
  entryPoints: z.array(z.string().max(200)).max(30),
  trustBoundaries: z.array(z.string().max(200)).max(20),
  summary: z.string().max(2000),
  threats: z
    .array(
      z.strictObject({
        stride: StrideCategorySchema,
        /** A component id or data-flow id from the architecture. */
        target: z.string().max(80),
        description: z.string().max(1200),
        likelihood: LevelSchema,
        impact: LevelSchema,
        riskLevel: LevelSchema,
        residualRisk: LevelSchema,
        status: z.enum(['mitigated', 'accepted', 'open']),
        mitigations: z
          .array(
            z.strictObject({
              control: z.string().max(60),
              description: z.string().max(400),
              requirementIds: z.array(z.string().max(20)).max(10),
            }),
          )
          .max(6),
        actionItems: z.array(z.string().max(300)).max(5),
      }),
    )
    .max(20),
});
export type ThreatModelOutput = z.infer<typeof ThreatModelOutputSchema>;

export interface ThreatModelOptions {
  /** The rules-based threat model; used whenever the AI step cannot be trusted or cannot run. */
  fallback: ThreatModel;
  projectId?: string;
  correlationId?: string;
  effort?: Effort;
  now?: Date;
  /** Requirement ids that exist (ASVS/AISVS). Citations outside this set are dropped. */
  knownRequirementIds?: Set<string>;
}

export interface ThreatModelOutcome {
  threatModel: ThreatModel;
  usedFallback: boolean;
  usage: UsageDelta;
  failure?: { reason: StructuredFailureReason; message: string };
}

export async function threatModel(
  provider: LlmProvider,
  design: DesignArtifacts,
  profile: DesignProfile,
  opts: ThreatModelOptions,
): Promise<ThreatModelOutcome> {
  if (provider.name === 'null') {
    return { threatModel: opts.fallback, usedFallback: true, usage: emptyUsageDelta(provider.model) };
  }

  const validTargets = new Set<string>([
    ...design.architecture.components.map((c) => c.id),
    ...design.architecture.dataFlows.map((f) => f.id),
  ]);
  const knownControls = new Set<string>([
    ...design.patterns.map((p) => p.id),
    ...design.patterns.flatMap((p) => p.implementedBy),
    ...design.architecture.dataFlows.flatMap((f) => f.controls),
  ]);

  const user = [
    'THE APPLICATION',
    renderProfile(profile),
    '',
    'How the owner described it (their own words):',
    wrapUntrusted('user-description', profile.app.description, { maxChars: 3000 }),
    '',
    renderArchitecture(design),
    '',
    renderControls(design),
    '',
    `Use only these identifiers as a threat target: ${[...validTargets].join(', ')}`,
    `Use only these control identifiers in mitigations: ${[...knownControls].sort().join(', ')}`,
  ].join('\n');

  const result = await provider.structured({
    purpose: 'threat-model',
    system: threatModelSystem(),
    user,
    schema: ThreatModelOutputSchema,
    effort: opts.effort ?? 'medium',
    maxTokens: 16_000,
    correlationId: opts.correlationId ?? 'threat-model',
    projectId: opts.projectId ?? 'unknown',
  });

  if (!result.ok) {
    return {
      threatModel: opts.fallback,
      usedFallback: true,
      usage: result.usage,
      failure: { reason: result.reason, message: result.message },
    };
  }

  const threats = normalizeThreats(result.data.threats, validTargets, knownControls, opts.knownRequirementIds);
  if (threats.length === 0) {
    return {
      threatModel: opts.fallback,
      usedFallback: true,
      usage: result.usage,
      failure: { reason: 'invalid_output', message: 'The AI threat model did not fit the design, so the built-in one was used.' },
    };
  }

  const model: ThreatModel = {
    method: 'STRIDE',
    performedBy: 'claude',
    model: result.servedModel,
    performedAt: (opts.now ?? new Date()).toISOString(),
    scope: result.data.scope || opts.fallback.scope,
    assets: result.data.assets.length > 0 ? result.data.assets : opts.fallback.assets,
    entryPoints: result.data.entryPoints.length > 0 ? result.data.entryPoints : opts.fallback.entryPoints,
    trustBoundaries: result.data.trustBoundaries.length > 0 ? result.data.trustBoundaries : opts.fallback.trustBoundaries,
    threats,
    summary: result.data.summary || opts.fallback.summary,
  };

  const parsed = ThreatModelSchema.safeParse(model);
  if (!parsed.success) {
    return {
      threatModel: opts.fallback,
      usedFallback: true,
      usage: result.usage,
      failure: { reason: 'invalid_output', message: 'The AI threat model could not be read, so the built-in one was used.' },
    };
  }
  return { threatModel: parsed.data, usedFallback: false, usage: result.usage };
}

const REQUIREMENT_ID = /^(?:V\d+\.\d+\.\d+|C\d+\.\d+\.\d+|AC\.\d+\.\d+)$/;

/** Keeps only threats that point at something in the architecture; drops invented controls and requirement ids. */
export function normalizeThreats(
  threats: ThreatModelOutput['threats'],
  validTargets: Set<string>,
  knownControls: Set<string>,
  knownRequirementIds?: Set<string>,
): Threat[] {
  const out: Threat[] = [];
  for (const t of threats) {
    if (!validTargets.has(t.target)) continue;
    const mitigations = t.mitigations
      .filter((m) => knownControls.has(m.control))
      .map((m) => ({
        control: m.control,
        description: m.description,
        requirementIds: m.requirementIds.filter(
          (id) => REQUIREMENT_ID.test(id) && (!knownRequirementIds || knownRequirementIds.has(id)),
        ),
      }));
    out.push({
      id: `T-${String(out.length + 1).padStart(2, '0')}`,
      stride: t.stride,
      target: t.target,
      description: t.description,
      likelihood: t.likelihood,
      impact: t.impact,
      riskLevel: t.riskLevel,
      mitigations,
      residualRisk: t.residualRisk,
      // A threat with nothing mitigating it is open, whatever the model called it.
      status: mitigations.length === 0 ? (t.status === 'accepted' ? 'accepted' : 'open') : t.status,
      actionItems: mitigations.length === 0 && t.actionItems.length === 0 ? ['Decide how to handle this risk.'] : t.actionItems,
    });
  }
  const order = { high: 0, medium: 1, low: 2 };
  return out.sort((a, b) => order[a.riskLevel] - order[b.riskLevel]);
}
