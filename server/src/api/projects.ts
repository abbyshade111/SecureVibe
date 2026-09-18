/**
 * Project CRUD, the wizard (profile save, quick-infer), design derivation, the AI second opinion, escalation
 * acknowledgement, the cost estimate, findings/decisions, attestations, human review, and run instructions.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Router } from 'express';
import { z } from 'zod';
import {
  AppearanceRequestSchema,
  AppearanceResponseSchema,
  AttestationRequestSchema,
  CreateProjectRequestSchema,
  DeriveDesignResponseSchema,
  EstimateResponseSchema,
  FindingDecisionRequestSchema,
  FindingsResponseSchema,
  HumanReviewRequestSchema,
  PeerReviewDecisionsRequestSchema,
  PeerReviewResponseSchema,
  QuickInferRequestSchema,
  RunInstructionsSchema,
  SaveProfileRequestSchema,
  RefineDecisionsRequestSchema,
  RefineResponseSchema,
  type RunInstructions,
  type VerificationResponse,
  DocumentResponseSchema,
  VerificationResponseSchema,
} from '@shared/api.js';
import { DesignProfileSchema, PartialDesignProfileSchema, type DesignProfile, type PartialDesignProfile } from '@shared/profile.js';
import { HumanCodeReviewSchema, isUploadedApp, type Project } from '@shared/project.js';
import { isOpen, type Finding } from '@shared/findings.js';
import { applyPeerReviewPatch, deriveDesign, peerReview, profileHash, quickInfer } from '../integration.js';
import { answerFieldAllowed, refineProfile } from '../llm/flows/refine.js';
import { applyRefinement } from '../design/refine-apply.js';
import { documentsFor, readDocument, DocumentNotAvailable } from '../verification/documents.js';
import { AppearanceError, setAppTheme } from '../generator/appearance.js';
import { PathConfinementError } from '../store/paths.js';
import { SELF_PROJECT_NAME, loadComplianceInputs, refreshReportsWithAnswers, RefreshUnavailableError, reviewIsCurrent, reviewScope, reviewTree } from '../verification/index.js';
import { effectiveAiSettings } from '../config.js';
import { PreviewError } from '../preview/index.js';
import { estimateForProject } from '../pipeline/estimate.js';
import type { SessionRecord } from '../security/token.js';
import { runIsLive } from '../pipeline/job.js';
import { templateOutdated } from '../generator/template-hash.js';
import { upgradeApp } from '../generator/upgrade.js';
import { diffVersions, fileDiff, listVersions, VersionNotFoundError } from '../versions/index.js';
import { conflict, forbidden, llmUnavailable, notFound, validationError } from '../security/errors.js';
import { toListItem } from '../store/index.js';
import { createHash } from 'node:crypto';
import type { ApiDeps } from './types.js';

function mergeProfile(current: unknown, patch: z.infer<typeof PartialDesignProfileSchema>): unknown {
  const base = (current ?? {}) as Record<string, unknown>;
  const out: Record<string, unknown> = { ...base };
  for (const [section, value] of Object.entries(patch)) {
    if (value === undefined) continue;
    out[section] = { ...(base[section] as Record<string, unknown> | undefined), ...(value as Record<string, unknown>) };
  }
  return out;
}

/** Design options for an app the owner uploaded (which AISVS parts apply depends on how it was written). */
function uploadedDesignOption(project: Project): { uploaded?: { aiAssisted: boolean } } {
  return isUploadedApp(project) ? { uploaded: { aiAssisted: project.origin?.aiAssisted === true } } : {};
}

/** Second opinions currently waiting on the AI, by project id. */
const IN_FLIGHT_PEER_REVIEWS = new Map<string, AbortController>();

export function projectsRouter(deps: ApiDeps): Router {
  const router = Router();

  router.post('/projects', (req, res) => {
    const body = CreateProjectRequestSchema.parse(req.body);
    let profile: DesignProfile | undefined;
    let startedFromExample: string | undefined;
    if (body.exampleId) {
      const example = deps.knowledge.examples.find((e) => e.id === body.exampleId);
      if (!example) throw validationError('That example could not be found.');
      profile = example.profile;
      startedFromExample = example.id;
    }
    const project = deps.store.create({
      name: body.name,
      mode: body.mode,
      ...(profile ? { profile } : {}),
      ...(startedFromExample ? { startedFromExample } : {}),
      ...(body.uploaded ? { origin: { kind: 'uploaded' as const, aiAssisted: body.uploaded.aiAssisted } } : {}),
    });
    res.status(201).json({ project });
  });

  // "A newer template is available" is worked out from the app's provenance each time, never stored.
  const withTemplateStatus = <T extends { id: string }>(project: T): T => {
    const outdated = templateOutdated(deps.store.paths(project.id).appDir, deps.config.paths.templateDir);
    return outdated === undefined ? project : { ...project, templateOutdated: outdated };
  };

  router.get('/projects', (_req, res) => {
    res.json({ projects: deps.store.list().map(withTemplateStatus) });
  });

  router.get('/projects/:id', (req, res) => {
    const project = deps.store.get(req.params['id']!);
    if (!project) throw notFound('That project could not be found.');
    res.json({ project: withTemplateStatus(project) });
  });

  // App versions (the current app and the app-v<N> folders kept on rebuild) and what changed between two of them.
  router.get('/projects/:id/versions', (req, res) => {
    deps.store.mustGet(req.params['id']!);
    res.json({ versions: listVersions(deps.store, req.params['id']!) });
  });

  const versionParam = (raw: unknown, fallback: string): string => {
    const value = typeof raw === 'string' && raw.trim() ? raw.trim() : fallback;
    if (!/^(current|v\d{1,4})$/.test(value)) throw validationError('That is not a version of this app.');
    return value;
  };

  router.get('/projects/:id/diff', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const versions = listVersions(deps.store, project.id);
    const previous = versions.find((v) => v.id !== 'current');
    const from = versionParam(req.query['from'], previous?.id ?? 'current');
    const to = versionParam(req.query['to'], 'current');
    try {
      res.json(diffVersions(deps.store, project.id, from, to));
    } catch (err) {
      if (err instanceof VersionNotFoundError) throw notFound(err.message);
      throw err;
    }
  });

  router.get('/projects/:id/diff/file', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const from = versionParam(req.query['from'], 'current');
    const to = versionParam(req.query['to'], 'current');
    const path = typeof req.query['path'] === 'string' ? req.query['path'] : '';
    if (!path || path.length > 512 || path.includes('\0')) throw validationError('Which file?');
    try {
      res.json(fileDiff(deps.store, project.id, from, to, path));
    } catch (err) {
      if (err instanceof VersionNotFoundError) throw notFound(err.message);
      throw err;
    }
  });

  // Update a built app to the latest template without rebuilding it (generator/upgrade.ts). The owner then runs a
  // free re-check so the results and reports describe the updated app.
  router.post('/projects/:id/upgrade', async (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (isUploadedApp(project)) throw validationError('An uploaded app has no SecureVibe template to update.');
    if (!project.design) throw validationError('Finish your design before updating the app.');
    const paths = deps.store.paths(project.id);
    if (!existsSync(join(paths.appDir, 'securevibe.provenance.json'))) throw validationError('Build the app first; there is nothing to update yet.');
    if (project.lastRunId && runIsLive(deps.store, project.lastRunId)) throw conflict('This app is being built or checked right now. Wait for that to finish first.');
    deps.previews.stop(project.id);
    const profile = DesignProfileSchema.parse(project.profile);
    const upgrade = await upgradeApp({
      templateDir: deps.config.paths.templateDir,
      projectDir: paths.dir,
      appDir: paths.appDir,
      projectId: project.id,
      profile,
      buildSpec: project.design.buildSpec,
      settings: deps.config.settings.get(),
      knowledgeDir: deps.config.paths.knowledgeDir,
      securevibeVersion: deps.config.version,
      designProfileHash: project.design.profileHash,
      designHash: project.profileHash ?? project.design.profileHash,
      log: (msg) => deps.logger.info({ projectId: project.id }, msg),
    });
    const saved = deps.store.update(project.id, (p) => {
      p.lastUpgrade = upgrade;
    });
    deps.logger.info(
      { event: 'app.template_upgraded', projectId: project.id, updated: upgrade.updated.length, added: upgrade.added.length, removed: upgrade.removed.length, kept: upgrade.kept.length },
      'app updated to the latest template',
    );
    res.json({ project: withTemplateStatus(saved), upgrade });
  });

  router.delete('/projects/:id', (req, res) => {
    const project = deps.store.get(req.params['id']!);
    if (!project) throw notFound('That project could not be found.');
    if (project.lastRunId && runIsLive(deps.store, project.lastRunId)) {
      throw conflict('This app is being built right now. Cancel the build first, then delete the app.');
    }
    deps.previews.stop(project.id);
    deps.store.delete(project.id);
    res.status(204).end();
  });

  // Archive hides an app from the main list without deleting anything; restore brings it back.
  router.post('/projects/:id/archive', (req, res) => {
    const saved = deps.store.update(req.params['id']!, (p) => {
      p.archivedAt = new Date().toISOString();
    });
    res.json({ project: saved });
  });

  router.post('/projects/:id/restore', (req, res) => {
    const saved = deps.store.update(req.params['id']!, (p) => {
      delete p.archivedAt;
    });
    res.json({ project: saved });
  });

  /**
   * Change how the app looks. Colour only, so nothing is generated and nothing is checked again: the answer is
   * saved with the design (a later rebuild keeps it) and written into the built app's settings file, where the app
   * picks it up the next time it starts.
   */
  router.put('/projects/:id/appearance', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = AppearanceRequestSchema.parse(req.body);
    const appDir = deps.store.paths(project.id).appDir;
    let applied = false;
    if (existsSync(join(appDir, '.env'))) {
      try {
        setAppTheme(appDir, body.theme);
        applied = true;
      } catch (err) {
        if (!(err instanceof AppearanceError)) throw err;
        throw validationError(err.message);
      }
    }
    deps.store.update(project.id, (p) => {
      p.profile = { ...p.profile, app: { ...p.profile?.app, theme: body.theme } };
    });
    res.json(
      AppearanceResponseSchema.parse({
        theme: body.theme,
        applied,
        message: applied
          ? 'Your app has the new look. Start it again (or reload its page if it is already running) to see it.'
          : 'Saved. Your app will be built with this look.',
      }),
    );
  });

  router.put('/projects/:id/profile', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = SaveProfileRequestSchema.parse(req.body);
    const merged = mergeProfile(project.profile, body.profile);
    const parsed = PartialDesignProfileSchema.parse(merged);
    project.profile = parsed;
    // The app's name is an answer like any other: renaming it there renames the app in "My apps" too.
    const answeredName = parsed.app?.name?.trim();
    if (answeredName) project.name = answeredName.slice(0, 60);
    if (body.wizardStep !== undefined) project.wizardStep = body.wizardStep;
    const full = DesignProfileSchema.safeParse(parsed);
    if (full.success && project.profileHash && project.profileHash !== profileHash(full.data)) {
      project.designStale = true;
      project.buildStale = true;
    }
    const saved = deps.store.save(project);
    res.json({ project: saved });
  });

  router.post('/projects/:id/quick-infer', async (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = QuickInferRequestSchema.parse(req.body);
    const provider = deps.getProvider('peer-review');
    if (provider.name === 'null') throw llmUnavailable('Quick mode needs AI to read your description. Use the guided questions instead, or add an Anthropic API key and restart SecureVibe.');
    const outcome = await quickInfer(provider, {
      description: body.description,
      ...(body.name ? { name: body.name } : {}),
      known: body.known,
      projectId: project.id,
      correlationId: `quick-infer-${project.id}-${Date.now()}`,
    });
    project.profile = outcome.profile;
    project.designStale = true;
    project.buildStale = true;
    deps.store.save(project);
    res.json({ profile: outcome.profile, inferredFields: outcome.inferredFields, needsConfirmation: outcome.needsConfirmation, assumptions: outcome.assumptions, screening: outcome.screening });
  });

  router.post('/projects/:id/design', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const parsed = DesignProfileSchema.safeParse(project.profile);
    if (!parsed.success) throw validationError('Your design is not complete yet.', parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })));
    const design = deriveDesign(parsed.data, {
      knowledge: deps.knowledge,
      frameworks: deps.frameworks,
      ...uploadedDesignOption(project),
      attestations: project.attestations,
      ...(project.design ? { previous: project.design } : {}),
      ...(project.escalationAcknowledgedAt ? { escalationAcknowledgedAt: project.escalationAcknowledgedAt } : {}),
    });
    project.design = design;
    project.profileHash = design.profileHash;
    project.designStale = false;
    project.status = 'designed';
    const saved = deps.store.save(project);
    res.json(DeriveDesignResponseSchema.parse({ project: saved, design }));
  });

  // "Let's check a few things": follow-up questions and suggested features for the answers so far.
  router.post('/projects/:id/refine', async (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const provider = deps.getProvider('refine');
    if (provider.name === 'null') {
      throw llmUnavailable('Follow-up questions need AI. Turn AI on in Settings (or add a key) and try again; you can always carry on without them.');
    }
    const outcome = await refineProfile(provider, project.profile as PartialDesignProfile, {
      projectId: project.id,
      correlationId: `refine-${project.id}-${Date.now().toString(36)}`,
      ...(deps.config.settings.get().reviewEffort ? { effort: effectiveAiSettings(deps.config.settings.get()).reviewEffort } : {}),
    });
    const saved = deps.store.update(project.id, (p) => {
      p.refinement = outcome.refinement;
    });
    res.json(RefineResponseSchema.parse({ project: saved, refinement: outcome.refinement }));
  });

  router.post('/projects/:id/refine/decisions', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = RefineDecisionsRequestSchema.parse(req.body);
    if (!project.refinement) throw validationError('There are no follow-up questions to answer yet.');
    const refinement = project.refinement;
    let profile = project.profile as PartialDesignProfile;

    for (const answer of body.answers) {
      const question = refinement.questions.find((q) => q.id === answer.questionId);
      if (!question) continue;
      question.answered = true;
      question.answer = answer.value;
      // Only an answer the question itself offered, for a field on the allow-list, changes the design.
      const allowed = question.field !== undefined && question.options.some((o) => o.value === answer.value) && answerFieldAllowed(question.field, answer.value);
      if (allowed) profile = applyRefinement(profile, question.field!, answer.value);
    }
    for (const decision of body.features) {
      const feature = refinement.features.find((f) => f.id === decision.suggestionId);
      if (!feature) continue;
      feature.accepted = decision.accepted;
      if (decision.accepted && answerFieldAllowed(feature.field, feature.value)) profile = applyRefinement(profile, feature.field, feature.value);
    }
    if (body.dismiss) refinement.dismissedAt = new Date().toISOString();

    const saved = deps.store.update(project.id, (p) => {
      p.profile = PartialDesignProfileSchema.parse(profile);
      p.refinement = refinement;
      const full = DesignProfileSchema.safeParse(p.profile);
      if (full.success && p.profileHash && p.profileHash !== profileHash(full.data)) {
        p.designStale = true;
        p.buildStale = true;
      }
      const name = p.profile.app?.name?.trim();
      if (name) p.name = name.slice(0, 60);
    });
    res.json({ project: saved, refinement: saved.refinement });
  });

  router.post('/projects/:id/design/peer-review', async (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const provider = deps.getProvider('quick-infer');
    const parsed = DesignProfileSchema.safeParse(project.profile);
    if (!parsed.success || !project.design) throw validationError('Finish your design before asking for a second opinion.');
    if (provider.name === 'null') {
      // Without AI the design continues; the report records that SbD step 5 was not performed.
      const skipped = {
        performedBy: 'skipped' as const,
        performedAt: new Date().toISOString(),
        summary: 'No second opinion was requested because SecureVibe is running without an Anthropic API key.',
        suggestions: [],
        skippedReason: 'Preview without AI: add an Anthropic API key and rebuild to get an AI second opinion on this design.',
      };
      project.design = { ...project.design, peerReview: skipped };
      deps.store.save(project);
      res.json(PeerReviewResponseSchema.parse({ peerReview: skipped, design: project.design }));
      return;
    }

    // One second opinion at a time per project; "Skip" aborts it through this controller.
    IN_FLIGHT_PEER_REVIEWS.get(project.id)?.abort();
    const controller = new AbortController();
    IN_FLIGHT_PEER_REVIEWS.set(project.id, controller);
    let outcome;
    try {
      outcome = await peerReview(provider, project.design, parsed.data, {
        projectId: project.id,
        correlationId: `peer-review-${project.id}-${Date.now()}`,
        effort: effectiveAiSettings(deps.config.settings.get()).reviewEffort,
        abort: controller.signal,
      });
    } finally {
      if (IN_FLIGHT_PEER_REVIEWS.get(project.id) === controller) IN_FLIGHT_PEER_REVIEWS.delete(project.id);
    }
    if (controller.signal.aborted) {
      // The person skipped it meanwhile; the skip endpoint already saved that decision.
      const current = deps.store.mustGet(project.id);
      if (!current.design?.peerReview) throw conflict('The second opinion was stopped before it finished. Reload the page to continue.');
      res.json(PeerReviewResponseSchema.parse({ peerReview: current.design.peerReview, design: current.design }));
      return;
    }
    let profile = parsed.data;
    for (const suggestion of outcome.peerReview.suggestions) {
      if (suggestion.kind !== 'control' || !suggestion.profilePatch) continue;
      profile = applyPeerReviewPatch(profile, suggestion.profilePatch);
      suggestion.accepted = true;
      suggestion.applied = true;
    }
    const design = deriveDesign(profile, {
      knowledge: deps.knowledge,
      frameworks: deps.frameworks,
      ...uploadedDesignOption(project),
      attestations: project.attestations,
      previous: { ...project.design, peerReview: outcome.peerReview },
      ...(project.escalationAcknowledgedAt ? { escalationAcknowledgedAt: project.escalationAcknowledgedAt } : {}),
    });
    design.peerReview = outcome.peerReview;
    project.profile = profile;
    project.design = design;
    project.profileHash = design.profileHash;
    deps.store.save(project);
    res.json(PeerReviewResponseSchema.parse({ peerReview: outcome.peerReview, design }));
  });

  // "Skip the second opinion": stops a running review (no further cost) and records the choice for the report.
  router.post('/projects/:id/design/peer-review/skip', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (!project.design) throw validationError('Finish your design before choosing to skip the second opinion.');
    IN_FLIGHT_PEER_REVIEWS.get(project.id)?.abort();
    IN_FLIGHT_PEER_REVIEWS.delete(project.id);
    const skipped = {
      performedBy: 'skipped' as const,
      performedAt: new Date().toISOString(),
      summary: 'You chose to skip the second opinion. Nothing was reviewed and nothing was changed.',
      suggestions: [],
      skippedReason: 'Skipped at your request (Secure by Design step 5 was not performed).',
    };
    project.design = { ...project.design, peerReview: skipped };
    const saved = deps.store.save(project);
    res.json(PeerReviewResponseSchema.parse({ peerReview: skipped, design: saved.design! }));
  });

  router.post('/projects/:id/design/peer-review/decisions', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = PeerReviewDecisionsRequestSchema.parse(req.body);
    const parsed = DesignProfileSchema.safeParse(project.profile);
    if (!parsed.success || !project.design?.peerReview) throw validationError('There is no second opinion to answer yet.');
    let profile = parsed.data;
    const peerReviewResult = project.design.peerReview;
    for (const decision of body.decisions) {
      const suggestion = peerReviewResult.suggestions.find((s) => s.id === decision.suggestionId);
      if (!suggestion) continue;
      suggestion.accepted = decision.accepted;
      if (!decision.accepted) {
        if (decision.dismissReason) suggestion.dismissReason = decision.dismissReason;
        continue;
      }
      const option = decision.optionIndex !== undefined ? suggestion.options?.[decision.optionIndex] : undefined;
      const patch = option?.profilePatch ?? suggestion.profilePatch;
      if (patch) {
        profile = applyPeerReviewPatch(profile, patch);
        suggestion.applied = true;
      }
    }
    const design = deriveDesign(profile, {
      knowledge: deps.knowledge,
      frameworks: deps.frameworks,
      ...uploadedDesignOption(project),
      attestations: project.attestations,
      previous: { ...project.design, peerReview: peerReviewResult },
      ...(project.escalationAcknowledgedAt ? { escalationAcknowledgedAt: project.escalationAcknowledgedAt } : {}),
    });
    design.peerReview = peerReviewResult;
    project.profile = profile;
    project.design = design;
    project.profileHash = design.profileHash;
    const saved = deps.store.save(project);
    res.json(DeriveDesignResponseSchema.parse({ project: saved, design }));
  });

  router.post('/projects/:id/escalation/acknowledge', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    project.escalationAcknowledgedAt = new Date().toISOString();
    const parsed = DesignProfileSchema.safeParse(project.profile);
    if (parsed.success && project.design) {
      project.design = deriveDesign(parsed.data, {
        knowledge: deps.knowledge,
        frameworks: deps.frameworks,
        ...uploadedDesignOption(project),
        attestations: project.attestations,
        previous: project.design,
        escalationAcknowledgedAt: project.escalationAcknowledgedAt,
      });
    }
    const saved = deps.store.save(project);
    res.json({ project: saved });
  });

  router.get('/projects/:id/estimate', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (!project.design) throw validationError('Finish your design before estimating the build.');
    const settings = deps.config.settings.get();
    const full = estimateForProject(project.profile as DesignProfile, project.design.buildSpec, settings, { reviewOnly: isUploadedApp(project) });
    // Without AI nothing is sent to Anthropic, so the build is free and much quicker.
    const estimate =
      deps.getProvider().name === 'null'
        ? {
            ...full,
            usdLow: 0,
            usdHigh: 0,
            minutesLow: Math.max(2, Math.round(full.minutesLow / 4)),
            minutesHigh: Math.max(5, Math.round(full.minutesHigh / 4)),
            note: isUploadedApp(project)
              ? 'This check runs without AI, so it uses no Anthropic credit. SecureVibe scans your code and writes the reports; the AI code review is skipped.'
              : 'This build runs without AI, so it uses no Anthropic credit. It builds the hardened starter app with your records, then runs every security check and writes the reports.',
          }
        : full;
    const session = res.locals['session'] as SessionRecord;
    const approvalCode = deps.approvals.issue({
      projectId: project.id,
      sessionId: session.id,
      designHash: project.design.profileHash,
      estimateUsdHigh: estimate.usdHigh,
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json(EstimateResponseSchema.parse({ estimate, approvalCode }));
  });

  router.get('/projects/:id/findings', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (!project.lastRunId) return res.json(FindingsResponseSchema.parse({ findings: [] }));
    const run = deps.store.readRun(project.id, project.lastRunId);
    const findings: Finding[] = (run?.findings ?? []).map((f) => {
      const decision = project.findingDecisions.find((d) => d.fingerprint === f.fingerprint);
      return decision ? { ...f, status: decision.status, triage: decision.triage } : f;
    });
    res.json(FindingsResponseSchema.parse({ findings }));
  });

  router.post('/projects/:id/findings/:findingId/decision', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = FindingDecisionRequestSchema.parse(req.body);
    if (!project.lastRunId) throw notFound('That finding could not be found.');
    const run = deps.store.readRun(project.id, project.lastRunId);
    const finding = run?.findings.find((f) => f.id === req.params['findingId']);
    if (!finding) throw notFound('That finding could not be found.');
    if (body.status === 'open') {
      deps.store.setFindingDecision(project.id, { fingerprint: finding.fingerprint, status: 'open' });
    } else {
      const now = new Date().toISOString();
      deps.store.setFindingDecision(project.id, {
        fingerprint: finding.fingerprint,
        status: body.status,
        triage: { reason: body.triage?.reason ?? '', by: 'owner', at: now, ...(body.triage?.compensatingControl ? { compensatingControl: body.triage.compensatingControl } : {}), ...(body.triage?.acknowledgedConsequence ? { acknowledgedConsequence: body.triage.acknowledgedConsequence } : {}) },
      });
    }
    res.status(204).end();
  });

  router.post('/projects/:id/attestations', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = AttestationRequestSchema.parse(req.body);
    const attestation = deps.store.addAttestation(project.id, { ...body, attestedBy: body.attestedBy || 'owner' });
    res.status(201).json({ attestation });
  });

  router.delete('/projects/:id/attestations/:attestationId', (req, res) => {
    const removed = deps.store.removeAttestation(req.params['id']!, req.params['attestationId']!);
    if (!removed) throw notFound('That attestation could not be found.');
    res.status(204).end();
  });

  router.post('/projects/:id/human-review', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = HumanReviewRequestSchema.parse(req.body);
    const scope = reviewScope(project, deps.store, deps.config);
    if (!scope) throw validationError('Build the app before recording a human code review.');
    const { hash, files: filesReviewed } = reviewTree(scope);
    const review = HumanCodeReviewSchema.parse({
      reviewedBy: body.reviewedBy,
      reviewedAt: new Date().toISOString(),
      filesReviewed,
      codeTreeHash: hash,
      ...(body.note ? { note: body.note } : {}),
    });
    const saved = deps.store.setHumanCodeReview(project.id, review);
    res.json({ project: saved });
  });

  /** Where a document named by a check may live: the app, the project's own folder, or SecureVibe itself. */
  const documentRoots = (projectId: string) => ({
    appDir: deps.store.paths(projectId).appDir,
    projectDir: deps.store.paths(projectId).dir,
    repoRoot: deps.config.paths.repoRoot,
  });

  router.get('/projects/:id/verification', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const run = project.lastRunId ? deps.store.readRun(project.id, project.lastRunId) : undefined;
    if (!run?.compliance) throw notFound('This app has no finished build with a compliance result yet.');
    const results = new Map(
      [...run.compliance.asvs.results, ...(run.compliance.aisvs?.results ?? []), ...(run.compliance.appendixC?.results ?? [])].map((r) => [`${r.standard}:${r.id}`, r]),
    );
    const answers = new Map(project.attestations.map((a) => [`${a.standard}:${a.requirementId}`, a]));
    const scope = reviewScope(project, deps.store, deps.config);
    const review = project.humanCodeReview;
    const lastInput = [...project.attestations.map((a) => a.attestedAt), ...(review ? [review.reviewedAt] : [])].sort().at(-1);
    const writtenAt = run.reportsRefreshedAt ?? run.finishedAt ?? run.startedAt;
    const body: VerificationResponse = {
      runId: run.id,
      builtAt: run.startedAt,
      suggestedName: (project.profile as Partial<DesignProfile>)?.deployment?.owner?.name ?? '',
      codeReview: {
        root: scope?.root ?? null,
        files: scope ? reviewTree(scope).files : [],
        ...(review ? { reviewedBy: review.reviewedBy, reviewedAt: review.reviewedAt, ...(review.note ? { note: review.note } : {}) } : {}),
        current: reviewIsCurrent(project, deps.store, deps.config),
      },
      items: run.compliance.manualVerification.map((m) => {
        const r = results.get(`${m.standard}:${m.requirementId}`);
        const answer = answers.get(`${m.standard}:${m.requirementId}`);
        return {
          requirementId: m.requirementId,
          standard: m.standard,
          chapterName: r?.chapterName ?? '',
          description: r?.description ?? '',
          ...(r?.plainLanguage ? { plainLanguage: r.plainLanguage } : {}),
          status: r?.status ?? 'not-verified',
          whoCanDo: m.manual.whoCanDo,
          ...(m.manual.question ? { question: m.manual.question } : {}),
          steps: m.manual.steps,
          ...(m.manual.whatCountsAsEvidence ? { whatCountsAsEvidence: m.manual.whatCountsAsEvidence } : {}),
          estimatedEffort: m.manual.estimatedEffort,
          ...(answer ? { answer } : {}),
          // The files this check names, so the wizard can put them in front of the person.
          documents: documentsFor([m.manual.question, ...m.manual.steps, m.manual.whatCountsAsEvidence], documentRoots(project.id)),
        };
      }),
      canRefresh: loadComplianceInputs(deps.store, project.id, run.id) !== undefined,
      reportsOutdated: lastInput !== undefined && lastInput > writtenAt,
      selfAssessment: project.name === SELF_PROJECT_NAME,
    };
    res.json(VerificationResponseSchema.parse(body));
  });

  // One document a human check refers to, so the wizard can show it without the person going looking for it.
  router.get('/projects/:id/document', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const path = typeof req.query['path'] === 'string' ? req.query['path'] : '';
    if (!path || path.length > 512 || path.includes('\0')) throw validationError('Which document?');
    try {
      const doc = readDocument(path, documentRoots(project.id));
      res.json(DocumentResponseSchema.parse({ path, where: doc.where, text: doc.text }));
    } catch (err) {
      if (err instanceof DocumentNotAvailable) throw notFound(err.message);
      if (err instanceof PathConfinementError) throw forbidden('That path is not allowed.');
      throw err;
    }
  });

  router.post('/projects/:id/reports/refresh', async (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (project.lastRunId && runIsLive(deps.store, project.lastRunId)) throw conflict('A build is running. Refresh the reports when it has finished.');
    try {
      const run = await refreshReportsWithAnswers(deps, project.id);
      deps.logger.info({ event: 'reports.refreshed', projectId: project.id, runId: run.id }, 'reports refreshed with human answers');
      res.json({ run });
    } catch (err) {
      if (err instanceof RefreshUnavailableError) throw conflict(err.message);
      throw err;
    }
  });

  router.get('/projects/:id/preview', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    res.json({ preview: deps.previews.info(project.id) });
  });

  router.post('/projects/:id/preview', async (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (project.lastRunId && runIsLive(deps.store, project.lastRunId)) throw conflict('The app is being built. Preview it when the build has finished.');
    if (!project.design) throw validationError('Design and build the app before previewing it.');
    if (isUploadedApp(project)) throw validationError('SecureVibe can only preview apps it built itself.');
    try {
      const preview = await deps.previews.start(project.id, project.design.buildSpec);
      deps.logger.info({ event: 'preview.started', projectId: project.id }, 'app preview started');
      res.json({ preview });
    } catch (err) {
      if (err instanceof PreviewError) {
        deps.logger.warn({ event: 'preview.failed', projectId: project.id, detail: err.detail }, 'app preview did not start');
        throw conflict(err.message);
      }
      throw err;
    }
  });

  router.delete('/projects/:id/preview', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    if (deps.previews.stop(project.id)) deps.logger.info({ event: 'preview.stopped', projectId: project.id }, 'app preview stopped');
    res.json({ preview: deps.previews.info(project.id) });
  });

  router.get('/projects/:id/app/run-instructions', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const { appDir } = deps.store.paths(project.id);
    if (!existsSync(appDir)) throw notFound('This project has not been built yet.');
    // SecureVibe does not know how to start an app it did not build.
    if (isUploadedApp(project)) throw notFound('Run instructions are only available for apps SecureVibe built.');
    res.json(buildRunInstructions(project.id, appDir, project.design?.buildSpec));
  });

  return router;
}

function buildRunInstructions(projectId: string, appDir: string, buildSpec?: { features: { adminMfa: boolean } }): RunInstructions {
  const hasNodeModules = existsSync(join(appDir, 'node_modules'));
  const hasEnv = existsSync(join(appDir, '.env'));
  const firstLoginFile = join(appDir, 'FIRST-LOGIN.txt');
  const hasFirstLogin = existsSync(firstLoginFile);

  const steps: RunInstructions['steps'] = [{ title: 'Open a terminal and go to your application folder', command: `cd "${appDir}"` }];
  if (!hasNodeModules) steps.push({ title: 'Install the packages', command: 'npm install', expected: 'A node_modules folder is created (this can take a minute).' });
  if (!hasEnv) steps.push({ title: 'Set up the app (secrets, database, first administrator)', command: 'npm run setup', expected: 'A one-time administrator password is printed and saved to FIRST-LOGIN.txt.' });
  steps.push({ title: 'Start the app', command: 'npm start', expected: 'A line saying the app is listening, with the address to open in your browser.', troubleshooting: 'If the port is already used by something else, set PORT=0 in .env and restart.' });

  let firstLogin: RunInstructions['firstLogin'];
  if (hasFirstLogin) {
    const text = readFileSync(firstLoginFile, 'utf8');
    const email = /Email address:\s*(\S+)/.exec(text)?.[1] ?? '';
    firstLogin = { url: 'http://127.0.0.1:3000', email, note: 'The one-time password is in the file FIRST-LOGIN.txt in your app folder (open it with TextEdit). It expires after 24 hours and must be changed at first sign-in. Delete FIRST-LOGIN.txt once you have signed in.' };
  }

  return RunInstructionsSchema.parse({
    appDir,
    steps,
    ...(firstLogin ? { firstLogin } : {}),
    needsAuthenticatorApp: buildSpec?.features.adminMfa ?? true,
    unfinished: [],
  });
}
