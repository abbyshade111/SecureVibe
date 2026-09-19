/**
 * Fetch wrapper for the SecureVibe local API. Adds the CSRF token to mutating requests, sends the
 * session cookie, and turns ApiError responses into plain-language ApiClientError instances the UI
 * can show directly.
 */
import type { z } from 'zod';
import type {
  ApiError,
  StatusResponse,
  ExampleProject,
  ProjectListItem,
  CreateProjectRequest,
  SaveProfileRequest,
  QuickInferResponse,
  DeriveDesignResponse,
  RunInstructions,
  FrameworkSummary,
  QuickInferRequestSchema,
  PeerReviewResponseSchema,
  PeerReviewDecisionsRequestSchema,
  EstimateResponseSchema,
  StartRunRequestSchema,
  StartRunResponseSchema,
  FindingDecisionRequestSchema,
  FindingsResponseSchema,
  AttestationRequestSchema,
  HumanReviewRequestSchema,
  UpdateSettingsRequestSchema,
  AppVersion,
  VersionDiff,
  FileDiffResponse,
  AppFileResponse,
} from '@shared/api.js';
import type { AppearanceResponse, ChecksResponse, DocumentResponse, MetricsResponse, SecurityAcrossAppsResponse, VerificationResponse } from '@shared/api.js';
import type { Project, Attestation } from '@shared/project.js';
import type { PipelineRun, ArtifactRef } from '@shared/pipeline.js';
import type { WizardCopy } from './wizardCopyTypes';
import { FALLBACK_WIZARD_COPY } from './wizardCopyFallback';

export class ApiClientError extends Error {
  code: string;
  details: unknown;
  correlationId?: string;
  status: number;

  constructor(status: number, error: ApiError['error']) {
    super(error.message);
    this.name = 'ApiClientError';
    this.code = error.code;
    this.details = error.details;
    this.correlationId = error.correlationId;
    this.status = status;
  }
}

let csrfToken = '';
let csrfInFlight: Promise<string> | null = null;

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

/**
 * Fetches the CSRF token on demand. A page that saves something as soon as it opens (the summary page derives
 * the design on mount) must not depend on the status request having finished first, and after a restart the
 * token we hold is stale — both cases are handled here rather than by every caller.
 */
async function ensureCsrfToken(force = false): Promise<string> {
  if (csrfToken && !force) return csrfToken;
  if (!csrfInFlight) {
    csrfInFlight = fetch('/api/status', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('status'))))
      .then((s: StatusResponse) => {
        csrfToken = s.csrfToken;
        return csrfToken;
      })
      .catch(() => '')
      .finally(() => {
        csrfInFlight = null;
      });
  }
  return csrfInFlight;
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

async function request<T>(path: string, init: RequestInit = {}, retriedCsrf = false): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (MUTATING.has(method)) {
    const token = await ensureCsrfToken();
    if (token) headers.set('X-CSRF-Token', token);
  }
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { ...init, method, headers, credentials: 'same-origin' });
  } catch {
    throw new ApiClientError(0, {
      code: 'network_error',
      message: 'SecureVibe could not be reached. Check that the app is still running on this computer.',
    });
  }
  if (res.status === 204) return undefined as T;
  const isJson = (res.headers.get('content-type') ?? '').includes('application/json');
  const body = isJson ? await res.json().catch(() => undefined) : undefined;
  if (!res.ok) {
    const err: ApiError['error'] = body?.error ?? {
      code: 'unknown',
      message: `Something went wrong (HTTP ${res.status}).`,
    };
    // A rejected token usually means SecureVibe restarted; fetch a fresh one and try the request once more.
    if (res.status === 403 && !retriedCsrf && MUTATING.has(method)) {
      const fresh = await ensureCsrfToken(true);
      if (fresh) return request<T>(path, init, true);
    }
    throw new ApiClientError(res.status, err);
  }
  return body as T;
}

/** Ends this browser's SecureVibe session. Opening the startup link again signs back in. */
export async function signOut(): Promise<void> {
  const token = await ensureCsrfToken();
  await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin', headers: token ? { 'X-CSRF-Token': token } : {} }).catch(() => undefined);
  csrfToken = '';
}

function j<T>(path: string, init?: RequestInit): Promise<T> {
  return request<T>(path, init);
}

// ---- status / settings --------------------------------------------------

export function getMetrics(days: 7 | 30 | 90): Promise<MetricsResponse> {
  return j<MetricsResponse>(`/metrics?days=${days}`);
}

/** Every app's security at once, for the across-apps view. */
export function getSecurityAcrossApps(): Promise<SecurityAcrossAppsResponse> {
  return j<SecurityAcrossAppsResponse>('/security');
}

export function saveAiKey(body: { service: 'anthropic' | 'openai' | 'google'; key?: string; remove?: boolean }): Promise<StatusResponse['aiServices']> {
  return j<{ aiServices: StatusResponse['aiServices'] }>('/settings/ai-key', { method: 'PUT', body: JSON.stringify(body) }).then((r) => r.aiServices);
}

export function getStatus(): Promise<StatusResponse> {
  return j<StatusResponse>('/status');
}

export async function updateSettings(body: z.infer<typeof UpdateSettingsRequestSchema>): Promise<StatusResponse['settings']> {
  const { settings } = await j<{ settings: StatusResponse['settings'] }>('/settings', { method: 'PUT', body: JSON.stringify(body) });
  return settings;
}

// ---- knowledge ------------------------------------------------------------

export async function getWizardCopy(): Promise<WizardCopy> {
  try {
    return await j<WizardCopy>('/knowledge/wizard-copy');
  } catch {
    return FALLBACK_WIZARD_COPY;
  }
}

export function getFrameworkSummary(): Promise<FrameworkSummary> {
  return j<FrameworkSummary>('/frameworks/summary');
}

export async function getExamples(): Promise<ExampleProject[]> {
  const { examples } = await j<{ examples: ExampleProject[] }>('/examples');
  return examples;
}

// ---- projects ---------------------------------------------------------

export async function listProjects(): Promise<ProjectListItem[]> {
  const { projects } = await j<{ projects: ProjectListItem[] }>('/projects');
  return projects;
}

export async function createProject(body: CreateProjectRequest): Promise<Project> {
  const { project } = await j<{ project: Project }>('/projects', { method: 'POST', body: JSON.stringify(body) });
  return project;
}

export async function getProject(id: string): Promise<Project> {
  const { project } = await j<{ project: Project }>(`/projects/${id}`);
  return project;
}

/** Hides an app from the main list (nothing is deleted). */
export function archiveProject(id: string): Promise<Project> {
  return j<{ project: Project }>(`/projects/${id}/archive`, { method: 'POST' }).then((r) => r.project);
}

export function restoreProject(id: string): Promise<Project> {
  return j<{ project: Project }>(`/projects/${id}/restore`, { method: 'POST' }).then((r) => r.project);
}

export function deleteProject(id: string): Promise<void> {
  return j<void>(`/projects/${id}`, { method: 'DELETE' });
}

export async function saveProfile(id: string, body: SaveProfileRequest): Promise<Project> {
  const { project } = await j<{ project: Project }>(`/projects/${id}/profile`, { method: 'PUT', body: JSON.stringify(body) });
  return project;
}

/**
 * Last-moment save while the page is closing: `keepalive` lets the request finish after the tab is gone.
 * Best effort; answers saved earlier are already on the server.
 */
export function saveProfileOnExit(id: string, body: SaveProfileRequest): void {
  const token = csrfToken;
  if (!token) return;
  void fetch(`/api/projects/${id}/profile`, {
    method: 'PUT',
    keepalive: true,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify(body),
  }).catch(() => undefined);
}

export function quickInfer(
  id: string,
  body: z.infer<typeof QuickInferRequestSchema>,
): Promise<QuickInferResponse> {
  return j<QuickInferResponse>(`/projects/${id}/quick-infer`, { method: 'POST', body: JSON.stringify(body) });
}

export function deriveDesign(id: string): Promise<DeriveDesignResponse> {
  return j<DeriveDesignResponse>(`/projects/${id}/design`, { method: 'POST' });
}

export function requestPeerReview(id: string): Promise<z.infer<typeof PeerReviewResponseSchema>> {
  return j(`/projects/${id}/design/peer-review`, { method: 'POST' });
}

/** Skips (or stops) the AI second opinion; the report records that it was skipped at the owner's request. */
export function skipPeerReview(id: string): Promise<z.infer<typeof PeerReviewResponseSchema>> {
  return j(`/projects/${id}/design/peer-review/skip`, { method: 'POST' });
}

export function submitPeerReviewDecisions(
  id: string,
  body: z.infer<typeof PeerReviewDecisionsRequestSchema>,
): Promise<z.infer<typeof PeerReviewResponseSchema>> {
  return j(`/projects/${id}/design/peer-review/decisions`, { method: 'POST', body: JSON.stringify(body) });
}

export async function acknowledgeEscalation(id: string): Promise<Project> {
  const { project } = await j<{ project: Project }>(`/projects/${id}/escalation/acknowledge`, { method: 'POST' });
  return project;
}

export function getEstimate(id: string): Promise<z.infer<typeof EstimateResponseSchema>> {
  return j(`/projects/${id}/estimate`);
}

// ---- runs ---------------------------------------------------------------

export function startRun(
  id: string,
  body: z.infer<typeof StartRunRequestSchema>,
): Promise<z.infer<typeof StartRunResponseSchema>> {
  return j(`/projects/${id}/runs`, { method: 'POST', body: JSON.stringify(body) });
}

export function setAppearance(id: string, theme: string): Promise<AppearanceResponse> {
  return j<AppearanceResponse>(`/projects/${id}/appearance`, { method: 'PUT', body: JSON.stringify({ theme }) });
}

export function getChecks(id: string): Promise<ChecksResponse> {
  return j<ChecksResponse>(`/projects/${id}/checks`);
}

export async function getRun(runId: string): Promise<PipelineRun> {
  const { run } = await j<{ run: PipelineRun }>(`/runs/${runId}`);
  return run;
}

export function cancelRun(runId: string): Promise<void> {
  return j<void>(`/runs/${runId}/cancel`, { method: 'POST' });
}

export function runEventsUrl(runId: string): string {
  return `/api/runs/${runId}/events`;
}

// ---- findings -------------------------------------------------------------

export function getFindings(id: string, opts: { run?: string; current?: boolean } = {}): Promise<z.infer<typeof FindingsResponseSchema>> {
  // `current` asks for every check's latest word rather than one run's, which is what the across-apps view counts:
  // after a check is re-run on its own, what it found is newer than the last run that ran everything. `run` asks
  // for one particular run.
  const query = opts.current ? '?current=1' : opts.run ? `?run=${encodeURIComponent(opts.run)}` : '';
  return j(`/projects/${id}/findings${query}`);
}

export function decideFinding(id: string, findingId: string, body: z.infer<typeof FindingDecisionRequestSchema>): Promise<void> {
  // No run is named: the server records the decision against the newest run that holds this finding, which is not
  // always the app's latest run once single checks have been re-run.
  return j<void>(`/projects/${id}/findings/${findingId}/decision`, { method: 'POST', body: JSON.stringify(body) });
}

// ---- attestations / human review -----------------------------------------

export function createAttestation(
  id: string,
  body: z.infer<typeof AttestationRequestSchema>,
): Promise<Attestation> {
  return j<Attestation>(`/projects/${id}/attestations`, { method: 'POST', body: JSON.stringify(body) });
}

export function deleteAttestation(id: string, attestationId: string): Promise<void> {
  return j<void>(`/projects/${id}/attestations/${attestationId}`, { method: 'DELETE' });
}

export interface PreviewInfo {
  running: boolean;
  url?: string;
  email?: string;
  password?: string;
  startedAt?: string;
  stopsAt?: string;
  differences: string[];
}

export function getPreview(id: string): Promise<PreviewInfo> {
  return j<{ preview: PreviewInfo }>(`/projects/${id}/preview`).then((r) => r.preview);
}

export function startPreview(id: string): Promise<PreviewInfo> {
  return j<{ preview: PreviewInfo }>(`/projects/${id}/preview`, { method: 'POST', body: '{}' }).then((r) => r.preview);
}

export function stopPreview(id: string): Promise<PreviewInfo> {
  return j<{ preview: PreviewInfo }>(`/projects/${id}/preview`, { method: 'DELETE' }).then((r) => r.preview);
}

export function createPlan(id: string): Promise<{ project: Project; plan: NonNullable<Project['buildPlan']> }> {
  return j(`/projects/${id}/plan`, { method: 'POST', body: '{}' });
}

export function approvePlan(id: string, featureIds: string[]): Promise<{ project: Project; plan: NonNullable<Project['buildPlan']> }> {
  return j(`/projects/${id}/plan/approve`, { method: 'POST', body: JSON.stringify({ featureIds }) });
}

export function requestRefinement(id: string): Promise<{ project: Project; refinement: NonNullable<Project['refinement']> }> {
  return j(`/projects/${id}/refine`, { method: 'POST', body: '{}' });
}

export function saveRefinementDecisions(
  id: string,
  body: { answers?: { questionId: string; value: string }[]; features?: { suggestionId: string; accepted: boolean }[]; dismiss?: boolean },
): Promise<{ project: Project; refinement?: Project['refinement'] }> {
  return j(`/projects/${id}/refine/decisions`, { method: 'POST', body: JSON.stringify(body) });
}

export function beginUpload(id: string): Promise<void> {
  return j<void>(`/projects/${id}/upload/begin`, { method: 'POST', body: '{}' });
}

export function uploadFile(id: string, path: string, file: Blob): Promise<{ stored: boolean; reason?: string }> {
  return j(`/projects/${id}/upload/file?path=${encodeURIComponent(path)}`, {
    method: 'PUT',
    body: file,
    headers: { 'Content-Type': 'application/octet-stream' },
  });
}

export function finishUpload(id: string): Promise<Project> {
  return j<{ project: Project }>(`/projects/${id}/upload/finish`, { method: 'POST', body: '{}' }).then((r) => r.project);
}

export function getVerification(id: string): Promise<VerificationResponse> {
  return j<VerificationResponse>(`/projects/${id}/verification`);
}

export function getDocument(id: string, path: string): Promise<DocumentResponse> {
  return j(`/projects/${id}/document?path=${encodeURIComponent(path)}`);
}

export function getVersions(id: string): Promise<AppVersion[]> {
  return j<{ versions: AppVersion[] }>(`/projects/${id}/versions`).then((r) => r.versions);
}

export function getVersionDiff(id: string, from: string, to: string): Promise<VersionDiff> {
  return j(`/projects/${id}/diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
}

export function getFileDiff(id: string, from: string, to: string, path: string): Promise<FileDiffResponse> {
  return j(`/projects/${id}/diff/file?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&path=${encodeURIComponent(path)}`);
}

export function upgradeTemplate(id: string): Promise<{ project: Project; upgrade: NonNullable<Project['lastUpgrade']> }> {
  return j(`/projects/${id}/upgrade`, { method: 'POST', body: '{}' });
}

export function refreshReports(id: string): Promise<PipelineRun> {
  return j<{ run: PipelineRun }>(`/projects/${id}/reports/refresh`, { method: 'POST', body: '{}' }).then((r) => r.run);
}

export function submitHumanReview(
  id: string,
  body: z.infer<typeof HumanReviewRequestSchema>,
): Promise<Project> {
  return j<{ project: Project }>(`/projects/${id}/human-review`, { method: 'POST', body: JSON.stringify(body) }).then((r) => r.project);
}

// ---- artifacts / run instructions -----------------------------------------

export async function getArtifacts(id: string, runId?: string): Promise<ArtifactRef[]> {
  const query = runId ? `?run=${encodeURIComponent(runId)}` : '';
  const { artifacts } = await j<{ artifacts: ArtifactRef[] }>(`/projects/${id}/artifacts${query}`);
  return artifacts;
}

/** A build that produced reports, for the report history on the results page. */
export interface ReportRun {
  id: string;
  mode: string;
  status: string;
  startedAt: string;
  finishedAt?: string;
  reportCount: number;
  headline?: string;
}

export async function getReportRuns(id: string): Promise<ReportRun[]> {
  const { runs } = await j<{ runs: ReportRun[] }>(`/projects/${id}/report-runs`);
  return runs;
}

/** With a run id the address names the run in its path, so links inside a report stay within that run. */
export function artifactUrl(id: string, name: string, runId?: string): string {
  return runId
    ? `/api/projects/${id}/reports/${encodeURIComponent(runId)}/${encodeURIComponent(name)}`
    : `/api/projects/${id}/artifacts/${encodeURIComponent(name)}`;
}

/** One file of the generated app, for "show me this code" on a finding. */
export function getAppFile(id: string, path: string, version = 'current'): Promise<AppFileResponse> {
  return j<AppFileResponse>(`/projects/${id}/app/file?path=${encodeURIComponent(path)}&version=${encodeURIComponent(version)}`);
}

export function getRunInstructions(id: string): Promise<RunInstructions> {
  return j<RunInstructions>(`/projects/${id}/app/run-instructions`);
}
