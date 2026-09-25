import { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router';
import { AppPreview } from '../components/AppPreview';
import { CodeViewer } from '../components/CodeViewer';
import { FindingCard } from '../components/FindingCard';
import { VersionDiff } from '../components/VersionDiff';
import { Mascot, mascotForRating } from '../components/Mascot';
import type { Finding } from '@shared/findings.js';
import type { PipelineRun } from '@shared/pipeline.js';
import type { RunInstructions } from '@shared/api.js';
import { STATUS_DEFINITIONS } from '@shared/compliance.js';
import { useProject } from '../hooks/useProject';
import {
  artifactUrl,
  createAttestation,
  decideFinding,
  getArtifacts,
  getEstimate,
  getFindings,
  getReportRuns,
  getRun,
  getRunInstructions,
  refreshReports,
  startRun,
  setAppearance,
  submitHumanReview,
  type ReportRun,
  upgradeTemplate,
} from '../lib/api';
import { Badge, Card, CopyRow, ErrorNotice, LoadingScreen } from '../components/Bits';
import { formatDate } from '../lib/format';
import type { ArtifactRef } from '@shared/pipeline.js';

const RATING_TONE = { good: 'good', 'needs-attention': 'warn', 'at-risk': 'bad' } as const;


const PLAN_LABEL: Record<string, string> = {
  built: 'Built',
  'files-in-place': 'Files in place',
  partly: 'Partly built',
  'not-built': 'Not built',
  'left-out': 'Left out',
};

const PLAN_TONE: Record<string, 'good' | 'warn' | 'bad' | 'neutral'> = {
  built: 'good',
  'files-in-place': 'warn',
  partly: 'warn',
  'not-built': 'bad',
  'left-out': 'neutral',
};

const RUN_KIND: Record<string, string> = { full: 'Build', demo: 'Demo build', 'verify-only': 'Re-check' };
const RUN_STATUS: Record<string, string> = { succeeded: 'finished', failed: 'failed', cancelled: 'canceled', interrupted: 'stopped', running: 'running' };

function reportRunLabel(r: ReportRun): string {
  const when = new Date(r.startedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  return `${RUN_KIND[r.mode] ?? 'Run'} on ${when} — ${RUN_STATUS[r.status] ?? r.status}`;
}


const THEMES = [
  { id: 'calm', label: 'Calm' },
  { id: 'warm', label: 'Warm' },
  { id: 'forest', label: 'Forest' },
  { id: 'contrast', label: 'High contrast' },
] as const;

export function ResultsPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { project, loading, error, reload } = useProject(id);
  const [run, setRun] = useState<PipelineRun | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [instructions, setInstructions] = useState<RunInstructions | null>(null);
  const [artifacts, setArtifacts] = useState<ArtifactRef[] | null>(null);
  const [reportRuns, setReportRuns] = useState<ReportRun[]>([]);
  const [reportRunId, setReportRunId] = useState<string | undefined>(undefined);
  const [dataError, setDataError] = useState<string | null>(null);
  const [reviewerName, setReviewerName] = useState('');
  const [showRebuild, setShowRebuild] = useState(false);
  const [showRecheck, setShowRecheck] = useState(false);
  const [rechecking, setRechecking] = useState<'free' | 'ai' | null>(null);
  const [recheckError, setRecheckError] = useState<string | null>(null);
  const [reviewEstimate, setReviewEstimate] = useState<{ usdLow: number; usdHigh: number; aiAvailable: boolean } | null>(null);

  // "Check this app again": every automated check on the app exactly as it is, nothing rewritten. Free without
  // AI; with the AI review it costs the review alone — for a built app, until now the only way to that review
  // was a full rebuild at fifteen times the price, which also changed the code.
  async function openRecheck() {
    setShowRecheck((v) => !v);
    if (reviewEstimate) return;
    try {
      const { estimate } = await getEstimate(id!, { reviewOnly: true });
      setReviewEstimate({ usdLow: estimate.usdLow, usdHigh: estimate.usdHigh, aiAvailable: estimate.usdHigh > 0 });
    } catch {
      setReviewEstimate({ usdLow: 0, usdHigh: 0, aiAvailable: false });
    }
  }

  async function recheck(withAi: boolean) {
    if (!id) return;
    setRechecking(withAi ? 'ai' : 'free');
    setRecheckError(null);
    try {
      const { approvalCode } = await getEstimate(id, { reviewOnly: true });
      const { run: started } = await startRun(id, { mode: 'verify-only', approved: true, approvalCode, ...(withAi ? {} : { withoutAi: true }) });
      navigate(`/projects/${id}/build?run=${encodeURIComponent(started.id)}`);
    } catch (e) {
      setRecheckError(e instanceof Error ? e.message : 'Could not start the check.');
      setRechecking(null);
    }
  }
  const [upgrading, setUpgrading] = useState(false);
  const [selectedFixes, setSelectedFixes] = useState<string[]>([]);
  const [savingTheme, setSavingTheme] = useState(false);
  const [themeMessage, setThemeMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const currentTheme = project?.profile?.app?.theme ?? 'calm';

  // Color only: no rebuild, no checks, no approval — the app reads the new value the next time it starts.
  async function chooseTheme(theme: string) {
    if (!id) return;
    setSavingTheme(true);
    setThemeMessage(null);
    try {
      const result = await setAppearance(id, theme);
      setThemeMessage({ ok: true, text: result.message });
      await reload();
    } catch (e) {
      setThemeMessage({ ok: false, text: e instanceof Error ? e.message : 'Could not change how your app looks.' });
    } finally {
      setSavingTheme(false);
    }
  }

  const [upgradeError, setUpgradeError] = useState<string | null>(null);

  // Update the app to the latest template (no AI, nothing rewritten), then run the free re-check so the results
  // describe the updated app.
  async function upgradeNow() {
    if (!id) return;
    setUpgrading(true);
    setUpgradeError(null);
    try {
      await upgradeTemplate(id);
      const { approvalCode } = await getEstimate(id);
      // Send the Build page to this exact run. Left to work it out from the project, it reads a lastRunId that was
      // fetched before this run existed, sees nothing running, and offers to start a build with AI instead — so a
      // button promising a free update appeared to ask for money.
      const { run: started } = await startRun(id, { mode: 'verify-only', approved: true, approvalCode, withoutAi: true });
      navigate(`/projects/${id}/build?run=${encodeURIComponent(started.id)}`);
    } catch (e) {
      setUpgradeError(e instanceof Error ? e.message : 'Could not update the app.');
      setUpgrading(false);
    }
  }
  const [refreshing, setRefreshing] = useState(false);
  const [refreshMessage, setRefreshMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function refreshReportsNow() {
    if (!id) return;
    setRefreshing(true);
    setRefreshMessage(null);
    try {
      await refreshReports(id);
      const runs = await getReportRuns(id);
      setReportRuns(runs);
      setReportRunId(runs[0]?.id);
      if (runs[0]) setArtifacts(await getArtifacts(id, runs[0].id));
      setRefreshMessage({ ok: true, text: 'The reports were rewritten with everything recorded so far.' });
    } catch (e) {
      setRefreshMessage({ ok: false, text: e instanceof Error ? e.message : 'Could not rewrite the reports.' });
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    if (!id || !project?.lastRunId) return;
    getRun(project.lastRunId)
      .then(setRun)
      .catch((e) => setDataError(e instanceof Error ? e.message : 'Could not load the results.'));
    getFindings(id)
      .then((r) => setFindings(r.findings))
      .catch(() => setFindings([]));
    getRunInstructions(id)
      .then(setInstructions)
      .catch(() => undefined);
    // The newest build that produced reports is shown first; earlier ones can be picked from the list.
    getReportRuns(id)
      .then((runs) => {
        setReportRuns(runs);
        setReportRunId(runs[0]?.id);
      })
      .catch(() => setReportRuns([]));
  }, [id, project?.lastRunId]);

  // Arriving at #reports (a link into the documents section): bring the reports into view once they are on the page.
  const location = useLocation();
  useEffect(() => {
    if (location.hash !== '#reports' || reportRuns.length === 0 || !run) return;
    document.getElementById('reports')?.scrollIntoView({ block: 'start' });
  }, [location.hash, reportRuns.length, run]);

  useEffect(() => {
    if (!id) return;
    if (!reportRunId) {
      setArtifacts([]);
      return;
    }
    getArtifacts(id, reportRunId)
      .then(setArtifacts)
      .catch(() => setArtifacts([]));
  }, [id, reportRunId]);

  async function refreshFindings() {
    if (!id) return;
    const r = await getFindings(id);
    setFindings(r.findings);
  }

  /** Sends one or more findings to a fix run; the Build page shows the estimate and asks for approval first. */
  function askAiToFix(findingIds: string[]) {
    if (findingIds.length === 0) return;
    navigate(`/projects/${id}/build?fix=${encodeURIComponent(findingIds.join(','))}`);
  }

  async function markFalsePositive(findingId: string, reason: string) {
    if (!id) return;
    await decideFinding(id, findingId, { status: 'false-positive', triage: { reason } });
    await refreshFindings();
  }

  async function acceptFinding(findingId: string, reason: string) {
    if (!id) return;
    await decideFinding(id, findingId, {
      status: 'accepted',
      triage: { reason: reason || 'Owner chose to leave this as-is.', acknowledgedConsequence: reason || undefined },
    });
    await refreshFindings();
  }

  async function attest(requirementId: string, standard: 'asvs' | 'aisvs' | 'aisvs-appendix-c' | 'sbd', result: 'yes' | 'no' | 'not-sure') {
    if (!id) return;
    await createAttestation(id, {
      requirementId,
      standard,
      result,
      note: '',
      attestedBy: reviewerName || project?.profile.deployment?.owner?.name || 'Owner',
    });
    await reload();
  }

  async function markReviewed() {
    if (!id || !reviewerName.trim()) return;
    await submitHumanReview(id, { reviewedBy: reviewerName.trim() });
    await reload();
  }

  if (loading) return <LoadingScreen label="Loading…" />;
  if (error || !project) return <ErrorNotice message={error ?? 'Could not load this app.'} />;
  if (!project.lastRunId) return <ErrorNotice message="This app has not been built yet." />;
  if (dataError) return <ErrorNotice message={dataError} />;
  if (!run) return <LoadingScreen label="Loading your results…" />;

  const compliance = run.compliance;
  const fixed = (findings ?? []).filter((f) => f.status === 'fixed');
  const nothingToDo = (findings ?? []).filter((f) => f.status === 'accepted' || f.status === 'false-positive');
  const openFindings = (findings ?? []).filter((f) => f.status === 'open' || f.status === 'fix-attempted');
  const needsOwner = openFindings.filter((f) => f.whoCanFix === 'owner' || f.whoCanFix === 'securevibe');
  const needsDeveloper = openFindings.filter((f) => f.whoCanFix === 'developer' || f.whoCanFix === 'hosting-provider');

  const ownerAttestations = (compliance?.manualVerification ?? []).filter((m) => m.manual.whoCanDo === 'owner');
  const alreadyAttested = new Set((project.attestations ?? []).map((a) => a.requirementId));
  const reviewFiles = run.provenance ? Object.keys(run.provenance.protectedFileHashes) : [];
  const uploaded = project.origin?.kind === 'uploaded';
  // What the AI could actually change: everything except the problems that live in the hosting, where there is no
  // code to edit. Uploaded apps are never rebuilt, so nothing there is offered either.
  const aiCanTry = uploaded ? [] : openFindings.filter((f) => f.whoCanFix !== 'hosting-provider');
  const fixProps = (f: Finding) =>
    aiCanTry.some((x) => x.id === f.id)
      ? { onFix: () => askAiToFix([f.id]), selected: selectedFixes.includes(f.id), onSelect: (on: boolean) => setSelectedFixes((ids) => (on ? [...ids, f.id] : ids.filter((x) => x !== f.id))) }
      : {};
  // The code sits in the app folder either way: SecureVibe wrote it, or the owner uploaded it there.
  const codeAvailable = uploaded || instructions !== null;

  return (
    <div className="sv-stack">
      {uploaded && (
        <div className="sv-banner">
          <p style={{ marginBottom: 0 }}>
            These results are for the code you uploaded
            {project.origin?.upload ? ` on ${formatDate(project.origin.upload.uploadedAt)}` : ''}. SecureVibe scanned it but did not run it,
            so checks that need a running app are shown as not verified.{' '}
            <Link to={`/projects/${id}/upload`}>Upload a new version</Link>
          </p>
        </div>
      )}

      {uploaded && !compliance && !project.design && run.status !== 'running' && (
        <div className="sv-banner sv-banner-warn">
          <h3>Which rules apply to this app is not decided yet</h3>
          <p>
            The checks that read the code as it is have run, and what they found is below. Whether the app meets the
            security rules is not scored, because which rules apply depends on a few questions about it that have not
            been answered. Answering them adds the compliance report and widens the AI review beyond ASVS Level 1, the
            floor it reads the code against until then.
          </p>
          <Link className="sv-btn" to={`/projects/${id}/wizard/about`}>
            Answer the questions
          </Link>
        </div>
      )}

      {(project.designStale || project.buildStale) && uploaded && (
        <div className="sv-banner sv-banner-warn">
          <h3>These results are out of date</h3>
          <p>You uploaded new code or changed your answers after this check. Check the app again to see where it stands now.</p>
          <button type="button" className="sv-btn" disabled={rechecking !== null} onClick={() => void recheck(false)}>
            {rechecking === 'free' ? 'Starting…' : 'Check again (free, no AI)'}
          </button>
          {recheckError && <ErrorNotice message={recheckError} />}
        </div>
      )}

      {run.status === 'running' && (
        <div className="sv-banner">
          <h3>{run.mode === 'verify-only' ? 'A check is running for this app' : 'A build is running for this app'}</h3>
          <p>The results below are from the last finished run; the new ones replace them when it ends.</p>
          <Link className="sv-btn" to={`/projects/${id}/build?run=${encodeURIComponent(run.id)}`}>
            Watch it
          </Link>
        </div>
      )}

      {/* A build that stopped part-way can be continued, and until now the only way to that button was the
          Build page for that exact run — a URL typed by hand. The night an owner's AI credit ran out mid-build,
          that was the route they did not find, and a rebuild would have paid again for work already done. */}
      {!uploaded && run.mode === 'full' && (run.status === 'failed' || run.status === 'canceled' || run.status === 'interrupted') && (
        <div className="sv-banner sv-banner-warn">
          <h3>This build stopped part-way</h3>
          <p>
            {run.stages.find((s) => s.id === 'generate')?.status === 'passed'
              ? 'Your app was already written before the build stopped. Carrying on keeps all of that work and only runs the checks again, so it costs nothing to write.'
              : 'The parts of your app that were written before the build stopped are still there. Carrying on keeps them and writes only the rest, so you do not pay twice for the same work.'}{' '}
            A fresh build would start over and pay for everything again.
          </p>
          <button type="button" className="sv-btn" onClick={() => navigate(`/projects/${id}/build?run=${encodeURIComponent(run.id)}`)}>
            Carry on from where it stopped
          </button>
        </div>
      )}

      {project.templateOutdated && !uploaded && (
        <div className="sv-banner">
          <h3>A newer SecureVibe template is available</h3>
          <p>
            SecureVibe's starter code has improved since this app was built (fixes, checks or tests). Updating swaps in
            the newer versions of the files your app never changed, keeps every file you or Claude changed, adds any
            new settings with their defaults, and then runs the free re-check. Nothing is rewritten by AI and it costs
            nothing.
          </p>
          <button type="button" className="sv-btn" disabled={upgrading} onClick={() => void upgradeNow()}>
            {upgrading ? 'Updating…' : 'Update and check again (free)'}
          </button>
          {upgradeError && <ErrorNotice message={upgradeError} />}
        </div>
      )}

      {project.lastUpgrade && !project.templateOutdated && !uploaded && (
        <div className="sv-card" style={{ margin: '12px 0 0', background: 'var(--color-bg-subtle)' }}>
          <p style={{ margin: 0 }}>
            <strong>Updated to the latest template</strong> on {formatDate(project.lastUpgrade.at)}: {project.lastUpgrade.updated.length} file(s) updated,{' '}
            {project.lastUpgrade.added.length} added, {project.lastUpgrade.removed.length} removed
            {project.lastUpgrade.envKeysAdded.length > 0 && <>, {project.lastUpgrade.envKeysAdded.length} new setting(s) added to .env</>}.
          </p>
          {project.lastUpgrade.kept.length > 0 && (
            <p className="sv-muted" style={{ margin: '8px 0 0' }}>
              Kept with your own or Claude's changes (the template's newer version was not applied there):{' '}
              {project.lastUpgrade.kept.slice(0, 8).join(', ')}
              {project.lastUpgrade.kept.length > 8 ? ` and ${project.lastUpgrade.kept.length - 8} more` : ''}. A rebuild applies everything.
            </p>
          )}
          {project.lastUpgrade.warnings.map((w) => (
            <p key={w} className="sv-muted" style={{ margin: '8px 0 0' }}>
              {w}
            </p>
          ))}
        </div>
      )}

      {(project.designStale || project.buildStale) && !uploaded && (
        <div className="sv-banner sv-banner-warn">
          <h3>Your design has changed since this build</h3>
          <p>
            You changed some answers after this version was built. Rebuilding uses the AI service again (another
            estimate is shown first) and keeps this version ({`app-v${project.appVersion}`}) so you can go back to
            it.
          </p>
          <button type="button" className="sv-btn" onClick={() => navigate(`/projects/${id}/summary`)}>
            Review and rebuild
          </button>
        </div>
      )}

      {compliance && (
        <Card>
          <h1 style={{ marginBottom: 4 }}>
            <Mascot state={mascotForRating(compliance.overall.rating)}>
              <Badge tone={RATING_TONE[compliance.overall.rating]}>{compliance.overall.rating.replace('-', ' ')}</Badge>
            </Mascot>
          </h1>
          <h2>{compliance.overall.headline}</h2>
          {compliance.overall.ratingReason && <p className="sv-muted">{compliance.overall.ratingReason}</p>}
          <p>{compliance.overall.canIUseIt}</p>
        </Card>
      )}

      {compliance && compliance.overall.topActions.length > 0 && (
        <Card>
          <h2>Top actions</h2>
          <ol>
            {compliance.overall.topActions.map((a) => (
              <li key={a.id}>
                <strong>{a.title}</strong> — {a.detail}{' '}
                <span className="sv-faint">
                  ({a.who}
                  {a.effort ? `, ${a.effort}` : ''}
                  {a.dueBy ? `, ${a.dueBy}` : ''})
                </span>
              </li>
            ))}
          </ol>
        </Card>
      )}


      <div className="sv-row" style={{ flexWrap: 'wrap' }}>
        <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${id}/wizard/about`}>
          Edit my answers
        </Link>
        <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => void openRecheck()} aria-expanded={showRecheck}>
          Check this app again
        </button>
        {!uploaded && (
          <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => setShowRebuild((v) => !v)} aria-expanded={showRebuild}>
            Rebuild
          </button>
        )}
        <a className="sv-btn sv-btn-secondary sv-btn-sm" href="#reports">
          Go to the reports
        </a>
        <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${id}/verify`}>
          Walk through the human checks
        </Link>
        <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${id}/security`}>
          Security checks
        </Link>
      </div>

      {showRecheck && (
        <Card>
          <h2>Check this app again</h2>
          <p>
            Runs every automated check on the app exactly as it is on this computer, then rewrites the reports. Nothing in the
            app is changed and nothing is written by AI. (This is different from <strong>Rerun the reports</strong> below, which
            only rewrites the reports from results already saved and checks nothing.)
          </p>
          <div className="sv-row" style={{ flexWrap: 'wrap' }}>
            <button type="button" className="sv-btn" disabled={rechecking !== null} onClick={() => void recheck(false)}>
              {rechecking === 'free' ? 'Starting…' : 'Check again (free, no AI)'}
            </button>
            <button
              type="button"
              className="sv-btn sv-btn-secondary"
              disabled={rechecking !== null || !reviewEstimate?.aiAvailable}
              onClick={() => void recheck(true)}
            >
              {rechecking === 'ai'
                ? 'Starting…'
                : reviewEstimate?.aiAvailable
                  ? `Check again with the AI review (about $${reviewEstimate.usdLow.toFixed(2)}–$${reviewEstimate.usdHigh.toFixed(2)})`
                  : 'Check again with the AI review (needs an AI key)'}
            </button>
          </div>
          <p className="sv-muted" style={{ marginTop: 8 }}>
            The AI review reads the code and gives a second opinion on each requirement; its findings are marked "AI-assessed",
            never "verified". The free check covers everything else. Your spending limit applies to the paid one.
          </p>
          {recheckError && <ErrorNotice message={recheckError} />}
        </Card>
      )}

      {showRebuild && (
        <Card>
          <h2>Rebuild this app</h2>
          <p>
            A rebuild writes your app again from your current answers. It is the way to add features or change how the
            app works: edit your answers first, then rebuild.
          </p>
          <ul>
            <li>
              <strong>Kept:</strong> this version is saved as <code className="sv-code">app-v{project.appVersion + 1}</code> in your
              app&apos;s folder, along with all its reports.
            </li>
            <li>
              <strong>Replaced:</strong> the code in the app folder, and anything you typed into the app itself while
              trying it out (the app&apos;s own database is part of that folder).
            </li>
            <li>
              <strong>Cost:</strong> a rebuild uses the AI service again. An estimate is shown before anything starts, and
              your spending limit applies.
            </li>
          </ul>
          <div className="sv-row" style={{ flexWrap: 'wrap' }}>
            <button type="button" className="sv-btn" onClick={() => navigate(`/projects/${id}/summary`)}>
              Review the design, then rebuild
            </button>
            <Link className="sv-btn sv-btn-secondary" to={`/projects/${id}/wizard/about`}>
              Edit my answers first
            </Link>
          </div>
        </Card>
      )}

      {!uploaded && (project.appVersion ?? 0) > 0 && (
        <Card>
          <h2>What changed since the previous version</h2>
          <VersionDiff projectId={id!} />
        </Card>
      )}

      {run.planCoverage && run.planCoverage.length > 0 && (
        <Card>
          <h2>What was planned, and what was built</h2>
          <p className="sv-muted">
            Checked against the app itself — its pages, record types and tests — not against what Claude said it did.
          </p>
          <table className="sv-table">
            <thead>
              <tr>
                <th scope="col">Feature</th>
                <th scope="col">Result</th>
                <th scope="col">What was found</th>
              </tr>
            </thead>
            <tbody>
              {run.planCoverage.map((c) => (
                <tr key={c.featureId}>
                  <td>{c.title}</td>
                  <td>
                    {/* "Files in place" is amber, not green: everything the plan named exists and nothing has
                        shown it works. It reads as weaker than "Built" without anyone having to explain it. */}
                    <Badge tone={PLAN_TONE[c.status] ?? 'neutral'}>{PLAN_LABEL[c.status] ?? c.status}</Badge>
                  </td>
                  <td className="sv-muted">{c.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {run.ownerTasks && run.ownerTasks.length > 0 && (
        <Card>
          <h2>What only you can do</h2>
          <p className="sv-muted">
            Worked out from the app itself and your answers, not from what Claude said. Each one says what stays
            switched off until it is done.
          </p>
          <ul>
            {run.ownerTasks.map((t) => (
              <li key={t.id} style={{ marginBottom: 8 }}>
                <strong>{t.title}</strong>
                <br />
                <span className="sv-muted">{t.because}</span>
                <br />
                <span className="sv-faint">{t.staysOff}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {instructions && (
        <AppPreview
          projectId={id!}
          {...(project.status === 'building' ? { disabled: 'The app is being built. Preview it when the build has finished.' } : {})}
        />
      )}

      {instructions && (
        <Card>
          <h2>Run your app</h2>
          <p className="sv-faint">
            Your app is in the folder below. Open the Terminal app and run each command underneath, one at a time (copy
            it, paste it, press Return).
          </p>
          <CopyRow text={instructions.appDir} />
          <p className="sv-faint">
            To look at the code itself: copy that folder and paste it into Finder&apos;s <strong>Go → Go to Folder…</strong>{' '}
            (or open the folder in a code editor). Every finding above also has a <strong>Show me this code</strong> link
            that opens the exact file and line here, without leaving SecureVibe.
          </p>
          <ol style={{ marginTop: 16 }}>
            {instructions.steps.map((s, i) => (
              <li key={i} style={{ marginBottom: 12 }}>
                <strong>{s.title}</strong>
                {s.command && <CopyRow text={s.command} />}
                {s.expected && <p className="sv-faint">Expect: {s.expected}</p>}
                {s.troubleshooting && (
                  <details className="sv-details">
                    <summary>Not working?</summary>
                    <p style={{ marginBottom: 0 }}>{s.troubleshooting}</p>
                  </details>
                )}
              </li>
            ))}
          </ol>
          {instructions.firstLogin && (
            <div className="sv-banner">
              <h3>Your first sign-in</h3>
              <p>
                Address: <code className="sv-code">{instructions.firstLogin.url}</code>
              </p>
              <p>
                Email: <code className="sv-code">{instructions.firstLogin.email}</code>
              </p>
              <p style={{ marginBottom: 0 }}>{instructions.firstLogin.note}</p>
            </div>
          )}
          {instructions.needsAuthenticatorApp && (
            <p className="sv-muted">
              You will be asked to set up an authenticator app (like Google Authenticator) the first time you sign
              in.
            </p>
          )}
          {/* Open, not folded. This list was empty for so long that it was reasonable to hide it; now that it says
              which outside services are not connected and which features came back short, an owner who never
              opens it is the owner who most needs it. The count is in the heading so it is worth opening. */}
          {instructions.unfinished.length > 0 && (
            <details className="sv-details" open>
              <summary>
                Things you still need to finish ({instructions.unfinished.length})
              </summary>
              <ul style={{ marginBottom: 0 }}>
                {instructions.unfinished.map((u, i) => (
                  <li key={i}>{u}</li>
                ))}
              </ul>
            </details>
          )}
        </Card>
      )}

      <Card>
        <h2>What we found</h2>
        {aiCanTry.length > 0 && (
          <div className="sv-card" style={{ margin: '0 0 16px', background: 'var(--color-bg-subtle)' }}>
            <p style={{ marginTop: 0 }}>
              <strong>Have the AI fix the code</strong> — tick the problems you want it to work on, or send them all.
              This rebuilds your app with those problems on the AI's list, then runs every check again, so you can see
              what was really fixed. You approve the cost first, this version is kept, and anything the AI cannot fix
              safely stays on this list.
            </p>
            <div className="sv-row" style={{ flexWrap: 'wrap', gap: 8 }}>
              <button type="button" className="sv-btn" disabled={selectedFixes.length === 0} onClick={() => askAiToFix(selectedFixes)}>
                {selectedFixes.length === 0 ? 'Fix the ticked problems' : `Fix the ${selectedFixes.length} ticked problem(s)`}
              </button>
              <button type="button" className="sv-btn sv-btn-secondary" onClick={() => askAiToFix(aiCanTry.map((f) => f.id))}>
                Fix all {aiCanTry.length}
              </button>
              {selectedFixes.length > 0 && (
                <button type="button" className="sv-btn-link" onClick={() => setSelectedFixes([])}>
                  Clear the ticks
                </button>
              )}
            </div>
          </div>
        )}
        {fixed.length === 0 && nothingToDo.length === 0 && needsOwner.length === 0 && needsDeveloper.length === 0 && (
          <p className="sv-muted">Nothing to report yet.</p>
        )}
        {fixed.length > 0 && (
          <div className="sv-finding-group">
            <div className="sv-finding-group-header">
              <span>Fixed for you</span>
              <Badge tone="good">{fixed.length}</Badge>
            </div>
            {fixed.map((f) => (
              <FindingCard key={f.id} finding={f} projectId={id!} canShowCode={codeAvailable} {...(instructions ? { appDir: instructions.appDir } : {})} />
            ))}
          </div>
        )}
        {needsOwner.length > 0 && (
          <div className="sv-finding-group">
            <div className="sv-finding-group-header">
              <span>Needs your decision</span>
              <Badge tone="warn">{needsOwner.length}</Badge>
            </div>
            {needsOwner.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                projectId={id!}
                canShowCode={codeAvailable}
                {...(instructions ? { appDir: instructions.appDir } : {})}
                {...fixProps(f)}
                onAccept={(reason) => acceptFinding(f.id, reason)}
                onFalsePositive={(reason) => markFalsePositive(f.id, reason)}
              />
            ))}
          </div>
        )}
        {needsDeveloper.length > 0 && (
          <div className="sv-finding-group">
            <div className="sv-finding-group-header">
              <span>Usually needs a developer</span>
              <Badge tone="bad">{needsDeveloper.length}</Badge>
            </div>
            {needsDeveloper.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                projectId={id!}
                canShowCode={codeAvailable}
                {...(instructions ? { appDir: instructions.appDir } : {})}
                {...fixProps(f)}
                onAccept={(reason) => acceptFinding(f.id, reason)}
                onFalsePositive={(reason) => markFalsePositive(f.id, reason)}
              />
            ))}
          </div>
        )}
        {nothingToDo.length > 0 && (
          <div className="sv-finding-group">
            <div className="sv-finding-group-header">
              <span>Nothing to do</span>
              <Badge tone="neutral">{nothingToDo.length}</Badge>
            </div>
            {nothingToDo.map((f) => (
              <FindingCard key={f.id} finding={f} projectId={id!} canShowCode={codeAvailable} {...(instructions ? { appDir: instructions.appDir } : {})} />
            ))}
          </div>
        )}
      </Card>

      <Card>
        <h2>How your app looks</h2>
        <p className="sv-help">
          The colors only. Changing this does not rebuild your app, costs nothing, and cannot affect how your app
          protects your data: every look is tested to stay readable, in ordinary and in dark mode.
        </p>
        <div className="sv-row" style={{ flexWrap: 'wrap', gap: 8 }}>
          {THEMES.map((theme) => (
            <button
              key={theme.id}
              type="button"
              className={`sv-btn sv-btn-sm ${currentTheme === theme.id ? '' : 'sv-btn-secondary'}`}
              disabled={savingTheme}
              onClick={() => void chooseTheme(theme.id)}
            >
              {theme.label}
              {currentTheme === theme.id ? ' ✓' : ''}
            </button>
          ))}
        </div>
        {themeMessage && <p className={themeMessage.ok ? 'sv-muted' : 'sv-error-text'}>{themeMessage.text}</p>}
      </Card>

      {reportRuns.length > 0 && (
        <Card id="reports">
          <h2>Reports you can download</h2>
          {compliance && (
            <div className="sv-card" style={{ margin: '0 0 16px', background: 'var(--color-bg-subtle)' }}>
              <h3 style={{ marginTop: 0 }}>
                <Badge tone={RATING_TONE[compliance.overall.rating]}>{compliance.overall.rating.replace('-', ' ')}</Badge> Your one-page summary
              </h3>
              <p style={{ margin: '8px 0' }}>{compliance.overall.headline}</p>
              <p className="sv-muted" style={{ margin: '0 0 8px' }}>{compliance.overall.canIUseIt}</p>
              {compliance.overall.topActions.length > 0 && (
                <>
                  <p style={{ margin: '8px 0 4px' }}>
                    <strong>What to do first</strong>
                  </p>
                  <ol style={{ margin: '0 0 8px' }}>
                    {compliance.overall.topActions.slice(0, 3).map((a) => (
                      <li key={a.id}>
                        {a.title}
                        {a.effort ? <span className="sv-faint"> — about {a.effort === 'more' ? 'a few days' : `a${a.effort === 'hour' ? 'n' : ''} ${a.effort === 'minutes' ? 'few minutes' : a.effort}`}</span> : null}
                      </li>
                    ))}
                  </ol>
                </>
              )}
              <div className="sv-row" style={{ flexWrap: 'wrap', gap: 8 }}>
                <a className="sv-btn sv-btn-sm" href={artifactUrl(id!, 'overview.html', reportRunId)} target="_blank" rel="noreferrer">
                  Open the one-page summary
                </a>
                <a className="sv-btn sv-btn-secondary sv-btn-sm" href={artifactUrl(id!, 'overview.pdf', reportRunId)} download>
                  Download it as a PDF
                </a>
              </div>
              <p className="sv-faint" style={{ margin: '8px 0 0' }}>
                The one page is what to send to someone who asks "is it safe to use?"; the reports below hold every detail behind it.
              </p>
            </div>
          )}
          <div className="sv-field">
            <label className="sv-label" htmlFor="reportRun">
              Reports from
            </label>
            <select id="reportRun" className="sv-input" value={reportRunId ?? ''} onChange={(e) => setReportRunId(e.target.value)}>
              {reportRuns.map((r, i) => (
                <option key={r.id} value={r.id}>
                  {reportRunLabel(r)}
                  {i === 0 ? ' (latest)' : ''}
                </option>
              ))}
            </select>
            {reportRuns.find((r) => r.id === reportRunId)?.headline && (
              <p className="sv-help">{reportRuns.find((r) => r.id === reportRunId)?.headline}</p>
            )}
          </div>
          <div className="sv-row" style={{ flexWrap: 'wrap', marginBottom: 16 }}>
            <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" disabled={refreshing} onClick={() => void refreshReportsNow()}>
              {refreshing ? 'Rewriting the reports…' : 'Rerun the reports'}
            </button>
            <span className="sv-faint">
              Rewrites these reports from the results already saved, including any answers you have given since. Free, and
              nothing is checked again.
            </span>
          </div>
          {refreshMessage && (
            <div className={refreshMessage.ok ? 'sv-banner sv-banner-good' : 'sv-banner sv-banner-bad'} style={{ marginBottom: 16 }}>
              <p style={{ marginBottom: 0 }}>{refreshMessage.text}</p>
            </div>
          )}
          <div className="sv-banner" style={{ marginBottom: 16 }}>
            <p style={{ marginTop: 0 }}>
              <strong>Human checks.</strong> Some requirements need a person to confirm them. A step-by-step guide takes
              you (or your developer) through each one and adds the answers to these reports.
            </p>
            <Link className="sv-btn sv-btn-sm" to={`/projects/${id}/verify`}>
              Walk through the human checks
            </Link>
          </div>
          <p className="sv-help">
            <strong>PDF</strong> files are written by SecureVibe itself, so they need no browser or print window: download
            one and keep it, or send it on. A PDF shows the letters of Western European languages and leaves out emoji;
            any other character appears as a question mark, so the web version of a report is the complete one.
          </p>
          <div className="sv-row" style={{ flexWrap: 'wrap', gap: 8, marginBottom: 12 }}>
            {!uploaded && (
              <a className="sv-btn sv-btn-secondary sv-btn-sm" href={artifactUrl(id!, 'handoff.zip', reportRunId)} download>
                Download the hand-off pack (zip)
              </a>
            )}
            {!uploaded && (
              <a className="sv-btn sv-btn-secondary sv-btn-sm" href={artifactUrl(id!, 'app.zip')} download>
                Download the app only (zip)
              </a>
            )}
            <a className="sv-btn sv-btn-secondary sv-btn-sm" href={artifactUrl(id!, 'scan-data.zip', reportRunId)} download>
              Download the scan data (zip)
            </a>
          </div>
          {!uploaded && (
            <p className="sv-muted">
              The hand-off pack is what to give a developer or a hosting provider: the app (without secrets), every report,
              the human-check answers, and a HANDOFF.md that explains how to run it, how the checks came out, what is still
              open and who can fix it, and what must happen before other people use it.
            </p>
          )}
          <p className="sv-muted">
            The scan data is for a security person or their tools: the raw output of every check in this build, as data
            rather than as a written report — every finding with its exact location, what each scanner reported, which
            tools ran and which did not and why, the list of packages (CycloneDX), and the findings in SARIF, which code
            editors and build servers read directly. It holds nothing the reports do not, and no passwords or keys. If you
            just want to know whether your app is safe to use, the reports above are the ones to read.
          </p>
          <table className="sv-table">
            <thead>
              <tr>
                <th>Report</th>
                <th>Format</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(artifacts ?? []).map((a) => (
                <tr key={a.name}>
                  <td>
                    {a.name}
                    {a.description && <div className="sv-faint">{a.description}</div>}
                  </td>
                  <td>{a.format.toUpperCase()}</td>
                  <td>
                    {a.format !== 'pdf' && (
                      <>
                        <a className="sv-btn sv-btn-secondary sv-btn-sm" href={artifactUrl(id!, a.name, reportRunId)} target="_blank" rel="noreferrer">
                          Open
                        </a>{' '}
                      </>
                    )}
                    <a className="sv-btn sv-btn-secondary sv-btn-sm" href={artifactUrl(id!, a.name, reportRunId)} download>
                      Download
                    </a>{' '}
                    {a.format === 'html' && !(artifacts ?? []).some((other) => other.name === a.name.replace(/\.html$/, '.pdf')) && (
                      // Reports checked before PDFs were written with them: the server makes the PDF on request.
                      <a className="sv-btn sv-btn-secondary sv-btn-sm" href={artifactUrl(id!, a.name.replace(/\.html$/, '.pdf'), reportRunId)} download>
                        Download as PDF
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {ownerAttestations.length > 0 && (
        <Card>
          <h2>A few things only you can confirm</h2>
          <div className="sv-field">
            <label className="sv-label" htmlFor="attestName">
              Your name
            </label>
            <input
              id="attestName"
              className="sv-input"
              value={reviewerName}
              onChange={(e) => setReviewerName(e.target.value)}
              placeholder={project.profile.deployment?.owner?.name ?? 'Your name'}
            />
          </div>
          {ownerAttestations.map((m) => {
            const already = alreadyAttested.has(m.requirementId);
            return (
              <div key={m.requirementId} className="sv-field">
                <p>
                  <strong>{m.manual.question ?? m.requirementId}</strong>
                </p>
                <p className="sv-faint">{STATUS_DEFINITIONS['not-verified']}</p>
                {already ? (
                  <Badge tone="good">Answered</Badge>
                ) : (
                  <div className="sv-row">
                    <button type="button" className="sv-btn sv-btn-sm" onClick={() => void attest(m.requirementId, m.standard, 'yes')}>
                      Yes
                    </button>
                    <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => void attest(m.requirementId, m.standard, 'no')}>
                      No
                    </button>
                    <button
                      type="button"
                      className="sv-btn-link"
                      onClick={() => void attest(m.requirementId, m.standard, 'not-sure')}
                    >
                      Not sure
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      )}

      {reviewFiles.length > 0 && (
        <Card>
          <h2>Human review pack</h2>
          <p className="sv-muted">
            These are the files that matter most for security. Automated checks and AI review looked at them, but no
            person has confirmed them yet. A quick read-through by a person you trust closes this gap.
          </p>
          <ul>
            {reviewFiles.map((f) => (
              <li key={f}>
                <code className="sv-code">{f}</code>
              </li>
            ))}
          </ul>
          {project.humanCodeReview ? (
            <Badge tone="good">Reviewed by {project.humanCodeReview.reviewedBy}</Badge>
          ) : (
            <div className="sv-field">
              <label className="sv-label" htmlFor="reviewerName2">
                Reviewer name
              </label>
              <input
                id="reviewerName2"
                className="sv-input"
                value={reviewerName}
                onChange={(e) => setReviewerName(e.target.value)}
              />
              <button
                type="button"
                className="sv-btn"
                disabled={!reviewerName.trim()}
                onClick={() => void markReviewed()}
              >
                Mark as reviewed by {reviewerName.trim() || '…'}
              </button>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
