import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useProject } from '../hooks/useProject';
import { useStatus } from '../hooks/useStatus';
import { useWizardCopy } from '../hooks/useWizardCopy';
import { acknowledgeEscalation, deriveDesign, requestPeerReview, skipPeerReview, submitPeerReviewDecisions } from '../lib/api';
import { Card, ErrorNotice, LoadingScreen, ProgressBar } from '../components/Bits';
import { checkSavedAnswers } from '@shared/answer-check.js';
import type { PeerReviewSuggestion } from '@shared/design.js';

type DesignPhase = 'design' | 'second-opinion';

/** What happens between submitting the answers and seeing the design, step by step. */
function DesignProgress({ phase, aiOff, skipping, onSkip }: { phase: DesignPhase; aiOff: boolean; skipping: boolean; onSkip: () => void }) {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    setSeconds(0);
    const timer = window.setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => window.clearInterval(timer);
  }, [phase]);

  const steps: { title: string; detail: string; state: 'done' | 'running' | 'waiting' }[] = [
    {
      title: 'Security requirements, architecture and checklist',
      detail: 'Turning your answers into security requirements, a trust-zone diagram, the 36-point design checklist, a risk rating and, if needed, a threat model.',
      state: phase === 'design' ? 'running' : 'done',
    },
    {
      title: 'Second opinion from Claude',
      detail: aiOff
        ? 'Skipped: AI is off, so no second opinion is requested (the report says so).'
        : 'Claude reads the design as an independent reviewer and suggests extra protections or questions for you. This usually takes one to two minutes and uses a little AI credit.',
      state: phase === 'second-opinion' ? 'running' : 'waiting',
    },
    {
      title: 'Your review',
      detail: 'You see the design in plain language, answer any questions and approve it before anything is built.',
      state: 'waiting',
    },
  ];
  const done = steps.filter((s) => s.state === 'done').length;
  const icon = { done: '✓', running: '◐', waiting: '○' } as const;
  const word = { done: 'done', running: 'working', waiting: 'next' } as const;

  return (
    <div className="sv-stack">
      <h1>Putting your design together</h1>
      <Card>
        <ProgressBar percent={((done + 0.5) / steps.length) * 100} label="Design progress" />
        <p className="sv-muted" style={{ marginTop: 12 }} aria-live="polite">
          Step {done + 1} of {steps.length}: {steps[done]!.title} · {seconds}s
        </p>
        <ol className="sv-steps" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {steps.map((s) => (
            <li key={s.title} style={{ padding: '10px 0', borderBottom: '1px solid var(--color-border)' }} aria-current={s.state === 'running' ? 'step' : undefined}>
              <div className="sv-row">
                <span aria-hidden="true">{icon[s.state]}</span>
                <strong>{s.title}</strong>
                <span className="sv-faint">{word[s.state]}</span>
              </div>
              <p className={s.state === 'running' ? 'sv-muted' : 'sv-faint'} style={{ margin: '4px 0 0 26px' }}>
                {s.detail}
              </p>
            </li>
          ))}
        </ol>
        {phase === 'second-opinion' && !aiOff && (
          <div style={{ marginTop: 16 }}>
            <button type="button" className="sv-btn sv-btn-secondary" disabled={skipping} onClick={onSkip}>
              {skipping ? 'Skipping…' : 'Skip the second opinion'}
            </button>
            <p className="sv-help" style={{ marginTop: 8 }}>
              Stops Claude now, so no more credit is used. Your design is kept as it is, and the reports will say
              this step was skipped at your request.
            </p>
          </div>
        )}
      </Card>
    </div>
  );
}

export function SummaryPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { project, loading, error, reload } = useProject(id);
  const { copy } = useWizardCopy();
  const { status } = useStatus();
  const [working, setWorking] = useState(false);
  const [workError, setWorkError] = useState<string | null>(null);
  const [decisions, setDecisions] = useState<Record<string, { accepted: boolean; optionIndex?: number }>>({});
  const [acknowledging, setAcknowledging] = useState(false);
  const [skipping, setSkipping] = useState(false);

  const needsDesign = !!project && (!project.design || project.designStale);
  const needsPeerReview = !!project?.design && !project.design.peerReview;

  useEffect(() => {
    if (!id || !needsDesign) return;
    setWorking(true);
    setWorkError(null);
    deriveDesign(id)
      .then(() => reload())
      .catch((e) => setWorkError(e instanceof Error ? e.message : 'Could not put together your design.'))
      .finally(() => setWorking(false));
  }, [id, needsDesign, reload]);

  useEffect(() => {
    if (!id || needsDesign || !needsPeerReview) return;
    setWorking(true);
    setWorkError(null);
    requestPeerReview(id)
      .then(() => reload())
      .catch((e) => setWorkError(e instanceof Error ? e.message : 'Could not get a second opinion.'))
      .finally(() => setWorking(false));
  }, [id, needsDesign, needsPeerReview, reload]);

  async function skipSecondOpinion() {
    if (!id) return;
    setSkipping(true);
    try {
      await skipPeerReview(id);
      await reload();
    } catch (e) {
      setWorkError(e instanceof Error ? e.message : 'Could not skip the second opinion.');
    } finally {
      setSkipping(false);
    }
  }

  if (loading) return <LoadingScreen label="Loading…" />;
  if (error || !project) return <ErrorNotice message={error ?? 'Could not load this app.'} />;
  if (workError && (needsDesign || needsPeerReview)) return <ErrorNotice message={workError} />;
  if (needsDesign || needsPeerReview) {
    return (
      <DesignProgress
        phase={needsDesign ? 'design' : 'second-opinion'}
        aiOff={!!status?.llm.previewMode}
        skipping={skipping}
        onSkip={() => void skipSecondOpinion()}
      />
    );
  }
  const design = project.design;
  if (!design) return <ErrorNotice message="No design has been put together for this app yet." />;

  const summaryCopy = copy?.summary;
  const clarifications = (design.peerReview?.suggestions ?? []).filter(
    (s) => s.kind === 'clarification' && s.accepted === null,
  );
  const controlsAdded = (design.peerReview?.suggestions ?? []).filter((s) => s.kind === 'control' && s.applied);
  const advice = (design.peerReview?.suggestions ?? []).filter((s) => s.kind === 'advice');

  async function submitClarifications() {
    if (!id) return;
    const list = clarifications
      .filter((c) => decisions[c.id])
      .map((c) => ({
        suggestionId: c.id,
        accepted: true,
        optionIndex: decisions[c.id]?.optionIndex,
      }));
    if (list.length === 0) return;
    setWorking(true);
    setWorkError(null);
    try {
      await submitPeerReviewDecisions(id, { decisions: list });
      await reload();
      setDecisions({});
    } catch (e) {
      setWorkError(e instanceof Error ? e.message : 'Could not save your answers.');
    } finally {
      setWorking(false);
    }
  }

  async function skipClarifications() {
    if (!id) return;
    setWorking(true);
    setWorkError(null);
    try {
      await submitPeerReviewDecisions(id, {
        decisions: clarifications.map((c) => ({
          suggestionId: c.id,
          accepted: false,
          dismissReason: 'Skipped by the owner without answering; nothing was changed in the design.',
        })),
      });
      await reload();
      setDecisions({});
    } catch (e) {
      setWorkError(e instanceof Error ? e.message : 'Could not skip the questions.');
    } finally {
      setWorking(false);
    }
  }

  async function acknowledge() {
    if (!id) return;
    setAcknowledging(true);
    try {
      await acknowledgeEscalation(id);
      await reload();
    } catch (e) {
      setWorkError(e instanceof Error ? e.message : 'Could not save your acknowledgement.');
    } finally {
      setAcknowledging(false);
    }
  }

  const needsAcknowledgement = design.riskTriage.escalate && !project.escalationAcknowledgedAt;
  const showAdminMfaNotice = project.profile.users?.adminMfa || design.riskTriage.level === 'high';
  // A question with no answers to pick (older designs) can only be skipped, so it does not hold up the build.
  const blockingClarifications = clarifications.filter((c) => (c.options ?? []).length > 0);
  const canBuild = blockingClarifications.length === 0 && !needsAcknowledgement;
  const uploaded = project.origin?.kind === 'uploaded';

  return (
    <div className="sv-stack">
      <h1>{uploaded ? "Here's what we'll check" : (summaryCopy?.headline ?? "Here's what we'll build")}</h1>
      {uploaded && (
        <div className="sv-banner">
          <p style={{ marginBottom: 0 }}>
            Your answers describe the app you uploaded. SecureVibe uses them to decide which security requirements apply,
            then checks your code for them. It does not change your code.{' '}
            <Link to={`/projects/${id}/upload`}>Upload a new version</Link>
          </p>
        </div>
      )}

      {project.profile.meta?.mode === 'quick' && summaryCopy?.quickModeNote && (
        <div className="sv-banner">
          <p style={{ marginBottom: 0 }}>{summaryCopy.quickModeNote}</p>
        </div>
      )}

      {workError && <ErrorNotice message={workError} />}

      <Card>
        <h2>{summaryCopy?.sections.app ?? 'Your app'}</h2>
        <p>{design.plainLanguageSummary}</p>
        {checkSavedAnswers(project.profile).length > 0 && (
          <div className="sv-banner sv-banner-warn">
            <p>
              <strong>Some of your saved answers look damaged.</strong> A rebuild makes the app from these answers, so
              it is worth a look first.
            </p>
            <ul style={{ marginBottom: 8 }}>
              {checkSavedAnswers(project.profile).map((p) => (
                <li key={`${p.entityIndex}-${p.kind}`}>{p.message}</li>
              ))}
            </ul>
            <p style={{ marginBottom: 0 }}>
              <Link to={`/projects/${id}/wizard/features`}>Look at the records</Link>
            </p>
          </div>
        )}
        {(project.profile.app?.entities ?? []).length === 0 && (
          <div className="sv-banner sv-banner-warn">
            <p style={{ marginBottom: 0 }}>
              <strong>You have not described any records yet.</strong> Records are the things your app keeps, for example
              &ldquo;condition&rdquo;, &ldquo;treatment&rdquo; or &ldquo;note&rdquo;. Without them the app is built with
              sign-in and security but no pages of its own, so it looks empty. Add them under{' '}
              <strong>What your app keeps</strong> in your answers.
            </p>
          </div>
        )}
        <p className="sv-faint" style={{ marginBottom: 0 }}>
          <Link to={`/projects/${id}/wizard/about`}>Change my answers</Link> ·{' '}
          <Link to={`/projects/${id}/refine`}>Ask Claude about my answers</Link>
        </p>
      </Card>

      <Card>
        <h2>{uploaded ? 'What SecureVibe will look for' : (summaryCopy?.sections.protections ?? 'How it will be protected')}</h2>
        <ul>
          {design.consequences.map((c, i) => (
            <li key={i}>{c}</li>
          ))}
        </ul>
      </Card>

      {design.assumptionsMade.length > 0 && (
        <Card>
          <h2>{summaryCopy?.sections.assumptions ?? 'Things we assumed (please check)'}</h2>
          <ul>
            {design.assumptionsMade.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
          {id && (
            <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${id}/wizard/about`}>
              Review my answers
            </Link>
          )}
        </Card>
      )}

      <Card>
        <h2>{summaryCopy?.sections.extraCare ?? 'Extra care level'}</h2>
        <p>
          <strong>{summaryCopy?.extraCareLevels[design.riskTriage.level]?.label ?? design.riskTriage.extraCareLabel}</strong>
        </p>
        <p>{summaryCopy?.extraCareLevels[design.riskTriage.level]?.text ?? design.riskTriage.plainLanguage}</p>
        {needsAcknowledgement && (
          <div className="sv-banner sv-banner-warn">
            <p>{design.riskTriage.escalationHandling}</p>
            <button type="button" className="sv-btn" disabled={acknowledging} onClick={() => void acknowledge()}>
              {acknowledging ? 'Saving…' : 'I understand, continue'}
            </button>
          </div>
        )}
      </Card>

      {showAdminMfaNotice && copy && (
        <div className="sv-banner">
          <h3>{summaryCopy?.sections.authenticator ?? 'You will need an authenticator app'}</h3>
          <p style={{ marginBottom: 0 }}>{copy.common.authenticatorNotice}</p>
        </div>
      )}

      {design.peerReview?.performedBy === 'skipped' && (
        <div className="sv-banner">
          <p style={{ marginBottom: 0 }}>
            <strong>No second opinion.</strong> {design.peerReview.summary} The reports will show that this design
            step (Secure by Design step 5) was not performed.
          </p>
        </div>
      )}

      {controlsAdded.length > 0 && (
        <Card>
          <h2>We also added…</h2>
          <ul>
            {controlsAdded.map((s: PeerReviewSuggestion) => (
              <li key={s.id}>
                <strong>{s.title}.</strong> {s.detail}
              </li>
            ))}
          </ul>
          <p className="sv-faint">
            This is an independent second look from Claude, using a different prompt from the one that designed your
            app.
          </p>
        </Card>
      )}

      {clarifications.length > 0 && (
        <Card>
          <h2>A couple of questions from our second opinion</h2>
          {clarifications.map((c) => (
            <div key={c.id} className="sv-field">
              <label className="sv-label">{c.title}</label>
              <p className="sv-help">{c.question ?? c.detail}</p>
              {(c.options ?? []).length === 0 && (
                <p className="sv-faint">
                  Nothing to choose here: SecureVibe cannot change this for you. Worth thinking about before you share
                  the app. It does not stop you building.
                </p>
              )}
              <div className="sv-option-list">
                {(c.options ?? []).map((opt, i) => (
                  <label className="sv-option" key={i} data-checked={decisions[c.id]?.optionIndex === i}>
                    <input
                      type="radio"
                      name={c.id}
                      checked={decisions[c.id]?.optionIndex === i}
                      onChange={() => setDecisions((prev) => ({ ...prev, [c.id]: { accepted: true, optionIndex: i } }))}
                    />
                    <span className="sv-option-body">
                      <span className="sv-option-label">{opt.label}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          ))}
          <div className="sv-row" style={{ flexWrap: 'wrap' }}>
            <button
              type="button"
              className="sv-btn"
              onClick={() => void submitClarifications()}
              disabled={working || !clarifications.some((c) => decisions[c.id])}
            >
              Save answers
            </button>
            <button type="button" className="sv-btn sv-btn-secondary" onClick={() => void skipClarifications()} disabled={working}>
              {working ? 'Saving…' : 'Skip these questions'}
            </button>
          </div>
          <p className="sv-faint" style={{ marginBottom: 0 }}>
            Skipping keeps your design exactly as it is. The reports will list these questions as skipped.
          </p>
        </Card>
      )}

      {advice.length > 0 && (
        <details className="sv-details">
          <summary>Advice for your reports</summary>
          <ul style={{ marginBottom: 0 }}>
            {advice.map((a) => (
              <li key={a.id}>
                <strong>{a.title}.</strong> {a.detail}
              </li>
            ))}
          </ul>
        </details>
      )}

      <details className="sv-details">
        <summary>{summaryCopy?.sections.technical ?? 'Technical details for your developer'}</summary>
        <h3>Diagram</h3>
        <pre className="sv-pre">{design.architecture.mermaid}</pre>
        <h3>Security patterns applied</h3>
        <ul>
          {design.patterns.map((p) => (
            <li key={p.id}>
              <strong>{p.name}.</strong> {p.why}
            </li>
          ))}
        </ul>
        <h3>Secure by Design checklist</h3>
        <table className="sv-table">
          <thead>
            <tr>
              <th>Id</th>
              <th>Statement</th>
              <th>Status</th>
              <th>Justification</th>
            </tr>
          </thead>
          <tbody>
            {design.checklist.map((c) => (
              <tr key={c.id}>
                <td>{c.id}</td>
                <td>{c.statement}</td>
                <td>{c.status.toUpperCase()}</td>
                <td>{c.justification}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {design.threatModel && (
          <>
            <h3>Threat model</h3>
            <p>{design.threatModel.summary}</p>
            <table className="sv-table">
              <thead>
                <tr>
                  <th>Id</th>
                  <th>Threat</th>
                  <th>Risk</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {design.threatModel.threats.map((t) => (
                  <tr key={t.id}>
                    <td>{t.id}</td>
                    <td>{t.description}</td>
                    <td>{t.riskLevel}</td>
                    <td>{t.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </details>

      <Card>
        <div className="sv-row-between">
          <div>
            <p className="sv-muted" style={{ marginBottom: 0 }}>
              {uploaded
                ? status?.llm.previewMode
                  ? 'This check runs without AI, so it costs nothing: SecureVibe scans your code and writes the reports. Nothing starts until you approve it.'
                  : 'Checking uses the AI service for the code review, which costs money (an estimate is shown first). Nothing starts until you approve it.'
                : status?.llm.previewMode
                ? 'This build runs without AI, so it costs nothing: you get the hardened starter app with your records, the security checks and the reports. Nothing is built until you approve it.'
                : (summaryCopy?.approveNote ??
                  'Building uses the AI service and costs money (an estimate is shown first). Nothing is built until you approve it.')}
            </p>
          </div>
          <button
            type="button"
            className="sv-btn"
            disabled={!canBuild}
            onClick={() => navigate(`/projects/${id}/build`)}
          >
            {uploaded ? 'Check my app' : (summaryCopy?.approveButton ?? 'Build my app')}
          </button>
        </div>
        {!canBuild && (
          <p className="sv-faint">
            {blockingClarifications.length > 0
              ? 'Answer or skip the second-opinion questions above first.'
              : 'Please read and acknowledge the extra care notice above first.'}
          </p>
        )}
      </Card>
    </div>
  );
}
