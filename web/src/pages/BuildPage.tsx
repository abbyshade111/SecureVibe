import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Mascot, mascotForRunStatus } from '../components/Mascot';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import {
  STAGE_DESCRIPTIONS,
  STAGE_IDS,
  type CostEstimate,
  type PipelineRun,
  type StageId,
} from '@shared/pipeline.js';
import { useProject } from '../hooks/useProject';
import { useStatus } from '../hooks/useStatus';
import { approvePlan, cancelRun, createPlan, getEstimate, getRun, runEventsUrl, startRun } from '../lib/api';
import { Card, ErrorNotice, LoadingScreen, ProgressBar } from '../components/Bits';
import { usd, usdRange, minutesRange } from '../lib/format';

const STAGE_STATUS_ICON: Record<string, string> = {
  pending: '○',
  running: '◐',
  passed: '✓',
  failed: '✕',
  skipped: '–',
  warning: '▲',
};

const FAILURE_ACTION_LABEL: Record<string, string> = {
  retry: 'Try again',
  'ask-claude-to-fix': 'Ask Claude to fix this and try again',
  'save-for-developer': 'Save details for a developer',
  'change-answers': 'Go back and change my answers',
  'add-api-key': 'Add an API key',
};

/** How many recent lines to keep. Enough to see movement, few enough not to become a wall of text. */
const ACTIVITY_LINES = 8;

/**
 * The agent's own words, in the owner's. "Claude is using write_file…" is accurate and means nothing to someone
 * who is not a programmer; what this line has to carry is that something is happening, and roughly what.
 */
const TOOL_WORDS: Record<string, string> = {
  write_file: 'writing a file',
  delete_file: 'removing a file',
  read_file: 'reading a file',
  list_files: 'looking through the files',
  run_checks: 'running the checks',
  run_tests: 'running the tests',
  search: 'searching the code',
};

export function plainActivity(message: string): string {
  const tool = /^Claude is using ([a-z_]+)/.exec(message);
  if (tool) return `Claude is ${TOOL_WORDS[tool[1] ?? ''] ?? `using ${(tool[1] ?? '').replace(/_/g, ' ')}`}…`;
  // Check messages arrive tagged with their stage; the tag is for the log, not for a person.
  return message.replace(/^\[[a-z-]+\]\s*/, '');
}

export function BuildPage() {
  const { id } = useParams<{ id: string }>();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { project, loading, error, reload } = useProject(id);
  const { status } = useStatus();

  const [estimate, setEstimate] = useState<CostEstimate | null>(null);
  const [approvalCode, setApprovalCode] = useState<string | null>(null);
  const [cap, setCap] = useState<number>(10);
  const [approved, setApproved] = useState(false);
  const [run, setRun] = useState<PipelineRun | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  const [estimateError, setEstimateError] = useState<string | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [activity, setActivity] = useState<{ at: string; text: string }[]>([]);
  const [liveSpend, setLiveSpend] = useState<{ usd: number; calls: number } | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const fixFindingIds = useMemo(() => {
    const raw = params.get('fix');
    return raw ? raw.split(',').filter(Boolean) : undefined;
  }, [params]);
  // A run someone else already started and sent us here to watch — the free template update does this. Without it
  // this page offers to start a build instead, which is the opposite of what the button they pressed said.
  const watchRunId = params.get('run') ?? undefined;
  const [attaching, setAttaching] = useState(Boolean(watchRunId));

  const loadEstimate = useCallback(
    (keepCap = false) => {
      if (!id) return;
      setEstimateError(null);
      getEstimate(id)
        .then((r) => {
          setEstimate(r.estimate);
          setApprovalCode(r.approvalCode);
          if (!keepCap) setCap(r.estimate.spendingCapUsd);
        })
        /**
         * Shown, not swallowed. The start button needs the approval code this call returns, so when the call
         * fails the button can never enable — and a `.catch(() => undefined)` here meant it sat there greyed out
         * with nothing on the page saying why. On 20 September 2026 an owner ticked the box, could not press the
         * button, and there was no way for them to find out that the estimate had been refused.
         */
        .catch((e: unknown) => setEstimateError(e instanceof Error ? e.message : 'The estimate could not be worked out.'));
    },
    [id],
  );

  useEffect(() => loadEstimate(), [loadEstimate]);

  useEffect(() => {
    if (status) setCap((c) => c || status.settings.defaultSpendingCapUsd);
  }, [status]);

  // Attach to the run we were sent to watch. Unlike the reconnect below, this one takes the run whatever its
  // status: a check that finished in the seconds it took to get here should show its result, not a build form.
  useEffect(() => {
    if (!watchRunId || run) return;
    let cancelled = false;
    getRun(watchRunId)
      .then((r) => {
        if (!cancelled) setRun(r);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setAttaching(false);
      });
    return () => {
      cancelled = true;
    };
  }, [watchRunId, run]);

  // Reconnect to an already-running run on load/reload.
  useEffect(() => {
    if (!project?.lastRunId || run || watchRunId) return;
    getRun(project.lastRunId)
      .then((r) => {
        if (r.status === 'running') setRun(r);
      })
      .catch(() => undefined);
  }, [project, run, watchRunId]);

  useEffect(() => {
    if (!run || run.status !== 'running') {
      esRef.current?.close();
      esRef.current = null;
      return;
    }
    const es = new EventSource(runEventsUrl(run.id));
    esRef.current = es;
    es.addEventListener('progress', (ev) => {
      // Every message the run sends already arrives here; the page used to throw the contents away and re-read
      // the run. The stage list only moves every few minutes, so a build that was working looked identical to one
      // that had stopped — and the owner watching a slow, paid build had nothing to tell them it was still going.
      try {
        const payload = JSON.parse((ev as MessageEvent<string>).data) as {
          type?: string;
          message?: string;
          at?: string;
          data?: { estimatedCostUsd?: number; calls?: number };
        };
        // The run knows what it has spent from its first AI call, but the file this page re-reads is only written
        // when a stage ends — and writing the app is one long stage. So an owner watching a paid build saw no
        // figure at all until it finished, and had nothing to tell her it was working rather than stuck.
        if (payload.type === 'spend' && typeof payload.data?.estimatedCostUsd === 'number') {
          setLiveSpend({ usd: payload.data.estimatedCostUsd, calls: payload.data.calls ?? 0 });
        }
        if (payload.type === 'log' && payload.message) {
          const line = { at: payload.at ?? new Date().toISOString(), text: plainActivity(payload.message) };
          setActivity((lines) => [...lines, line].slice(-ACTIVITY_LINES));
        }
      } catch {
        // A message this page cannot read is not a reason to stop following the run.
      }
      getRun(run.id)
        .then(setRun)
        .catch(() => undefined);
    });
    es.onerror = () => {
      // The browser retries automatically; also poll once as a fallback.
      getRun(run.id)
        .then(setRun)
        .catch(() => undefined);
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run?.id, run?.status]);

  useEffect(() => {
    if (!run || run.status !== 'running') return;
    const started = new Date(run.startedAt).getTime();
    const timer = setInterval(() => setElapsedMs(Date.now() - started), 1000);
    return () => clearInterval(timer);
  }, [run]);

  useEffect(() => {
    if (run?.status === 'succeeded') {
      void reload();
      navigate(`/projects/${id}/results`);
    }
  }, [run, id, navigate, reload]);

  // Browser notification when the build ends while this tab is in the background (the desktop notification from
  // Settings covers the case where the browser is closed). Permission is asked only when the owner clicks the button.
  const lastStatus = useRef<PipelineRun['status'] | null>(null);
  const [browserNotify, setBrowserNotify] = useState<NotificationPermission | 'unsupported'>(() => (typeof Notification === 'undefined' ? 'unsupported' : Notification.permission));
  useEffect(() => {
    const previous = lastStatus.current;
    lastStatus.current = run?.status ?? null;
    if (!run || previous !== 'running' || run.status === 'running') return;
    if (browserNotify !== 'granted' || !document.hidden) return;
    const what = run.mode === 'verify-only' ? 'check' : 'build';
    const body = run.status === 'succeeded' ? `The ${what} finished. Open SecureVibe to see the results.` : run.status === 'failed' ? `The ${what} did not finish.` : `The ${what} was ${run.status}.`;
    try {
      new Notification(`SecureVibe: ${project?.name ?? 'your app'}`, { body });
    } catch {
      // notifications blocked by the browser: nothing to do
    }
  }, [run, browserNotify, project?.name]);
  async function askBrowserNotify() {
    if (typeof Notification === 'undefined') return;
    try {
      setBrowserNotify(await Notification.requestPermission());
    } catch {
      setBrowserNotify('denied');
    }
  }

  const uploaded = project?.origin?.kind === 'uploaded';
  // Writing with AI needs an approved plan for the current design; builds without AI and check-only runs do not.
  // A fix run rebuilds the app with the chosen problems on the agent's list, so the server asks for an approved
  // plan exactly as it does for any other AI build. Hiding the plan here left an owner refused with "approve the
  // build plan first" on a page that offered no way to approve one.
  const needsPlan = !uploaded && status?.llm.previewMode !== true;
  const plan = project?.buildPlan && project.buildPlan.designHash === project.design?.profileHash ? project.buildPlan : undefined;
  const [planning, setPlanning] = useState(false);
  const [planError, setPlanError] = useState<string | null>(null);
  const [editingPlan, setEditingPlan] = useState(false);
  const [chosenFeatures, setChosenFeatures] = useState<Record<string, boolean>>({});

  async function preparePlan() {
    if (!id) return;
    setPlanning(true);
    setPlanError(null);
    try {
      await createPlan(id);
      setChosenFeatures({});
      setEditingPlan(false);
      await reload();
    } catch (e) {
      setPlanError(e instanceof Error ? e.message : 'Could not prepare the plan.');
    } finally {
      setPlanning(false);
    }
  }

  async function approveThePlan() {
    if (!id || !plan) return;
    setPlanning(true);
    setPlanError(null);
    try {
      await approvePlan(id, plan.features.filter((f) => chosenFeatures[f.id] ?? f.wanted).map((f) => f.id));
      setEditingPlan(false);
      await reload();
      // The approval code was issued for the page as it was; the estimate is fetched again with the plan in place.
      loadEstimate(true);
    } catch (e) {
      setPlanError(e instanceof Error ? e.message : 'Could not save the plan.');
    } finally {
      setPlanning(false);
    }
  }

  /**
   * 'ai': the normal build. 'free-build': the starter app from the answers, without AI (free). 'recheck': every
   * automated check on the app as it is, without AI and without changing it (free).
   */
  async function begin(kind: 'ai' | 'free-build' | 'recheck' = 'ai', resumeFromRunId?: string) {
    if (!id || !approvalCode) return;
    setStartError(null);
    try {
      const withoutAi = kind !== 'ai';
      const res = await startRun(id, {
        mode: uploaded || kind === 'recheck' ? 'verify-only' : 'full',
        approved: true,
        approvalCode,
        spendingCapUsd: cap,
        ...(withoutAi ? { withoutAi: true } : {}),
        ...(fixFindingIds && !uploaded && !withoutAi ? { fixFindingIds } : {}),
        ...(resumeFromRunId ? { resumeFromRunId } : {}),
      });
      setRun(res.run);
    } catch (e) {
      setStartError(e instanceof Error ? e.message : 'Could not start the build.');
      // An approval works once: show the (possibly updated) estimate again and ask for a fresh approval.
      setApproved(false);
      setApprovalCode(null);
      loadEstimate(true);
    }
  }

  async function cancel() {
    if (!run) return;
    try {
      await cancelRun(run.id);
    } catch {
      /* the SSE stream will reflect the final state */
    }
  }

  if (loading) return <LoadingScreen label="Loading…" />;
  if (error || !project) return <ErrorNotice message={error ?? 'Could not load this app.'} />;

  if (attaching) return <LoadingScreen label="Opening the check…" />;

  if (!run) {
    return (
      <div className="sv-stack">
        <h1>{uploaded ? 'Check my app' : fixFindingIds ? `Ask the AI to fix ${fixFindingIds.length} problem(s)` : 'Build my app'}</h1>
        {needsPlan && (
          <Card>
            <h2>The plan</h2>
            {!plan && (
              <>
                <p>
                  Before Claude writes anything, it lists the features it intends to build — what each lets you do,
                  which pages and records it adds, and the tests that will prove it. You approve the list, or leave
                  features out, and after the build each feature is checked against what actually exists.
                </p>
                <p className="sv-muted">Preparing the plan costs a few cents and takes under a minute.</p>
                {planError && <ErrorNotice message={planError} />}
                <button type="button" className="sv-btn" disabled={planning} onClick={() => void preparePlan()}>
                  {planning ? 'Preparing the plan…' : 'Prepare the plan'}
                </button>
              </>
            )}
            {plan && (
              <>
                <p>{plan.summary}</p>
                {plan.approvedAt && !editingPlan ? (
                  <>
                    <ul>
                      {plan.features.map((f) => (
                        <li key={f.id} className={f.wanted ? '' : 'sv-faint'}>
                          <strong>{f.title}</strong>
                          {f.wanted ? '' : ' — left out'}
                        </li>
                      ))}
                    </ul>
                    <p className="sv-faint">
                      Approved {new Date(plan.approvedAt).toLocaleString()}
                      {plan.estimatedSteps ? ` · about ${plan.estimatedSteps} working steps` : ''}.
                    </p>
                    <div className="sv-row" style={{ flexWrap: 'wrap' }}>
                      <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => setEditingPlan(true)}>
                        Change what to build
                      </button>
                      <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" disabled={planning} onClick={() => void preparePlan()}>
                        {planning ? 'Preparing…' : 'Ask for a new plan'}
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <p className="sv-muted">Untick anything you do not want built.</p>
                    {plan.features.map((f) => (
                      <label key={f.id} className="sv-checkbox-row" style={{ alignItems: 'flex-start', marginBottom: 12 }}>
                        <input
                          type="checkbox"
                          checked={chosenFeatures[f.id] ?? f.wanted}
                          onChange={(e) => setChosenFeatures((prev) => ({ ...prev, [f.id]: e.target.checked }))}
                        />
                        <span>
                          <strong>{f.title}</strong>
                          <br />
                          <span className="sv-muted">{f.whatItDoes}</span>
                          {(f.pages.length > 0 || f.records.length > 0) && (
                            <>
                              <br />
                              <span className="sv-faint">
                                {f.pages.length > 0 ? `Pages: ${f.pages.join(', ')}` : ''}
                                {f.pages.length > 0 && f.records.length > 0 ? ' · ' : ''}
                                {f.records.length > 0 ? `Records: ${f.records.join(', ')}` : ''}
                              </span>
                            </>
                          )}
                        </span>
                      </label>
                    ))}
                    {planError && <ErrorNotice message={planError} />}
                    <div className="sv-row" style={{ flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        className="sv-btn"
                        disabled={planning || !plan.features.some((f) => chosenFeatures[f.id] ?? f.wanted)}
                        onClick={() => void approveThePlan()}
                      >
                        {planning ? 'Saving…' : 'Approve this plan'}
                      </button>
                      <button type="button" className="sv-btn sv-btn-secondary" disabled={planning} onClick={() => void preparePlan()}>
                        Ask for a new plan
                      </button>
                    </div>
                  </>
                )}
              </>
            )}
          </Card>
        )}
        <Card>
          <h2>What this will do</h2>
          <p>
            {uploaded
              ? 'We scan the code you uploaded for security problems, leaked secrets and vulnerable packages, and check it against the OWASP security standards. Your app is not run. This usually takes a few minutes.'
              : 'We write the app, install it, test it and check it against the OWASP security standards. This usually takes a few minutes.'}
          </p>
          {estimate && (
            <p>
              <strong>Estimated time:</strong> {minutesRange(estimate.minutesLow, estimate.minutesHigh)}.{' '}
              <strong>Estimated AI cost:</strong> {usdRange(estimate.usdLow, estimate.usdHigh)}.
            </p>
          )}
          {estimate?.note && <p className="sv-faint">{estimate.note}</p>}

          <div className="sv-field">
            <label className="sv-label" htmlFor="cap">
              Stop if the AI cost passes (US dollars)
            </label>
            <p className="sv-help">SecureVibe stops the build before going over this amount.</p>
            <input
              id="cap"
              type="number"
              min={1}
              max={500}
              className="sv-input"
              value={cap}
              onChange={(e) => setCap(Number(e.target.value))}
            />
          </div>

          <label className="sv-checkbox-row">
            <input type="checkbox" checked={approved} onChange={(e) => setApproved(e.target.checked)} />
            <span>I understand this will write code and run checks on my computer.</span>
          </label>

          {startError && <ErrorNotice message={startError} />}
          {status?.llm.previewMode && (
            <div className="sv-banner sv-banner-warn">
              <p style={{ marginBottom: 0 }}>
                {status.llm.switchedOff ? 'AI is switched off.' : 'No AI is configured.'} Your app still gets pages for every
                record you described, built from the hardened starting application, but Claude will not write your other
                features or review the code, and nothing is spent. The reports say exactly which parts were skipped.
                {status.llm.switchedOff === 'setting' && (
                  <>
                    {' '}
                    <Link to="/settings">Turn AI on in Settings</Link> to have Claude write the rest.
                  </>
                )}
              </p>
            </div>
          )}

          {estimateError && (
            <ErrorNotice
              title="This app cannot be checked yet"
              message={`${estimateError} Until that is sorted out, the button below stays switched off.`}
            />
          )}
          {needsPlan && !plan?.approvedAt && <p className="sv-faint">Approve the plan above first.</p>}
          <button type="button" className="sv-btn" disabled={!approved || !approvalCode || (needsPlan && !plan?.approvedAt)} onClick={() => void begin()}>
            {uploaded ? 'Check my app' : fixFindingIds ? 'Fix and rebuild' : 'Build my app'}
          </button>
          {!uploaded && project.status === 'built' && (
            <p className="sv-muted" style={{ marginTop: 12 }}>
              Or run every automated check on the app as it is, without AI and without changing it (free, a few minutes):{' '}
              <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" disabled={!approved || !approvalCode} onClick={() => void begin('recheck')}>
                Check again without AI (free)
              </button>
            </p>
          )}
          {!uploaded && !fixFindingIds && status?.llm.previewMode !== true && (
            <p className="sv-muted" style={{ marginTop: 12 }}>
              Or build the starter app without AI: pages for every record you described, every security check and every
              report, but no features written by Claude. Free, about four minutes, and a good way to see the whole process
              first:{' '}
              <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" disabled={!approved || !approvalCode} onClick={() => void begin('free-build')}>
                Build without AI (free)
              </button>
            </p>
          )}
        </Card>
      </div>
    );
  }

  const stagesById = new Map(run.stages.map((s) => [s.id, s]));
  const seconds = Math.floor(elapsedMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const secondsPart = seconds % 60;
  const stagesDone = run.stages.filter((s) => s.status !== 'pending' && s.status !== 'running').length;
  const percent = (stagesDone / STAGE_IDS.length) * 100;

  return (
    <div className="sv-stack">
      {/* A check-only run writes nothing, so calling it a build misdescribes what is happening and what it costs. */}
      <h1>
        {mascotForRunStatus(run.status) ? (
          <Mascot state={mascotForRunStatus(run.status)!} size={48}>
            {uploaded || run.mode === 'verify-only' ? 'Checking your app' : 'Building your app'}
          </Mascot>
        ) : uploaded || run.mode === 'verify-only' ? (
          'Checking your app'
        ) : (
          'Building your app'
        )}
      </h1>
      {run.status === 'running' && (
        <Card>
          <ProgressBar percent={percent} label="Build progress" />
          <div className="sv-row-between" style={{ marginTop: 12 }}>
            <span className="sv-muted">
              Elapsed: {minutes}m {secondsPart}s
            </span>
            {/*
                Shown from the first second, starting at nothing, rather than appearing once money has been spent.
                Gated on having a figure, this was invisible for the first two minutes of every run — which is
                exactly the stretch where somebody watches a progress bar and wonders what it is costing them.
                Zero is a true and reassuring answer to that, and a number that starts at zero and moves is
                easier to trust than one that materialises part-way through. On a run with AI switched off it
                simply stays at zero for the whole run, which demonstrates the point better than a label saying
                so would.

                The live figure when the stream has sent one, the saved figure otherwise — a reconnected page has
                no stream history, and a figure from the file is better than none.
            */}
            <span className="sv-muted">
              AI spend so far: {usd(liveSpend ? liveSpend.usd : (run.llmUsage?.estimatedCostUsd ?? 0))}
              {liveSpend && liveSpend.calls > 0 ? ` (${liveSpend.calls} call${liveSpend.calls === 1 ? '' : 's'})` : ''}
            </span>
            {browserNotify === 'default' && (
              <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => void askBrowserNotify()}>
                Notify me in the browser when it is done
              </button>
            )}{' '}
            <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => void cancel()}>
              Cancel
            </button>
          </div>
          {activity.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <p className="sv-label" style={{ marginBottom: 4 }}>What it is doing right now</p>
              <ul className="sv-stack" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                {activity.map((line, i) => (
                  <li key={`${line.at}-${i}`} className={i === activity.length - 1 ? 'sv-muted' : 'sv-faint'} style={{ margin: 0 }}>
                    {line.text}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      )}

      <Card>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {STAGE_IDS.map((sid: StageId) => {
            const desc = STAGE_DESCRIPTIONS[sid];
            const s = stagesById.get(sid);
            const statusKey = s?.status ?? 'pending';
            return (
              <li key={sid} style={{ padding: '10px 0', borderBottom: '1px solid var(--color-border)' }}>
                <div className="sv-row">
                  <span aria-hidden="true">{STAGE_STATUS_ICON[statusKey]}</span>
                  <strong>{desc.title}</strong>
                  <span className="sv-faint">{statusKey}</span>
                </div>
                {statusKey === 'running' && <p className="sv-muted" style={{ margin: '4px 0 0 26px' }}>{desc.running}</p>}
                {statusKey === 'pending' && <p className="sv-faint" style={{ margin: '4px 0 0 26px' }}>{desc.why}</p>}
                {s?.summary && statusKey !== 'pending' && statusKey !== 'running' && (
                  <p className="sv-muted" style={{ margin: '4px 0 0 26px' }}>
                    {s.summary}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      </Card>

      {run.status === 'failed' && run.failure && (
        <div className="sv-banner sv-banner-bad">
          <h3>Something went wrong</h3>
          <p>{run.failure.message}</p>
          {run.failure.detail && (
            <details className="sv-details">
              <summary>Technical detail</summary>
              <pre className="sv-pre">{run.failure.detail}</pre>
            </details>
          )}
          <div className="sv-row">
            {run.failure.options.map((opt) => (
              <button
                key={opt}
                type="button"
                className="sv-btn sv-btn-secondary"
                onClick={() => {
                  if (opt === 'change-answers') navigate(`/projects/${id}/wizard/about`);
                  else if (opt === 'add-api-key') navigate('/');
                  else if (opt === 'save-for-developer') navigate(`/projects/${id}/results`);
                  else {
                    setRun(null);
                  }
                }}
              >
                {FAILURE_ACTION_LABEL[opt] ?? opt}
              </button>
            ))}
          </div>
        </div>
      )}


      {run.status !== 'running' && run.status !== 'succeeded' && !uploaded && run.mode === 'full' && (
        <Card>
          <h3 style={{ marginTop: 0 }}>Carry on from where it stopped</h3>
          <p className="sv-help">
            {run.stages.find((s) => s.id === 'generate')?.status === 'passed'
              ? 'Your app was already written before this build stopped. Carrying on keeps all of that work and only runs the checks again, so it costs nothing to write.'
              : 'The parts of your app that were written before this build stopped are still there. Carrying on keeps them and writes only the rest, so you do not pay twice for the same work.'}
          </p>
          <button type="button" className="sv-btn" disabled={!approvalCode} onClick={() => void begin('ai', run.id)}>
            Carry on from where it stopped
          </button>
        </Card>
      )}

      {run.status === 'cancelled' && (
        <div className="sv-banner sv-banner-warn">
          <p style={{ marginBottom: 0 }}>The build was cancelled.</p>
        </div>
      )}

      {run.status === 'interrupted' && (
        <div className="sv-banner sv-banner-warn">
          <p>SecureVibe stopped unexpectedly before this build finished (for example, it was closed or restarted).</p>
          <button type="button" className="sv-btn sv-btn-secondary" onClick={() => setRun(null)}>
            Try again
          </button>
        </div>
      )}
    </div>
  );
}
