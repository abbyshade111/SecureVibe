import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import type { VerificationItem, VerificationResponse } from '@shared/api.js';
import { createAttestation, getEstimate, getVerification, refreshReports, startRun, submitHumanReview } from '../lib/api';
import { Badge, Card, ErrorNotice, LoadingScreen, ProgressBar } from '../components/Bits';
import { formatDate } from '../lib/format';
import { useScrollToTop } from '../hooks/useScrollToTop';

type StepId = 'start' | 'code' | 'owner' | 'developer' | 'specialist' | 'finish';
type Answer = 'yes' | 'no' | 'not-sure';

const STEPS: { id: StepId; label: string }[] = [
  { id: 'start', label: 'Start' },
  { id: 'code', label: 'Code review' },
  { id: 'owner', label: 'Your questions' },
  { id: 'developer', label: 'Developer checks' },
  { id: 'specialist', label: 'Specialist checks' },
  { id: 'finish', label: 'Finish' },
];

const NAME_KEY = 'securevibe.reviewerName';
const EFFORT_ORDER = { minutes: 0, hour: 1, day: 2 } as const;
const EFFORT_LABEL = { minutes: 'A few minutes', hour: 'About an hour', day: 'About a day' } as const;
const WHO_LABEL = {
  owner: 'You',
  developer: 'A developer',
  'security-professional': 'A security professional',
  'hosting-provider': 'Your hosting provider',
} as const;

function readName(): string {
  try {
    return localStorage.getItem(NAME_KEY) ?? '';
  } catch {
    return '';
  }
}

function keyOf(item: VerificationItem): string {
  return `${item.standard}:${item.requirementId}`;
}

function inStep(item: VerificationItem, step: StepId): boolean {
  if (step === 'owner') return item.whoCanDo === 'owner';
  if (step === 'developer') return item.whoCanDo === 'developer';
  if (step === 'specialist') return item.whoCanDo === 'security-professional' || item.whoCanDo === 'hosting-provider';
  return false;
}

function answerLabel(result: Answer, owner: boolean): string {
  if (result === 'yes') return owner ? 'Yes' : 'Checked: it holds';
  if (result === 'no') return owner ? 'No' : 'Checked: it does not hold';
  return 'Not sure';
}

/** One requirement at a time, unanswered ones first, quickest first. */
function ItemStep({
  items,
  owner,
  name,
  onAnswer,
  onDone,
}: {
  items: VerificationItem[];
  owner: boolean;
  name: string;
  onAnswer: (item: VerificationItem, result: Answer, note: string, link: string) => Promise<void>;
  onDone: () => void;
}) {
  const [showAnswered, setShowAnswered] = useState(false);
  const queue = useMemo(
    () =>
      [...items]
        .filter((i) => showAnswered || !i.answer)
        .sort((a, b) => Number(!!a.answer) - Number(!!b.answer) || EFFORT_ORDER[a.estimatedEffort] - EFFORT_ORDER[b.estimatedEffort]),
    // The order is fixed when the step opens or the filter changes, so answering does not reshuffle the list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [showAnswered, items.length],
  );
  const [index, setIndex] = useState(0);
  const [note, setNote] = useState('');
  const [link, setLink] = useState('');
  // Each check starts at the top of the page, not where the last one ended.
  useScrollToTop(index);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const current = queue[index] ? (items.find((i) => keyOf(i) === keyOf(queue[index]!)) ?? queue[index]) : undefined;
  useEffect(() => {
    setNote(current?.answer?.note ?? '');
    setLink(current?.answer?.evidenceLink ?? '');
    setError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current && keyOf(current)]);

  const answered = items.filter((i) => i.answer).length;
  if (items.length === 0) {
    return (
      <>
        <p>Nothing in this part for this build.</p>
        <button type="button" className="sv-btn" onClick={onDone}>
          Continue
        </button>
      </>
    );
  }
  if (!current) {
    return (
      <>
        <div className="sv-banner sv-banner-good">
          <p style={{ marginBottom: 0 }}>
            <strong>All {items.length} answered.</strong> You can go through them again to change an answer.
          </p>
        </div>
        <div className="sv-row" style={{ flexWrap: 'wrap' }}>
          <button type="button" className="sv-btn" onClick={onDone}>
            Continue
          </button>
          <button
            type="button"
            className="sv-btn sv-btn-secondary"
            onClick={() => {
              setShowAnswered(true);
              setIndex(0);
            }}
          >
            Review my answers
          </button>
        </div>
      </>
    );
  }

  const linkOk = link.trim() === '' || /^https?:\/\/\S+$/i.test(link.trim());
  async function answer(result: Answer) {
    if (!current) return;
    if (!name.trim()) {
      setError('Enter your name on the Start step first, so the answer says who gave it.');
      return;
    }
    if (!linkOk) {
      setError('The evidence link must start with http:// or https://.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onAnswer(current, result, note.trim(), link.trim());
      setIndex((i) => i + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the answer.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <ProgressBar percent={Math.round((answered / items.length) * 100)} label={`${answered} of ${items.length} answered`} />
      <p className="sv-faint" style={{ marginTop: 8 }}>
        Item {index + 1} of {queue.length}
        {showAnswered ? '' : ' still to answer'} · {EFFORT_LABEL[current.estimatedEffort]} · Who: {WHO_LABEL[current.whoCanDo]}
      </p>

      <div className="sv-card" style={{ margin: '12px 0' }}>
        <p className="sv-faint" style={{ marginTop: 0 }}>
          {current.requirementId} · {current.chapterName}
          {current.answer && (
            <>
              {' '}
              · <Badge tone="info">Answered: {answerLabel(current.answer.result, owner)}</Badge>
            </>
          )}
        </p>
        <h3 style={{ marginTop: 0 }}>{owner ? (current.question ?? current.plainLanguage ?? current.description) : current.plainLanguage ?? current.description}</h3>
        {(owner ? current.question !== undefined : current.plainLanguage !== undefined) && (
          <details className="sv-details">
            <summary>The exact requirement</summary>
            <p style={{ marginBottom: 0 }}>{current.description}</p>
          </details>
        )}
        {current.steps.length > 0 && (
          <>
            <h4>How to check</h4>
            <ol>
              {current.steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
          </>
        )}
        {current.whatCountsAsEvidence && (
          <p>
            <strong>What to write down:</strong> {current.whatCountsAsEvidence}
          </p>
        )}

        <div className="sv-field">
          <label className="sv-label" htmlFor="verifyNote">
            {owner ? 'Note (optional)' : 'What you found (optional, but it makes the answer much stronger)'}
          </label>
          <textarea id="verifyNote" className="sv-textarea" rows={3} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
        {!owner && (
          <div className="sv-field">
            <label className="sv-label" htmlFor="verifyLink">
              Link to evidence (optional)
            </label>
            <input
              id="verifyLink"
              className="sv-input"
              inputMode="url"
              placeholder="https://…"
              value={link}
              onChange={(e) => setLink(e.target.value)}
              aria-invalid={!linkOk}
            />
          </div>
        )}
        {error && <ErrorNotice message={error} />}
        <div className="sv-row" style={{ flexWrap: 'wrap' }}>
          <button type="button" className="sv-btn" disabled={busy} onClick={() => void answer('yes')}>
            {answerLabel('yes', owner)}
          </button>
          <button type="button" className="sv-btn sv-btn-secondary" disabled={busy} onClick={() => void answer('no')}>
            {answerLabel('no', owner)}
          </button>
          <button type="button" className="sv-btn sv-btn-secondary" disabled={busy} onClick={() => void answer('not-sure')}>
            Not sure
          </button>
        </div>
      </div>

      <div className="sv-row-between" style={{ flexWrap: 'wrap', gap: 8 }}>
        <div className="sv-row">
          <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" disabled={index === 0} onClick={() => setIndex((i) => i - 1)}>
            Back
          </button>
          <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => setIndex((i) => i + 1)}>
            Skip for now
          </button>
        </div>
        <div className="sv-row">
          <button
            type="button"
            className="sv-btn-link"
            onClick={() => {
              setShowAnswered((v) => !v);
              setIndex(0);
            }}
          >
            {showAnswered ? 'Only show unanswered' : 'Include answered ones'}
          </button>
          <button type="button" className="sv-btn-link" onClick={onDone}>
            Leave the rest for later
          </button>
        </div>
      </div>
    </>
  );
}

function CodeReviewStep({
  data,
  name,
  onRecorded,
  onDone,
}: {
  data: VerificationResponse;
  name: string;
  onRecorded: (note: string) => Promise<void>;
  onDone: () => void;
}) {
  const review = data.codeReview;
  const [readAll, setReadAll] = useState(false);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [again, setAgain] = useState(false);

  const byFolder = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const f of review.files) {
      const dir = f.includes('/') ? f.slice(0, f.lastIndexOf('/')) : '.';
      m.set(dir, [...(m.get(dir) ?? []), f.slice(f.lastIndexOf('/') + 1)]);
    }
    return [...m.entries()];
  }, [review.files]);

  if (review.files.length === 0) {
    return (
      <>
        <p>There are no security-critical files to review for this build.</p>
        <button type="button" className="sv-btn" onClick={onDone}>
          Continue
        </button>
      </>
    );
  }

  if (review.current && review.reviewedBy && !again) {
    return (
      <>
        <div className="sv-banner sv-banner-good">
          <p style={{ marginBottom: 0 }}>
            <strong>Done.</strong> {review.reviewedBy} reviewed these {review.files.length} files on {formatDate(review.reviewedAt)}, and
            they have not changed since.
          </p>
        </div>
        <div className="sv-row" style={{ flexWrap: 'wrap' }}>
          <button type="button" className="sv-btn" onClick={onDone}>
            Continue
          </button>
          <button type="button" className="sv-btn sv-btn-secondary" onClick={() => setAgain(true)}>
            Record a new review
          </button>
        </div>
      </>
    );
  }

  async function record() {
    setBusy(true);
    setError(null);
    try {
      await onRecorded(note.trim());
      setAgain(false);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not record the review.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {review.reviewedBy && !review.current && (
        <div className="sv-banner sv-banner-warn">
          <p style={{ marginBottom: 0 }}>
            {review.reviewedBy} reviewed these files on {formatDate(review.reviewedAt)}, but they have changed since, so that
            review no longer counts.
          </p>
        </div>
      )}
      <p>
        These {review.files.length} files hold the app&apos;s security: sign-in, permissions, input checks, secrets and
        logging. Automated checks and the AI looked at them, but the standards also want a <strong>person</strong> to read
        them. Ideally that is someone who can read code; if that is not you, send them this list.
      </p>
      {review.root && (
        <p className="sv-faint">
          The files are in <code className="sv-code">{review.root}</code>.
        </p>
      )}
      <details className="sv-details" open>
        <summary>What to look for</summary>
        <ul style={{ marginBottom: 0 }}>
          <li>No passwords, keys or tokens written in the code.</li>
          <li>Every page and action that changes data checks who is signed in and what they may do.</li>
          <li>Anything a user types is checked before it is used, and shown back safely.</li>
          <li>Errors do not show internal details, and security events are logged.</li>
          <li>Nothing looks unfinished, switched off “for testing”, or surprising.</li>
        </ul>
      </details>
      <details className="sv-details">
        <summary>The {review.files.length} files</summary>
        {byFolder.map(([dir, files]) => (
          <div key={dir}>
            <p style={{ marginBottom: 4 }}>
              <code className="sv-code">{dir}/</code>
            </p>
            <ul style={{ marginTop: 0 }}>
              {files.map((f) => (
                <li key={f}>
                  <code className="sv-code">{f}</code>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </details>
      <label className="sv-checkbox-row">
        <input type="checkbox" checked={readAll} onChange={(e) => setReadAll(e.target.checked)} />
        <span>I read all {review.files.length} files looking for the points above.</span>
      </label>
      <div className="sv-field">
        <label className="sv-label" htmlFor="reviewNote">
          What did you find? (optional)
        </label>
        <textarea id="reviewNote" className="sv-textarea" rows={3} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      {error && <ErrorNotice message={error} />}
      <div className="sv-row" style={{ flexWrap: 'wrap' }}>
        <button type="button" className="sv-btn" disabled={!readAll || !name.trim() || busy} onClick={() => void record()}>
          {busy ? 'Saving…' : `Record the review by ${name.trim() || '…'}`}
        </button>
        <button type="button" className="sv-btn sv-btn-secondary" onClick={onDone}>
          Skip for now
        </button>
      </div>
      {!name.trim() && <p className="sv-faint">Enter your name on the Start step first.</p>}
    </>
  );
}

export function VerifyPage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const step = (STEPS.some((s) => s.id === params.get('step')) ? params.get('step') : 'start') as StepId;
  const [data, setData] = useState<VerificationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState(readName);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [refreshed, setRefreshed] = useState(false);
  const [rechecking, setRechecking] = useState(false);
  const navigate = useNavigate();

  const load = useCallback(async () => {
    if (!id) return;
    try {
      setData(await getVerification(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the checks.');
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  function go(next: StepId) {
    setParams({ step: next });
    window.scrollTo({ top: 0 });
  }

  function saveName(value: string) {
    setName(value);
    try {
      localStorage.setItem(NAME_KEY, value);
    } catch {
      // Remembering the name is only a convenience.
    }
  }

  if (error) return <ErrorNotice message={error} />;
  if (!data || !id) return <LoadingScreen label="Loading the checks…" />;

  const effectiveName = name.trim() || data.suggestedName;
  const group = (s: StepId) => data.items.filter((i) => inStep(i, s));
  const counts = (s: StepId) => ({ total: group(s).length, answered: group(s).filter((i) => i.answer).length });
  const stepState = (s: StepId): 'done' | 'current' | 'todo' => {
    if (s === step) return 'current';
    if (s === 'code') return data.codeReview.current || data.codeReview.files.length === 0 ? 'done' : 'todo';
    if (s === 'owner' || s === 'developer' || s === 'specialist') return counts(s).total > 0 && counts(s).answered === counts(s).total ? 'done' : 'todo';
    return 'todo';
  };
  const nextOf = (s: StepId): StepId => STEPS[STEPS.findIndex((x) => x.id === s) + 1]?.id ?? 'finish';

  async function answer(item: VerificationItem, result: Answer, note: string, link: string) {
    const saved = await createAttestation(id!, {
      requirementId: item.requirementId,
      standard: item.standard,
      result,
      note,
      attestedBy: effectiveName,
      ...(link ? { evidenceLink: link } : {}),
    });
    setData((d) =>
      d
        ? { ...d, reportsOutdated: true, items: d.items.map((i) => (keyOf(i) === keyOf(item) ? { ...i, answer: saved } : i)) }
        : d,
    );
  }

  async function recordReview(note: string) {
    await submitHumanReview(id!, { reviewedBy: effectiveName, ...(note ? { note } : {}) });
    await load();
  }

  async function recheck() {
    setRechecking(true);
    setRefreshError(null);
    try {
      const { approvalCode } = await getEstimate(id!);
      await startRun(id!, { mode: 'verify-only', approved: true, approvalCode, withoutAi: true });
      navigate(`/projects/${id}/build`);
    } catch (e) {
      setRefreshError(e instanceof Error ? e.message : 'Could not start the check.');
      setRechecking(false);
    }
  }

  async function refresh() {
    setRefreshing(true);
    setRefreshError(null);
    try {
      await refreshReports(id!);
      setRefreshed(true);
      await load();
    } catch (e) {
      setRefreshError(e instanceof Error ? e.message : 'Could not update the reports.');
    } finally {
      setRefreshing(false);
    }
  }

  const title = STEPS.find((s) => s.id === step)!.label;

  return (
    <div className="sv-stack">
      <div>
        <Link to={`/projects/${id}/results#reports`}>← Back to the reports</Link>
      </div>
      <h1 style={{ marginBottom: 0 }}>Human checks</h1>
      <nav aria-label="Steps">
        <ol className="sv-steps">
          {STEPS.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                className="sv-step-pill"
                style={{ background: 'none', cursor: 'pointer', font: 'inherit' }}
                data-state={stepState(s.id)}
                aria-current={s.id === step ? 'step' : undefined}
                onClick={() => go(s.id)}
              >
                {stepState(s.id) === 'done' && s.id !== step ? '✓ ' : ''}
                {s.label}
                {(s.id === 'owner' || s.id === 'developer' || s.id === 'specialist') && counts(s.id).total > 0 && (
                  <span className="sv-faint">
                    {' '}
                    {counts(s.id).answered}/{counts(s.id).total}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ol>
      </nav>

      <Card>
        <h2>{title}</h2>

        {step === 'start' && (
          <>
            <p>
              Some security requirements cannot be checked by a machine. This walks you through each one for the build
              of {formatDate(data.builtAt)}, one at a time. Every answer is saved as you give it, so you can stop and come
              back later.
            </p>
            <ul>
              <li>
                <strong>Code review:</strong>{' '}
                {data.codeReview.files.length === 0
                  ? 'nothing to review.'
                  : data.codeReview.current
                    ? `done by ${data.codeReview.reviewedBy}.`
                    : `a person reads ${data.codeReview.files.length} security-critical files.`}
              </li>
              <li>
                <strong>Your questions:</strong> {counts('owner').total} yes-or-no questions about how the app is used (
                {counts('owner').answered} answered).
              </li>
              <li>
                <strong>Developer checks:</strong> {counts('developer').total} checks for someone who can read code (
                {counts('developer').answered} answered).
              </li>
              <li>
                <strong>Specialist checks:</strong> {counts('specialist').total} for a security professional or your hosting
                provider ({counts('specialist').answered} answered).
              </li>
            </ul>
            <p className="sv-muted">
              Answer only what you can honestly confirm. &ldquo;Not sure&rdquo; is a fine answer: the reports then say the
              requirement still needs checking. Each answer is recorded with your name and the date.
            </p>
            <div className="sv-field">
              <label className="sv-label" htmlFor="verifierName">
                Your name
              </label>
              <input
                id="verifierName"
                className="sv-input"
                maxLength={80}
                autoComplete="name"
                value={name}
                placeholder={data.suggestedName || 'Your name'}
                onChange={(e) => saveName(e.target.value)}
              />
            </div>
            <button type="button" className="sv-btn" disabled={!effectiveName} onClick={() => go('code')}>
              Start
            </button>
          </>
        )}

        {step === 'code' && <CodeReviewStep data={data} name={effectiveName} onRecorded={recordReview} onDone={() => go(nextOf('code'))} />}

        {(step === 'owner' || step === 'developer' || step === 'specialist') && (
          <>
            <p className="sv-muted">
              {step === 'owner' && 'Questions about how the app is run and used. Only you can answer these.'}
              {step === 'developer' &&
                'Checks for someone who can read the code. If that is not you, share this page with them, or leave these for later.'}
              {step === 'specialist' &&
                'Checks that need a security professional or your hosting provider. Record their answer here once you have it.'}
            </p>
            <ItemStep key={step} items={group(step)} owner={step === 'owner'} name={effectiveName} onAnswer={answer} onDone={() => go(nextOf(step))} />
          </>
        )}

        {step === 'finish' && (
          <>
            <table className="sv-table">
              <caption className="sv-visually-hidden">Progress</caption>
              <thead>
                <tr>
                  <th scope="col">Part</th>
                  <th scope="col">Progress</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Code review</td>
                  <td>
                    {data.codeReview.files.length === 0
                      ? 'Nothing to review'
                      : data.codeReview.current
                        ? `Done by ${data.codeReview.reviewedBy}`
                        : 'Not done yet'}
                  </td>
                </tr>
                {(['owner', 'developer', 'specialist'] as const).map((s) => (
                  <tr key={s}>
                    <td>{STEPS.find((x) => x.id === s)!.label}</td>
                    <td>
                      {counts(s).answered} of {counts(s).total} answered
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <h3>Put your answers in the reports</h3>
            {data.canRefresh ? (
              <>
                <p className="sv-muted">
                  This rewrites the reports for this build with your answers. Nothing is scanned or sent to the AI again, so
                  it is free and takes a few seconds.
                </p>
                {refreshed && !data.reportsOutdated ? (
                  <div className="sv-banner sv-banner-good">
                    <p style={{ marginBottom: 0 }}>
                      <strong>The reports are up to date.</strong> <Link to={`/projects/${id}/results#reports`}>Open the reports</Link>
                    </p>
                  </div>
                ) : (
                  <button type="button" className="sv-btn" disabled={refreshing} onClick={() => void refresh()}>
                    {refreshing ? 'Updating the reports…' : data.reportsOutdated ? 'Update the reports' : 'Update the reports again'}
                  </button>
                )}
              </>
            ) : data.selfAssessment ? (
              <p className="sv-muted">
                These reports were made before SecureVibe could add answers to existing reports. Your answers are saved.
                SecureVibe checks itself from the command line, so the next self-assessment run includes them; after that
                run, this button works for every later answer. The free way (no AI) is{' '}
                <code className="sv-code">npm run self-assess -- --no-ai</code> in the SecureVibe folder.
              </p>
            ) : (
              <>
                <p className="sv-muted">
                  These reports were made before SecureVibe could add answers to existing reports. Your answers are saved.
                  Check the app again to include them: this runs every automated check on the app as it is, without AI (so
                  it is free) and without changing the app. It usually takes a few minutes. After that, updating the
                  reports with new answers takes seconds.
                </p>
                <button type="button" className="sv-btn" disabled={rechecking} onClick={() => void recheck()}>
                  {rechecking ? 'Starting…' : 'Check again without AI (free)'}
                </button>
              </>
            )}
            {refreshError && <ErrorNotice message={refreshError} />}
          </>
        )}
      </Card>
    </div>
  );
}
