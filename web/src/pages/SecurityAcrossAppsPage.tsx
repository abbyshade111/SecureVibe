/**
 * Every app's security in one place, for someone whose job is the security of all of them.
 *
 * The thing this page deliberately does not do is add apps together. A note-taker on a laptop and an app going on
 * the internet with other people's records are not comparable, so a figure that mixes them is not information — it
 * is reassurance, and this project spends most of its effort removing that. So each app keeps its own numbers, with
 * where it runs and the level it is measured against printed beside them, and the only counts that span apps count
 * apps, which can honestly be compared.
 *
 * Every number opens the findings it counted, in the same card the Results page uses, with the same three actions:
 * send it to the AI to fix, accept it as it stands, or say it was never a real problem.
 */
import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import type { AppSecurityRow, SecurityAcrossAppsResponse } from '@shared/api.js';
import type { Finding } from '@shared/findings.js';
import { CHECK_FOR_SOURCE, STAGE_DESCRIPTIONS } from '@shared/pipeline.js';
import { decideFinding, getEstimate, getFindings, getSecurityAcrossApps, startRun } from '../lib/api';
import { Badge, Card, ErrorNotice, LoadingScreen } from '../components/Bits';
import { FindingCard } from '../components/FindingCard';
import { formatDate } from '../lib/format';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
type Severity = (typeof SEVERITIES)[number];

const SEVERITY_TONE: Record<Severity, 'bad' | 'warn' | 'neutral'> = {
  critical: 'bad',
  high: 'bad',
  medium: 'warn',
  low: 'neutral',
  info: 'neutral',
};

/** Where an app runs, in the words the wizard used, because it is what makes one app's numbers unlike another's. */
const EXPOSURE: Record<string, string> = {
  'local-only': 'On this computer only',
  'local-network': 'On the local network',
  'internet-later': 'Going on the internet',
  unknown: 'Not said yet',
};

const NO_COUNTS: Record<string, string> = {
  'never-built': 'Never built, so nothing has been checked.',
  'never-fully-checked': 'No check has run every step yet, so there is nothing to count. Single checks have run.',
  'checks-unreadable': 'Its check records could not be read, so nothing is counted here.',
};

const WHO_CAN_FIX: Record<string, string> = {
  securevibe: 'SecureVibe can fix',
  developer: 'Usually needs a developer',
  owner: 'For you to decide',
  'hosting-provider': 'For whoever hosts it',
};

/** The one-line verdict for an app, in the order a person wants to hear it. */
function headline(app: AppSecurityRow): { text: string; tone: 'good' | 'warn' | 'bad' | 'neutral' } {
  if (app.noCounts) return { text: 'Not checked', tone: 'neutral' };
  const open = app.open ?? {};
  if ((open.critical ?? 0) > 0) return { text: 'Something serious is open', tone: 'bad' };
  if ((open.high ?? 0) > 0) return { text: 'Something serious is open', tone: 'bad' };
  if ((open.medium ?? 0) > 0) return { text: 'Worth a look', tone: 'warn' };
  if ((open.low ?? 0) > 0 || (open.info ?? 0) > 0) return { text: 'Nothing serious open', tone: 'good' };
  return { text: 'Nothing open', tone: 'good' };
}

function AppRow({ app, onDecided }: { app: AppSecurityRow; onDecided: () => Promise<void> }) {
  const navigate = useNavigate();
  const [open, setOpen] = useState<Severity | 'all' | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rechecking, setRechecking] = useState<string | null>(null);
  const verdict = headline(app);

  /**
   * Hands the finding to a fix run on the Build page, which shows what it will cost and asks before spending. This
   * page never starts a paid run itself.
   */
  function askAiToFix(finding: Finding): void {
    navigate(`/projects/${app.projectId}/build?fix=${encodeURIComponent(finding.id)}`);
  }

  /**
   * "I have fixed it myself." There is no button here that marks a finding fixed, because saying so would not make
   * it so: the check that raised it is what decides. This runs that one check again — free, no AI, a few seconds —
   * and the finding is gone from the next reading of this page if the check no longer reports it.
   */
  async function recheck(finding: Finding): Promise<void> {
    const check = CHECK_FOR_SOURCE[finding.source];
    if (!check) return;
    setRechecking(finding.id);
    setError(null);
    try {
      const { approvalCode } = await getEstimate(app.projectId);
      const { run } = await startRun(app.projectId, { mode: 'verify-only', approved: true, approvalCode, withoutAi: true, checks: [check] });
      // Hand the Build page the run that was just started. Without it that page has nothing to follow and offers to
      // start a build instead — which reads as "your check did not happen" while it is quietly running.
      navigate(`/projects/${app.projectId}/build?run=${encodeURIComponent(run.id)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'That check could not be started.');
      setRechecking(null);
    }
  }

  /** The findings behind a number, fetched when a person asks for them rather than for every app up front. */
  const show = useCallback(
    async (severity: Severity | 'all') => {
      if (open === severity) {
        setOpen(null);
        return;
      }
      setOpen(severity);
      setError(null);
      try {
        // The same thing the numbers above counted: every check's latest word. Asking for one run would disagree
        // with them as soon as a single check had been run again.
        const res = await getFindings(app.projectId, { current: true });
        setFindings(res.findings);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Those findings could not be read.');
      }
    },
    [app.projectId, open],
  );

  const shown = (findings ?? []).filter((f) => f.status === 'open' && (open === 'all' || f.severity === open));

  return (
    <Card>
      <div className="sv-row-between" style={{ alignItems: 'flex-start', gap: 16 }}>
        <div>
          <p>
            <strong>{app.name}</strong> <Badge tone={verdict.tone}>{verdict.text}</Badge>{' '}
            {app.origin === 'uploaded' && <Badge tone="info">Your own code</Badge>}
          </p>
          {/* Printed on every row, because without it the numbers beside it cannot be read fairly. */}
          <p className="sv-muted">
            {EXPOSURE[app.exposure] ?? EXPOSURE.unknown}
            {app.targetLevel ? ` · Measured at level ${app.targetLevel}` : ''}
            {app.audience ? ` · Used by: ${app.audience}` : ''}
          </p>
        </div>
        <p className="sv-muted" style={{ textAlign: 'right', margin: 0 }}>
          <Link to={`/projects/${app.projectId}/results`}>Its reports</Link>
          {' · '}
          <Link to={`/projects/${app.projectId}/security`}>Run its checks</Link>
        </p>
      </div>

      {app.noCounts ? (
        <p className="sv-muted">{NO_COUNTS[app.noCounts] ?? NO_COUNTS['never-built']}</p>
      ) : (
        <>
          <p className="sv-muted">
            {app.lastFullCheck?.finishedAt ? `Every check last ran ${formatDate(app.lastFullCheck.finishedAt)}.` : 'Every check has run.'}{' '}
            {app.since.checksRerunSince > 0 &&
              `${app.since.checksRerunSince} check${app.since.checksRerunSince === 1 ? ' has' : 's have'} been run again since; each number below is from the last time that check ran. `}
            {app.since.answersChanged && 'Your answers have changed since, so this may no longer describe what you want built. '}
          </p>
          <p className="sv-row" style={{ gap: 8, flexWrap: 'wrap' }}>
            {SEVERITIES.filter((s) => (app.open?.[s] ?? 0) > 0).map((s) => (
              <button key={s} type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => void show(s)} aria-expanded={open === s}>
                <Badge tone={SEVERITY_TONE[s]}>{app.open![s]}</Badge> {s}
              </button>
            ))}
            {Object.values(app.open ?? {}).some((n) => n > 0) ? (
              <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => void show('all')} aria-expanded={open === 'all'}>
                Show them all
              </button>
            ) : (
              <span className="sv-muted">Nothing open from that check.</span>
            )}
          </p>
          {(app.decided.accepted > 0 || app.decided.falsePositive > 0) && (
            <p className="sv-faint">
              {/* Kept apart on purpose: "I accept this risk" and "this was never a problem" mean opposite things,
                  and filing one as the other changes what the app appears to carry. */}
              Already decided: {app.decided.accepted} accepted as they are, {app.decided.falsePositive} judged not real.
            </p>
          )}
          {Object.keys(app.whoCanFix).length > 0 && (
            <p className="sv-faint">
              Who can act:{' '}
              {Object.entries(app.whoCanFix)
                .map(([who, n]) => `${n} ${WHO_CAN_FIX[who] ?? who}`)
                .join(' · ')}
            </p>
          )}
        </>
      )}

      {open && (
        <div className="sv-stack" style={{ marginTop: 12 }}>
          {error && <ErrorNotice message={error} />}
          {!findings && !error && <p className="sv-muted">Reading them…</p>}
          {findings && shown.length === 0 && <p className="sv-muted">Nothing open at that level any more.</p>}
          {shown.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              projectId={app.projectId}
              canShowCode={app.origin === 'generated'}
              // An uploaded app is only ever read, never rebuilt, so there is nothing for the AI to write in it;
              // and a finding only its host can act on is not the AI's to try either.
              {...(app.origin === 'generated' && f.whoCanFix !== 'hosting-provider' ? { onFix: () => askAiToFix(f) } : {})}
              {...(CHECK_FOR_SOURCE[f.source]
                ? {
                    onRecheck: () => void recheck(f),
                    // The check's name is quoted because every one of them is a phrase ("Checking configuration",
                    // "Running the tests"), and "(free)" is there to separate it from the paid button beside it.
                    recheckLabel:
                      rechecking === f.id
                        ? 'Starting…'
                        : `I've fixed it — run "${STAGE_DESCRIPTIONS[CHECK_FOR_SOURCE[f.source]!].title}" again (free)`,
                  }
                : {})}
              onAccept={async (reason) => {
                await decideFinding(app.projectId, f.id, { status: 'accepted', triage: { reason } });
                setFindings((list) => (list ?? []).map((item) => (item.id === f.id ? { ...item, status: 'accepted' } : item)));
                // The counts above this list were worked out before the decision, so they now disagree with it.
                await onDecided();
              }}
              onFalsePositive={async (reason) => {
                await decideFinding(app.projectId, f.id, { status: 'false-positive', triage: { reason } });
                setFindings((list) => (list ?? []).map((item) => (item.id === f.id ? { ...item, status: 'false-positive' } : item)));
                await onDecided();
              }}
            />
          ))}
        </div>
      )}
    </Card>
  );
}

export default function SecurityAcrossAppsPage() {
  const [data, setData] = useState<SecurityAcrossAppsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await getSecurityAcrossApps());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Your apps could not be read.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (!data && !error) return <LoadingScreen label="Reading every app…" />;
  // A failed read says so and shows nothing else: a page of zeros would be a statement about the apps.
  if (!data)
    return (
      <div className="sv-stack">
        <h1>Security across your apps</h1>
        <ErrorNotice message={error ?? 'Your apps could not be read.'} />
        <p className="sv-muted">Nothing is listed because that read failed, not because there is nothing to list.</p>
      </div>
    );

  return (
    <div className="sv-stack">
      <h1>Security across your apps</h1>
      <p className="sv-help">
        Every app you have, worst first. Nothing on this page adds one app to another: an app that runs only on this
        computer and an app going on the internet are not the same risk, so their numbers are kept apart and shown
        next to where each one runs. Every number opens the findings it counted.
      </p>
      {error && <ErrorNotice message={error} />}

      <Card>
        <p>
          <strong>{data.apps.length}</strong> app{data.apps.length === 1 ? '' : 's'}.{' '}
          <strong>{data.appsNeedingAttention}</strong> need{data.appsNeedingAttention === 1 ? 's' : ''} attention —
          something serious is open, or nothing has been checked.
          {data.appsNeverFullyChecked > 0 && (
            <>
              {' '}
              <strong>{data.appsNeverFullyChecked}</strong> {data.appsNeverFullyChecked === 1 ? 'has' : 'have'} never
              had every check run, which is unknown rather than clean.
            </>
          )}
        </p>
        <p className="sv-faint">
          These count apps, not findings. A count of findings across apps would add a note-taker's spelling mistakes
          to a clinic's open door and call the sum a number.
        </p>
      </Card>

      {data.apps.length === 0 ? (
        <Card>
          <p className="sv-muted">
            You have no apps yet. <Link to="/">Describe one</Link> and SecureVibe will build and check it.
          </p>
        </Card>
      ) : (
        data.apps.map((app) => <AppRow key={app.projectId} app={app} onDecided={load} />)
      )}
    </div>
  );
}
