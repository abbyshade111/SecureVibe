import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import type { CheckStatus, ChecksResponse } from '@shared/api.js';
import { getChecks, getEstimate, startRun } from '../lib/api';
import { Badge, Card, ErrorNotice, LoadingScreen } from '../components/Bits';
import { formatDate } from '../lib/format';
import { useProject } from '../hooks/useProject';

const TONE = { passed: 'good', warning: 'warn', failed: 'bad', skipped: 'neutral', 'never-run': 'neutral' } as const;
const LABEL = {
  passed: 'Nothing to fix',
  warning: 'Worth a look',
  failed: 'Found problems',
  skipped: 'Not run',
  'never-run': 'Never run',
} as const;

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

function problemsLine(check: CheckStatus): string | undefined {
  if (!check.findingCounts) return undefined;
  const parts = SEVERITY_ORDER.filter((s) => check.findingCounts![s]).map((s) => `${check.findingCounts![s]} ${s}`);
  return parts.length ? `Still open from that run: ${parts.join(', ')}.` : undefined;
}

export default function SecurityPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { project, loading: projectLoading, error: projectError } = useProject(id);
  const [data, setData] = useState<ChecksResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    try {
      setData(await getChecks(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read your checks.');
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  /** Starts a run and follows it on the build page, where the progress already lives. */
  async function run(checks?: CheckStatus['id'][]) {
    if (!id) return;
    setStarting(checks ? checks.join(',') : 'all');
    setError(null);
    try {
      const { approvalCode } = await getEstimate(id);
      await startRun(id, { mode: 'verify-only', approved: true, approvalCode, withoutAi: true, ...(checks ? { checks } : {}) });
      navigate(`/projects/${id}/build`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not start that check.');
      setStarting(null);
    }
  }

  if (projectLoading || (!data && !error)) return <LoadingScreen label="Reading your checks…" />;
  if (projectError) return <ErrorNotice message={projectError} />;

  return (
    <div className="sv-stack">
      <h1>Security checks{project ? ` for ${project.name}` : ''}</h1>
      <p className="sv-help">
        These are the checks SecureVibe makes on your app. You can run them again whenever you like: they cost
        nothing, use no AI, and read the code exactly as it is on your computer right now.
      </p>
      {error && <ErrorNotice message={error} />}

      <Card>
        <h2>Run everything again</h2>
        <p className="sv-help">
          Runs every check, works out how your app stands against the security standard, and rewrites your reports.
          This is the one to use after you have changed something.
        </p>
        {data?.lastFullCheck ? (
          <p className="sv-muted">
            Your last full check was {formatDate(data.lastFullCheck.finishedAt)} and it {data.lastFullCheck.status === 'succeeded' ? 'finished' : `ended: ${data.lastFullCheck.status}`}.{' '}
            <Link to={`/projects/${id}/results`}>See the results</Link>.
          </p>
        ) : (
          <p className="sv-muted">Your app has not had a full check yet.</p>
        )}
        <button type="button" className="sv-btn" disabled={Boolean(starting) || data?.running} onClick={() => void run()}>
          {starting === 'all' ? 'Starting…' : 'Run every check again'}
        </button>
        {data?.running && <p className="sv-muted">A check is running right now. <Link to={`/projects/${id}/build`}>Watch it</Link>.</p>}
      </Card>

      <Card>
        <h2>Run one check on its own</h2>
        <p className="sv-help">
          Useful when you have just changed one thing and want a quick answer. Running one check on its own does not
          change your compliance report or your reports: those keep the results of your last full check, because a
          report written from one check would say nothing about everything that was not run.
        </p>
        <ul className="sv-stack" style={{ listStyle: 'none', padding: 0 }}>
          {data?.checks.map((check) => (
            <li key={check.id} className="sv-row-between" style={{ alignItems: 'flex-start', gap: 16, borderTop: '1px solid var(--color-border)', paddingTop: 12 }}>
              <div>
                <p>
                  <strong>{check.title}</strong> <Badge tone={TONE[check.status]}>{LABEL[check.status]}</Badge>
                </p>
                <p className="sv-help">{check.covers}</p>
                <p className="sv-muted">
                  {check.ranAt ? `Last run ${formatDate(check.ranAt)}. ${check.summary}` : check.summary}
                </p>
                {problemsLine(check) && <p className="sv-muted">{problemsLine(check)}</p>}
              </div>
              <button
                type="button"
                className="sv-btn sv-btn-secondary sv-btn-sm"
                disabled={Boolean(starting) || data.running}
                onClick={() => void run([check.id])}
              >
                {starting === check.id ? 'Starting…' : 'Run this one'}
              </button>
            </li>
          ))}
        </ul>
      </Card>

      <Card>
        <p className="sv-muted">
          Some extra scanners are only run if you have them on this computer, and the experimental AI scanner only if
          you switched it on. <Link to="/settings">Settings</Link> says which are in use, and every report lists what
          ran and what did not.
        </p>
      </Card>
    </div>
  );
}
