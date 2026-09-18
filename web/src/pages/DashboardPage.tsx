import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import type { MetricsResponse } from '@shared/api.js';
import { getMetrics } from '../lib/api';
import { Badge, Card, ErrorNotice, LoadingScreen } from '../components/Bits';
import { formatDate, humanize, usd } from '../lib/format';

type Period = 7 | 30 | 90;

function Tile({ value, label, tone }: { value: string; label: string; tone?: 'bad' }) {
  return (
    <div className="sv-tile">
      <div className="sv-tile-value" style={tone === 'bad' ? { color: 'var(--color-danger)' } : undefined}>
        {value}
      </div>
      <div className="sv-tile-label">{label}</div>
    </div>
  );
}

/** Horizontal bars; the numbers are always written out, so the bars are decoration only. */
function Bars({ rows, value, format, tone }: { rows: { key: string; label: string }[]; value: (key: string) => number; format: (n: number) => string; tone?: 'bad' }) {
  const max = Math.max(...rows.map((r) => value(r.key)), 0);
  if (rows.length === 0) return <p className="sv-muted">Nothing in this period.</p>;
  return (
    <ul className="sv-bars">
      {rows.map((r) => (
        <li key={r.key} className="sv-bar-row">
          <span>{r.label}</span>
          <strong>{format(value(r.key))}</strong>
          <span className="sv-bar-track" aria-hidden="true">
            <span
              className={tone === 'bad' ? 'sv-bar-fill sv-bar-fill-bad' : 'sv-bar-fill'}
              style={{ display: 'block', width: `${max > 0 ? Math.max(2, (value(r.key) / max) * 100) : 0}%` }}
            />
          </span>
        </li>
      ))}
    </ul>
  );
}

/** One column per day. The total is in the heading; each column has its value as a tooltip. */
function DailyColumns({ days, value, describe }: { days: string[]; value: (i: number) => number; describe: (i: number) => string }) {
  const max = Math.max(...days.map((_, i) => value(i)), 0);
  return (
    <div>
      <div className="sv-columns" aria-hidden="true">
        {days.map((d, i) => {
          const v = value(i);
          return (
            <span
              key={d}
              className={v > 0 ? 'sv-column' : 'sv-column sv-column-empty'}
              style={{ height: `${max > 0 && v > 0 ? Math.max(3, (v / max) * 100) : 0}%` }}
              title={`${d}: ${describe(i)}`}
            />
          );
        })}
      </div>
      <div className="sv-columns-axis" aria-hidden="true">
        <span>{days[0]}</span>
        <span>{days[days.length - 1]}</span>
      </div>
    </div>
  );
}

const STATUS_TONE: Record<string, 'good' | 'warn' | 'bad' | 'neutral'> = {
  succeeded: 'good',
  running: 'warn',
  failed: 'bad',
  cancelled: 'neutral',
  interrupted: 'neutral',
};

export function DashboardPage() {
  const [period, setPeriod] = useState<Period>(30);
  const [data, setData] = useState<MetricsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setError(null);
    getMetrics(period)
      .then((d) => live && setData(d))
      .catch((e) => live && setError(e instanceof Error ? e.message : 'Could not load the dashboard.'));
    return () => {
      live = false;
    };
  }, [period]);

  if (error) return <ErrorNotice message={error} />;
  if (!data) return <LoadingScreen label="Counting…" />;

  const { ai, builds, security, findings } = data;
  const aiPurpose = new Map(ai.byPurpose.map((r) => [r.key, r.usd ?? 0]));
  const aiApp = new Map(ai.byApp.map((r) => [r.key, r.usd ?? 0]));
  const events = new Map(security.byEvent.map((r) => [r.key, r.count]));
  const openBySeverity = new Map(findings.open.map((r) => [r.key, r.count]));
  const criticalOrHigh = (openBySeverity.get('critical') ?? 0) + (openBySeverity.get('high') ?? 0);
  const totalOpen = findings.open.reduce((n, r) => n + r.count, 0);

  return (
    <div className="sv-stack">
      <div className="sv-row-between" style={{ flexWrap: 'wrap', gap: 12 }}>
        <h1 style={{ margin: 0 }}>Dashboard</h1>
        <div className="sv-segmented" role="group" aria-label="Period">
          {([7, 30, 90] as const).map((p) => (
            <button key={p} type="button" aria-pressed={period === p} onClick={() => setPeriod(p)}>
              {p} days
            </button>
          ))}
        </div>
      </div>
      <p className="sv-muted" style={{ marginTop: 0 }}>
        Counted from what SecureVibe keeps on this computer: the AI call log, your builds and the security log. Since{' '}
        {formatDate(data.from)}.
      </p>

      <div className="sv-tiles">
        <Tile value={usd(ai.totalUsd)} label={`AI spending (${ai.calls} calls)`} />
        <Tile value={builds.averageUsd === null ? '–' : usd(builds.averageUsd)} label="Average AI cost per build" />
        <Tile value={String(builds.total)} label={`Builds and checks${builds.medianMinutes !== null ? ` · usually ${builds.medianMinutes} min` : ''}`} />
        <Tile value={String(criticalOrHigh)} label={`Critical or high findings open (${totalOpen} open in total)`} tone={criticalOrHigh > 0 ? 'bad' : undefined} />
        <Tile value={String(security.refusals)} label="Refused requests" tone={security.refusals > 0 ? 'bad' : undefined} />
        <Tile value={String(security.signIns)} label={`Sign-ins${security.lastSignInAt ? ` · last ${formatDate(security.lastSignInAt)}` : ''}`} />
      </div>

      <Card>
        <h2>AI spending</h2>
        <h3 style={{ marginTop: 0 }}>Per day ({usd(ai.totalUsd)} in total)</h3>
        <DailyColumns
          days={ai.byDay.map((d) => d.day)}
          value={(i) => ai.byDay[i]!.usd}
          describe={(i) => `${usd(ai.byDay[i]!.usd)}, ${ai.byDay[i]!.calls} calls`}
        />
        <div className="sv-grid" style={{ marginTop: 16 }}>
          <div>
            <h3>What it was spent on</h3>
            <Bars rows={ai.byPurpose} value={(k) => aiPurpose.get(k) ?? 0} format={usd} />
          </div>
          <div>
            <h3>By app</h3>
            <Bars rows={ai.byApp} value={(k) => aiApp.get(k) ?? 0} format={usd} />
          </div>
        </div>
        <ul className="sv-muted" style={{ marginBottom: 0 }}>
          <li>
            {Math.round(ai.cacheShare * 100)}% of the text sent to Claude was re-used from the cache, which costs about a
            tenth of the normal price.
          </li>
          <li>
            {ai.failedCalls === 0
              ? 'No AI calls failed.'
              : `${ai.failedCalls} AI call(s) failed (for example no credit left or an unusable answer).`}
          </li>
          {ai.byModel.length > 0 && <li>Models: {ai.byModel.map((m) => `${m.label} (${m.count} calls, ${usd(m.usd ?? 0)})`).join(', ')}.</li>}
        </ul>
      </Card>

      <Card>
        <h2>Builds</h2>
        <p className="sv-muted">
          {builds.byStatus.map((s) => `${s.count} ${s.label}`).join(' · ') || 'No builds in this period.'}
          {builds.maxUsd !== null && ` · most expensive: ${usd(builds.maxUsd)}`}
        </p>
        {builds.recent.length > 0 && (
          <div className="sv-table-scroll">
            <table className="sv-table">
              <caption className="sv-visually-hidden">Recent builds</caption>
              <thead>
                <tr>
                  <th scope="col">App</th>
                  <th scope="col">Started</th>
                  <th scope="col">Result</th>
                  <th scope="col">Time</th>
                  <th scope="col">AI cost</th>
                  <th scope="col">Open findings</th>
                </tr>
              </thead>
              <tbody>
                {builds.recent.map((r) => (
                  <tr key={r.runId}>
                    <td>
                      <Link to={`/projects/${r.projectId}/results`}>{r.appName}</Link>
                      {r.mode === 'verify-only' && <span className="sv-faint"> (checks only)</span>}
                    </td>
                    <td>{formatDate(r.startedAt)}</td>
                    <td>
                      <Badge tone={STATUS_TONE[r.status] ?? 'neutral'}>{humanize(r.status)}</Badge>
                    </td>
                    <td>{r.minutes === null ? '–' : `${r.minutes} min`}</td>
                    <td>
                      {usd(r.usd)}
                      {r.spendingCapUsd !== undefined && r.usd > 0 && <span className="sv-faint"> of {usd(r.spendingCapUsd)}</span>}
                    </td>
                    <td>{r.openFindings}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <h2>Security log</h2>
        {security.recordingSince === null ? (
          <p className="sv-muted">
            Nothing recorded yet. SecureVibe records sign-ins and refused requests from now on.
          </p>
        ) : (
          <>
            <h3 style={{ marginTop: 0 }}>
              Refused requests per day ({security.refusals} in total)
            </h3>
            <DailyColumns
              days={security.byDay.map((d) => d.day)}
              value={(i) => security.byDay[i]!.refusals}
              describe={(i) => `${security.byDay[i]!.refusals} refused, ${security.byDay[i]!.signIns} sign-ins`}
            />
            <div className="sv-grid" style={{ marginTop: 16 }}>
              <div>
                <h3>By kind</h3>
                <Bars rows={security.byEvent} value={(k) => events.get(k) ?? 0} format={String} />
              </div>
              <div>
                <h3>Most recent refusals</h3>
                {security.recent.length === 0 ? (
                  <p className="sv-muted">None in this period.</p>
                ) : (
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {security.recent.slice(0, 8).map((e, i) => (
                      <li key={i}>
                        <strong>{e.label}</strong>
                        <span className="sv-faint">
                          {' '}
                          · {formatDate(e.ts)}
                          {e.method && e.path ? ` · ${e.method} ${e.path}` : ''}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
            <p className="sv-faint" style={{ marginBottom: 0 }}>
              A few refusals are normal (for example an old tab after a restart). Many in a short time, or requests from
              another website, are worth a closer look. Recording since {formatDate(security.recordingSince)}.
            </p>
          </>
        )}
      </Card>

      <Card>
        <h2>Open findings</h2>
        <p className="sv-muted">From the latest build of each app that is not archived.</p>
        <div className="sv-grid">
          <div>
            <h3>By severity</h3>
            <Bars rows={findings.open.map((r) => ({ ...r, label: humanize(r.label) }))} value={(k) => openBySeverity.get(k) ?? 0} format={String} tone="bad" />
          </div>
          <div>
            <h3>By app</h3>
            {findings.byApp.length === 0 ? (
              <p className="sv-muted">No app has been built yet.</p>
            ) : (
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {findings.byApp.map((a) => (
                  <li key={a.projectId}>
                    <Link to={`/projects/${a.projectId}/results`}>{a.appName}</Link>: {a.open} open
                    {a.critical + a.high > 0 && (
                      <strong style={{ color: 'var(--color-danger)' }}>
                        {' '}
                        ({a.critical} critical, {a.high} high)
                      </strong>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}
