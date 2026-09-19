import { useEffect, useState } from 'react';
import type { AppVersion, DiffFile, FileDiffResponse, VersionDiff as VersionDiffData } from '@shared/api.js';
import { getFileDiff, getVersionDiff, getVersions } from '../lib/api';
import { formatDate } from '../lib/format';
import { Badge, ErrorNotice } from './Bits';

const ORIGIN_LABEL: Record<string, string> = {
  template: 'SecureVibe template',
  expanded: 'Made from your answers',
  'ai-generated': 'Written by Claude',
  'ai-fixed': 'Fixed by Claude',
  user: 'Your own change',
};

const KIND_LABEL: Record<DiffFile['kind'], { text: string; tone: 'good' | 'bad' | 'info' }> = {
  added: { text: 'New', tone: 'good' },
  removed: { text: 'Removed', tone: 'bad' },
  changed: { text: 'Changed', tone: 'info' },
};

function versionName(v: AppVersion): string {
  return v.builtAt ? `${v.label} (${formatDate(v.builtAt)})` : v.label;
}

/** "What changed since the previous version": file changes with their origins, and how the checks moved. */
export function VersionDiff({ projectId }: { projectId: string }) {
  const [versions, setVersions] = useState<AppVersion[]>([]);
  const [from, setFrom] = useState<string>('');
  const [to, setTo] = useState<string>('current');
  const [diff, setDiff] = useState<VersionDiffData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [fileText, setFileText] = useState<Record<string, FileDiffResponse>>({});

  useEffect(() => {
    let cancelled = false;
    getVersions(projectId)
      .then((list) => {
        if (cancelled) return;
        setVersions(list);
        const previous = list.find((v) => v.id !== 'current');
        if (previous) setFrom(previous.id);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Could not list the versions.'));
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  useEffect(() => {
    if (!from || !to || from === to) {
      setDiff(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setOpen(null);
    setFileText({});
    getVersionDiff(projectId, from, to)
      .then((d) => {
        if (!cancelled) setDiff(d);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Could not compare the versions.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, from, to]);

  async function toggle(path: string) {
    if (open === path) {
      setOpen(null);
      return;
    }
    setOpen(path);
    if (!fileText[path]) {
      try {
        const d = await getFileDiff(projectId, from, to, path);
        setFileText((m) => ({ ...m, [path]: d }));
      } catch (e) {
        setFileText((m) => ({ ...m, [path]: { path, kind: 'changed', unified: e instanceof Error ? e.message : 'Could not load this file.', truncated: false } }));
      }
    }
  }

  if (versions.length < 2) return null;

  const results = diff?.results;
  const delta = (before: number, after: number, unit = '%') => {
    const d = Math.round((after - before) * 10) / 10;
    return d === 0 ? `unchanged at ${after}${unit}` : `${before}${unit} → ${after}${unit} (${d > 0 ? '+' : ''}${d}${unit})`;
  };

  return (
    <>
      <p className="sv-muted">
        Every rebuild keeps the previous version of your app. Compare two versions to see which files changed, where each
        one came from, and how the checks moved. Settings files with secrets are never shown.
      </p>
      <div className="sv-row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <label>
          From{' '}
          <select value={from} onChange={(e) => setFrom(e.target.value)}>
            {versions.map((v) => (
              <option key={v.id} value={v.id}>
                {versionName(v)}
              </option>
            ))}
          </select>
        </label>
        <label>
          to{' '}
          <select value={to} onChange={(e) => setTo(e.target.value)}>
            {versions.map((v) => (
              <option key={v.id} value={v.id}>
                {versionName(v)}
              </option>
            ))}
          </select>
        </label>
      </div>
      {error && <ErrorNotice message={error} />}
      {loading && <p className="sv-muted">Comparing…</p>}
      {diff && !loading && (
        <>
          {results && (
            <div className="sv-card" style={{ margin: '12px 0', background: 'var(--color-bg-subtle)' }}>
              <h3 style={{ marginTop: 0 }}>How the checks moved</h3>
              <ul>
                <li>
                  Problems: {results.findingsResolved.length} resolved, {results.findingsNew.length} new, {results.findingsStillOpen} still open.
                </li>
                {results.asvs && <li>ASVS verified coverage: {delta(results.asvs.before, results.asvs.after)}.</li>}
                {results.aisvs && <li>AISVS verified coverage: {delta(results.aisvs.before, results.aisvs.after)}.</li>}
                {results.tests && (
                  <li>
                    App tests passing: {results.tests.before.passed} of {results.tests.before.total} → {results.tests.after.passed} of {results.tests.after.total}.{' '}
                    {/* "132 of 194" reads as "62 are failing", and usually none are: the rest are skipped because
                        the app has no uploads, no scheduled jobs, no assistant. This comparison only carries the
                        total and the passing count, so the line cannot yet name the reason — it can at least
                        stop implying one. Naming it needs the failed and skipped counts, which is server work. */}
                    <span className="sv-faint">
                      A test that is not passing has either failed or been skipped because your app does not have
                      that feature; this comparison does not yet say which.
                    </span>
                  </li>
                )}
              </ul>
              {results.findingsNew.length > 0 && (
                <>
                  <h4>New problems</h4>
                  <ul>
                    {results.findingsNew.map((f) => (
                      <li key={f.fingerprint}>
                        <Badge tone={f.severity === 'critical' || f.severity === 'high' ? 'bad' : f.severity === 'medium' ? 'warn' : 'neutral'}>{f.severity}</Badge> {f.title}
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {results.findingsResolved.length > 0 && (
                <>
                  <h4>Resolved</h4>
                  <ul>
                    {results.findingsResolved.map((f) => (
                      <li key={f.fingerprint}>
                        <Badge tone="good">{f.severity}</Badge> {f.title}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
          {diff.files.length === 0 ? (
            <p>No files differ between these two versions.</p>
          ) : (
            <>
              {/* Folded away: a rebuild differs in 65 files, and an unfolded list that long stops being
                  information and becomes scenery — the summary above it scrolls out of sight, and the one file
                  worth noticing scrolls past with the rest. */}
              <details className="sv-details">
                <summary>
                  {diff.files.length} file(s) differ{diff.truncated ? ' (only the first are listed)' : ''} — show them
                </summary>
              <p>Click a file to see the lines that changed.</p>
              <table className="sv-table">
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Change</th>
                    <th>Came from</th>
                    <th>Lines</th>
                  </tr>
                </thead>
                <tbody>
                  {diff.files.map((f) => (
                    <FileRow key={f.path} file={f} open={open === f.path} text={fileText[f.path]} onToggle={() => void toggle(f.path)} />
                  ))}
                </tbody>
              </table>
              </details>
            </>
          )}
        </>
      )}
    </>
  );
}

function FileRow({ file, open, text, onToggle }: { file: DiffFile; open: boolean; text?: FileDiffResponse; onToggle: () => void }) {
  const kind = KIND_LABEL[file.kind];
  return (
    <>
      <tr>
        <td>
          <button type="button" className="sv-link" onClick={onToggle} aria-expanded={open}>
            {file.path}
          </button>
        </td>
        <td>
          <Badge tone={kind.tone}>{kind.text}</Badge>
        </td>
        <td>{file.origin ? (ORIGIN_LABEL[file.origin] ?? file.origin) : '—'}</td>
        <td>{file.secret ? 'secrets, not shown' : file.binary ? 'not text' : file.kind === 'changed' ? `+${file.linesAdded} −${file.linesRemoved}` : ''}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={4}>
            {text ? (
              <pre className="sv-diff" style={{ whiteSpace: 'pre-wrap', overflowX: 'auto', margin: 0 }}>
                {text.unified.split('\n').map((line, i) => (
                  <span key={i} className={line.startsWith('+') && !line.startsWith('+++') ? 'sv-diff-add' : line.startsWith('-') && !line.startsWith('---') ? 'sv-diff-del' : line.startsWith('@@') ? 'sv-diff-hunk' : ''}>
                    {line}
                    {'\n'}
                  </span>
                ))}
              </pre>
            ) : (
              <span className="sv-muted">Loading…</span>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
