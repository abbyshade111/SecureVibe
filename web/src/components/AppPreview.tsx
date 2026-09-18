import { useEffect, useState } from 'react';
import { getPreview, startPreview, stopPreview, type PreviewInfo } from '../lib/api';
import { Card, CopyRow, ErrorNotice } from './Bits';
import { formatDate } from '../lib/format';

/** Start, open and stop a throw-away preview of the built app. */
export function AppPreview({ projectId, disabled }: { projectId: string; disabled?: string }) {
  const [info, setInfo] = useState<PreviewInfo | null>(null);
  const [busy, setBusy] = useState<'start' | 'stop' | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getPreview(projectId)
      .then(setInfo)
      .catch(() => setInfo({ running: false, differences: [] }));
  }, [projectId]);

  async function act(kind: 'start' | 'stop') {
    setBusy(kind);
    setError(null);
    try {
      setInfo(kind === 'start' ? await startPreview(projectId) : await stopPreview(projectId));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Something went wrong with the preview.');
    } finally {
      setBusy(null);
    }
  }

  // Only ever link to a preview on this computer (the server gives http://localhost:<port>/preview-signin?t=…).
  const previewUrl = (() => {
    if (!info?.url) return undefined;
    try {
      const url = new URL(info.url);
      return url.protocol === 'http:' && url.hostname === 'localhost' && url.port !== '' ? url.href : undefined;
    } catch {
      return undefined;
    }
  })();

  return (
    <Card id="preview">
      <h2>Preview your app</h2>
      {!info?.running ? (
        <>
          <p className="sv-muted">
            Try the app in your browser without setting anything up. SecureVibe starts a private copy on this computer
            and gives you a sign-in to use.
          </p>
          {info && info.differences.length > 0 && (
            <details className="sv-details">
              <summary>How the preview differs from your real app</summary>
              <ul style={{ marginBottom: 0 }}>
                {info.differences.map((d) => (
                  <li key={d}>{d}</li>
                ))}
              </ul>
            </details>
          )}
          {disabled && <p className="sv-faint">{disabled}</p>}
          <button type="button" className="sv-btn" disabled={busy !== null || !!disabled} onClick={() => void act('start')}>
            {busy === 'start' ? 'Starting the preview… (up to a minute)' : 'Start the preview'}
          </button>
        </>
      ) : (
        <>
          <p>
            Your app is running. <strong>Open the preview</strong> opens it in a new tab and signs you in as a preview
            administrator; the app shows a note on every page saying so. Your real app always asks for a password.
          </p>
          <details className="sv-details">
            <summary>Sign in by hand instead</summary>
            <p className="sv-muted">Use these on the app&apos;s own sign-in page, for example to show what signing in looks like.</p>
          <div className="sv-field">
            <span className="sv-label">Email address</span>
            <CopyRow text={info.email ?? ''} />
          </div>
          <div className="sv-field">
            <span className="sv-label">One-time password</span>
            <CopyRow text={info.password ?? ''} />
          </div>
          </details>
          <div className="sv-row" style={{ flexWrap: 'wrap' }}>
            {previewUrl && (
              <a className="sv-btn" href={previewUrl} target="_blank" rel="noreferrer noopener">
                Open the preview
              </a>
            )}
            <button type="button" className="sv-btn sv-btn-secondary" disabled={busy !== null} onClick={() => void act('stop')}>
              {busy === 'stop' ? 'Stopping…' : 'Stop the preview'}
            </button>
          </div>
          <p className="sv-faint" style={{ marginBottom: 0 }}>
            The preview stops by itself at {formatDate(info.stopsAt)}, and when you rebuild the app or close SecureVibe.
            Everything you enter in it is thrown away. Keep the link private while it runs: anyone on this computer who
            has it is signed in as that administrator.
          </p>
        </>
      )}
      {error && <ErrorNotice message={error} />}
    </Card>
  );
}
