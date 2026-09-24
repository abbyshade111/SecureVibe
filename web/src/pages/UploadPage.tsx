import { useEffect, useRef, useState } from 'react';
import { whatWeCanSay } from '@shared/languages.js';
import { Link, useNavigate, useParams } from 'react-router';
import { useProject } from '../hooks/useProject';
import { Card, ErrorNotice, LoadingScreen, ProgressBar } from '../components/Bits';
import { formatDate } from '../lib/format';
import { planUpload, runUpload, type UploadPlan } from '../lib/upload';

function size(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function UploadPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { project, loading, error, reload } = useProject(id);
  const [plan, setPlan] = useState<UploadPlan | null>(null);
  const [done, setDone] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Folder picking is not part of the HTML standard attributes React knows about.
  useEffect(() => {
    inputRef.current?.setAttribute('webkitdirectory', '');
    inputRef.current?.setAttribute('directory', '');
  }, [project]);

  useEffect(() => () => abortRef.current?.abort(), []);

  if (loading) return <LoadingScreen label="Loading…" />;
  if (error || !project || !id) return <ErrorNotice message={error ?? 'Could not load this app.'} />;

  if (project.origin?.kind !== 'uploaded') {
    return <ErrorNotice title="Not an uploaded app" message='Only apps added with "Check an app you already have" on My apps take uploads.' />;
  }
  const previous = project.origin?.upload;
  const hasAnswers = project.wizardStep > 0 || project.design !== undefined;
  /**
   * The questions come next, and they are not a detour: `POST /projects/:id/runs` refuses an uploaded app that
   * has no design with "Answer the questions about your app before checking it", because they are what decides
   * which rules apply to it. Sending somebody straight to the check page instead — which this did for half an
   * hour on 20 September 2026 — lands them on a page whose button can never enable, for a reason nothing shows.
   *
   * Whether an uploaded app should need them at all is a fair question and a real one: most of the scanners do
   * not, and somebody checking code they did not write cannot answer half of them. That is on the backlog as a
   * decision to make rather than something to route around here.
   */
  // The check runs with or without the answers (24 September 2026): what the answers add is the compliance
  // report and the AI review, because they decide which rules apply. So the check page comes next either way.
  const nextStep = project.design ? `/projects/${id}/summary` : `/projects/${id}/security`;

  async function start() {
    if (!plan || plan.problem || !id) return;
    setUploading(true);
    setUploadError(null);
    setDone(0);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      await runUpload(id, plan, setDone, controller.signal);
      await reload();
      navigate(nextStep);
    } catch (e) {
      setUploadError(e instanceof Error ? e.message : 'The upload did not finish.');
    } finally {
      setUploading(false);
    }
  }

  const skippedByReason = new Map<string, number>();
  for (const s of plan?.skipped ?? []) skippedByReason.set(s.reason, (skippedByReason.get(s.reason) ?? 0) + 1);

  return (
    <div className="sv-stack">
      <h1>{previous ? 'Upload a new version' : 'Upload your app'}</h1>
      <Card>
        <p>
          Choose the folder that holds your app&apos;s code. SecureVibe copies it into its own workspace on this computer
          and checks the copy; your folder is not changed.
        </p>
        <ul className="sv-muted">
          <li>
            Left out on purpose: installed packages (<code className="sv-code">node_modules</code>), build output, version
            history, and secrets files such as <code className="sv-code">.env</code> and private keys.
          </li>
          <li>SecureVibe scans the code; it never runs your app or its tests.</li>
          <li>Up to 5,000 files and 50 MB (without the left-out parts).</li>
        </ul>
        {previous && (
          <p className="sv-faint">
            Current version: {previous.files} files, uploaded {formatDate(previous.uploadedAt)}. A new upload replaces it; the old copy
            is kept.
          </p>
        )}

        <div className="sv-field">
          <label className="sv-label" htmlFor="appFolder">
            Your app&apos;s folder
          </label>
          <input
            ref={inputRef}
            id="appFolder"
            type="file"
            multiple
            disabled={uploading}
            onChange={(e) => {
              setUploadError(null);
              setPlan(e.target.files && e.target.files.length > 0 ? planUpload(e.target.files) : null);
            }}
          />
        </div>

        <p className="sv-faint">
          Or choose one .zip of the app: SecureVibe unpacks it, leaves out the same things, and checks what comes
          out.{' '}
          <input
            type="file"
            accept=".zip,application/zip"
            disabled={uploading}
            onChange={(e) => {
              setUploadError(null);
              setPlan(e.target.files && e.target.files.length > 0 ? planUpload(e.target.files) : null);
            }}
          />
        </p>

        {plan && !plan.problem && !plan.archive && (
          /**
           * What this app will actually get, said before the upload rather than discovered in the report.
           * The first person to hand SecureVibe somebody else's code uploaded a Python app, waited through a
           * check, paid for an AI review, and was told "0 of 106 requirements verified" — a sentence about
           * code that had never been read. The report no longer says that, and this is the half that stops
           * somebody spending twenty minutes to find out (ADR-012).
           */
          <div className="sv-banner">
            <p style={{ marginBottom: 4 }}>
              <strong>{whatWeCanSay(plan.files.map((f) => f.path)).headline}</strong>
            </p>
            <p className="sv-faint" style={{ marginBottom: 0 }}>
              {whatWeCanSay(plan.files.map((f) => f.path)).detail}
            </p>
          </div>
        )}

        {plan && (
          <div className={plan.problem ? 'sv-banner sv-banner-warn' : 'sv-banner'}>
            {plan.problem ? (
              <p style={{ marginBottom: 0 }}>{plan.problem}</p>
            ) : (
              <p style={{ marginBottom: 0 }}>
                <strong>{plan.folderName || 'Folder'}:</strong>{' '}
                {plan.archive ? `one zip (${size(plan.bytes)}) will be uploaded and unpacked.` : `${plan.files.length} files (${size(plan.bytes)}) will be uploaded.`}
              </p>
            )}
            {skippedByReason.size > 0 && (
              <p className="sv-faint" style={{ marginBottom: 0 }}>
                Left out: {[...skippedByReason.entries()].map(([reason, n]) => `${n} × ${reason}`).join(', ')}.
              </p>
            )}
          </div>
        )}

        {uploading && plan && (
          <ProgressBar
            percent={plan.archive ? (done > 0 ? 100 : 10) : Math.round((done / plan.files.length) * 100)}
            label={plan.archive ? (done > 0 ? 'Unpacked' : 'Uploading and unpacking the zip…') : `${done} of ${plan.files.length} files uploaded`}
          />
        )}
        {uploadError && <ErrorNotice message={uploadError} />}

        <div className="sv-row" style={{ flexWrap: 'wrap', marginTop: 12 }}>
          <button type="button" className="sv-btn" disabled={!plan || !!plan.problem || uploading} onClick={() => void start()}>
            {uploading ? 'Uploading…' : 'Upload and continue'}
          </button>
          {uploading ? (
            <button type="button" className="sv-btn sv-btn-secondary" onClick={() => abortRef.current?.abort()}>
              Cancel
            </button>
          ) : (
            previous && (
              <Link className="sv-btn sv-btn-secondary" to={nextStep}>
                Keep the current version
              </Link>
            )
          )}
        </div>

        {!hasAnswers && (
          <p className="sv-faint" style={{ marginTop: 12, marginBottom: 0 }}>
            Next comes the check itself: secrets, dependencies, configuration and the virus scan read the code as it
            is. To get the compliance report and the AI review as well, answer a few questions about what this app
            does (whether it takes payments, whether it holds health or financial information, whether your
            organisation has a central sign-in): they decide which rules apply to it. If you did not write this
            app and cannot answer one, say so rather than guessing: &quot;not sure&quot; is an answer SecureVibe
            understands and it never counts as evidence either way.
          </p>
        )}

      </Card>
    </div>
  );
}
