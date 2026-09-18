import { useState } from 'react';
import { Link } from 'react-router';
import type { ProjectListItem } from '@shared/api.js';
import { archiveProject, deleteProject, restoreProject } from '../lib/api';
import { formatDate } from '../lib/format';
import { QUESTION_STEP_IDS, resumeStepId } from '../lib/wizardSteps';
import { Badge, ErrorNotice } from './Bits';

const STATUS_LABEL: Record<ProjectListItem['status'], { text: string; tone: 'good' | 'warn' | 'bad' | 'info' | 'neutral' }> = {
  draft: { text: 'Not finished', tone: 'neutral' },
  designed: { text: 'Design ready', tone: 'info' },
  building: { text: 'Building…', tone: 'warn' },
  built: { text: 'Built', tone: 'good' },
  failed: { text: 'Build failed', tone: 'bad' },
};

const UPLOADED_STATUS_LABEL: Partial<typeof STATUS_LABEL> = {
  designed: { text: 'Ready to check', tone: 'info' },
  building: { text: 'Checking…', tone: 'warn' },
  built: { text: 'Checked', tone: 'good' },
  failed: { text: 'Check failed', tone: 'bad' },
};

export function projectHref(p: ProjectListItem): string {
  if (p.status === 'building') return `/projects/${p.id}/build`;
  if (p.origin?.kind === 'uploaded' && !p.origin.upload) return `/projects/${p.id}/upload`;
  // Anything that has run at least once has results (and reports) to show.
  if (p.status === 'built' || p.status === 'failed' || p.lastRunId) return `/projects/${p.id}/results`;
  if (p.status === 'designed') return `/projects/${p.id}/summary`;
  return `/projects/${p.id}/wizard/${resumeStepId(p.wizardStep)}`;
}

/** Apps still in the questions: they pick up where the owner left off. */
function isUnfinished(p: ProjectListItem): boolean {
  return p.status === 'draft' && !p.lastRunId;
}

/** The owner's apps, with archive (hide, restorable) and delete (permanent, confirmed by typing the name). */
export function AppList({ projects, onChanged }: { projects: ProjectListItem[]; onChanged: () => Promise<void> }) {
  const [showArchived, setShowArchived] = useState(false);
  const [confirming, setConfirming] = useState<ProjectListItem | null>(null);
  const [typedName, setTypedName] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const active = projects.filter((p) => !p.archivedAt);
  const archived = projects.filter((p) => p.archivedAt);

  async function act(p: ProjectListItem, action: () => Promise<unknown>, failure: string) {
    setBusy(p.id);
    setError(null);
    try {
      await action();
      await onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : failure);
    } finally {
      setBusy(null);
    }
  }

  async function confirmDelete() {
    if (!confirming) return;
    const target = confirming;
    await act(target, () => deleteProject(target.id), 'Could not delete this app.');
    setConfirming(null);
    setTypedName('');
  }

  function rows(list: ProjectListItem[], isArchived: boolean) {
    return list.map((p) => {
      const label = p.origin?.kind === 'uploaded' ? (UPLOADED_STATUS_LABEL[p.status] ?? STATUS_LABEL[p.status]) : STATUS_LABEL[p.status];
      return (
        <tr key={p.id}>
          <td>{p.name}</td>
          <td>
            <Badge tone={label.tone}>{label.text}</Badge>
            {p.origin?.kind === 'uploaded' && (
              <span style={{ marginLeft: 8 }}>
                <Badge tone="neutral">{p.origin.upload ? 'Uploaded' : 'Not uploaded yet'}</Badge>
              </span>
            )}
            {isUnfinished(p) && (
              <span className="sv-faint" style={{ marginLeft: 8 }}>
                Step {Math.min((p.wizardStep ?? 0) + 1, QUESTION_STEP_IDS.length)} of {QUESTION_STEP_IDS.length}
              </span>
            )}
            {p.designStale && (
              <span style={{ marginLeft: 8 }}>
                <Badge tone="warn">Design changed</Badge>
              </span>
            )}
            {p.templateOutdated && p.status === 'built' && (
              <span style={{ marginLeft: 8 }}>
                <Badge tone="info">Template update</Badge>
              </span>
            )}
            {p.buildStale && (
              <span style={{ marginLeft: 8 }}>
                <Badge tone="warn">Rebuild needed</Badge>
              </span>
            )}
          </td>
          <td>{formatDate(isArchived && p.archivedAt ? p.archivedAt : p.updatedAt)}</td>
          <td>
            <div className="sv-row" style={{ flexWrap: 'wrap' }}>
              {!isArchived && (
                <Link
                  className={isUnfinished(p) ? 'sv-btn sv-btn-sm' : 'sv-btn sv-btn-secondary sv-btn-sm'}
                  to={projectHref(p)}
                  aria-label={`${isUnfinished(p) ? 'Continue' : 'Open'} ${p.name}`}
                >
                  {isUnfinished(p) ? 'Continue' : 'Open'}
                </Link>
              )}
              {!isArchived && p.lastRunId && (
                <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${p.id}/results`} aria-label={`Results for ${p.name}`}>
                  Results
                </Link>
              )}
              {!isArchived && p.lastRunId && (
                <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${p.id}/verify`} aria-label={`Human checks for ${p.name}`}>
                  Human checks
                </Link>
              )}
              {!isArchived && p.lastRunId && (
                <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${p.id}/security`} aria-label={`Security checks for ${p.name}`}>
                  Security checks
                </Link>
              )}
              {!isArchived && !isUnfinished(p) && p.status !== 'building' && (
                <Link
                  className="sv-btn sv-btn-secondary sv-btn-sm"
                  to={`/projects/${p.id}/wizard/about`}
                  aria-label={`Edit the answers for ${p.name}`}
                >
                  Edit app
                </Link>
              )}
              {isArchived ? (
                <button
                  type="button"
                  className="sv-btn sv-btn-secondary sv-btn-sm"
                  disabled={busy === p.id}
                  onClick={() => void act(p, () => restoreProject(p.id), 'Could not restore this app.')}
                  aria-label={`Restore ${p.name}`}
                >
                  Restore
                </button>
              ) : (
                <button
                  type="button"
                  className="sv-btn sv-btn-secondary sv-btn-sm"
                  disabled={busy === p.id || p.status === 'building'}
                  onClick={() => void act(p, () => archiveProject(p.id), 'Could not archive this app.')}
                  aria-label={`Archive ${p.name}`}
                >
                  Archive
                </button>
              )}
              <button
                type="button"
                className="sv-btn sv-btn-danger sv-btn-sm"
                disabled={busy === p.id || p.status === 'building'}
                onClick={() => {
                  setConfirming(p);
                  setTypedName('');
                  setError(null);
                }}
                aria-label={`Delete ${p.name}`}
              >
                Delete
              </button>
            </div>
          </td>
        </tr>
      );
    });
  }

  function table(list: ProjectListItem[], isArchived: boolean) {
    return (
      <table className="sv-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>{isArchived ? 'Archived' : 'Last updated'}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>{rows(list, isArchived)}</tbody>
      </table>
    );
  }

  return (
    <>
      {error && <ErrorNotice message={error} />}
      {active.length === 0 && <p className="sv-muted">{archived.length > 0 ? 'All your apps are archived.' : 'You have not started an app yet.'}</p>}
      {active.length > 0 && table(active, false)}

      {confirming && (
        <div className="sv-banner sv-banner-bad" role="alertdialog" aria-labelledby="delete-title" style={{ marginTop: 16 }}>
          <h3 id="delete-title">Delete &ldquo;{confirming.name}&rdquo; for good?</h3>
          <p>
            This removes its answers, design, generated code, earlier versions and every report from this computer. It
            cannot be undone. To keep it out of the way instead, use <strong>Archive</strong>.
          </p>
          <div className="sv-field">
            <label className="sv-label" htmlFor="delete-confirm-name">
              Type the app&apos;s name to confirm
            </label>
            <input
              id="delete-confirm-name"
              className="sv-input"
              value={typedName}
              autoComplete="off"
              onChange={(e) => setTypedName(e.target.value)}
            />
          </div>
          <div className="sv-row">
            <button
              type="button"
              className="sv-btn sv-btn-danger"
              disabled={typedName.trim() !== confirming.name.trim() || busy === confirming.id}
              onClick={() => void confirmDelete()}
            >
              Delete permanently
            </button>
            <button type="button" className="sv-btn sv-btn-secondary" onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {archived.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <button type="button" className="sv-btn-link" aria-expanded={showArchived} onClick={() => setShowArchived((v) => !v)}>
            {showArchived ? 'Hide' : 'Show'} archived apps ({archived.length})
          </button>
          {showArchived && table(archived, true)}
        </div>
      )}
    </>
  );
}
