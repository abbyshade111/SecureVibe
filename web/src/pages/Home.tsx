import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import type { ExampleProject, ProjectListItem } from '@shared/api.js';
import { createProject, getExamples, listProjects } from '../lib/api';
import { useStatus } from '../hooks/useStatus';
import { AppList } from '../components/AppList';
import { Card, ErrorNotice, LoadingScreen } from '../components/Bits';
import { formatDate } from '../lib/format';

interface PendingStart {
  mode: 'guided' | 'quick';
  exampleId?: string;
  defaultName: string;
  /** Checking an app the owner already has. */
  upload?: boolean;
}

export function Home() {
  const { status, loading: statusLoading, error: statusError } = useStatus();
  const [projects, setProjects] = useState<ProjectListItem[] | null>(null);
  const [examples, setExamples] = useState<ExampleProject[] | null>(null);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const [showApiKeyHelp, setShowApiKeyHelp] = useState(false);
  const [pendingStart, setPendingStart] = useState<PendingStart | null>(null);
  const [newName, setNewName] = useState('');
  const [creating, setCreating] = useState(false);
  const [aiAssisted, setAiAssisted] = useState<boolean | null>(null);
  const navigate = useNavigate();

  async function reloadProjects() {
    try {
      setProjects(await listProjects());
    } catch (e) {
      setProjectsError(e instanceof Error ? e.message : 'Could not load your apps.');
    }
  }

  useEffect(() => {
    listProjects()
      .then(setProjects)
      .catch((e) => setProjectsError(e instanceof Error ? e.message : 'Could not load your apps.'));
    getExamples()
      .then(setExamples)
      .catch(() => setExamples([]));
  }, []);

  function openStartPanel(mode: 'guided' | 'quick', exampleId?: string, defaultName = '', upload = false) {
    setPendingStart({ mode, exampleId, defaultName, upload });
    setAiAssisted(null);
    setNewName(defaultName);
    setProjectsError(null);
  }

  async function confirmStart() {
    if (!pendingStart || !newName.trim()) return;
    if (pendingStart.upload && aiAssisted === null) return;
    setCreating(true);
    try {
      const project = await createProject({
        name: newName.trim(),
        mode: pendingStart.mode,
        exampleId: pendingStart.exampleId,
        ...(pendingStart.upload ? { uploaded: { aiAssisted: aiAssisted === true } } : {}),
      });
      navigate(pendingStart.upload ? `/projects/${project.id}/upload` : `/projects/${project.id}/wizard/about`);
    } catch (e) {
      setProjectsError(e instanceof Error ? e.message : 'Could not create the app.');
    } finally {
      setCreating(false);
    }
  }

  if (statusLoading) return <LoadingScreen label="Starting up…" />;
  if (statusError || !status) return <ErrorNotice message={statusError ?? 'SecureVibe is not responding.'} />;

  const blockingIssues = status.preflight.filter((p) => !p.ok && p.blocking);
  const nonBlockingIssues = status.preflight.filter((p) => !p.ok && !p.blocking);

  return (
    <div className="sv-stack">
      <h1>My apps</h1>

      {blockingIssues.length > 0 && (
        <Card>
          <h2>Before you start</h2>
          <p className="sv-muted">These need fixing first. Each one tells you exactly what to do.</p>
          <ul>
            {blockingIssues.map((p) => (
              <li key={p.id}>
                <strong>{p.title}.</strong> {p.detail}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {status.llm.previewMode && (
        <div className="sv-banner sv-banner-warn">
          <h3>Preview without AI</h3>
          <p>{status.llm.message}</p>
          {status.llm.switchedOff === 'setting' ? (
            <Link className="sv-btn-link" to="/settings">
              Turn AI on in Settings
            </Link>
          ) : (
            <button
              type="button"
              className="sv-btn-link"
              onClick={() => setShowApiKeyHelp((v) => !v)}
              aria-expanded={showApiKeyHelp}
            >
              {showApiKeyHelp ? 'Hide' : 'How to add an API key'}
            </button>
          )}
          {showApiKeyHelp && (
            <div style={{ marginTop: 12 }}>
              <p>
                <strong>What preview mode does:</strong>
              </p>
              <ul>
                <li>Walks you through every design question and shows what each answer changes.</li>
                <li>Builds the hardened starting application with sign-in, permissions and logging already in place.</li>
                <li>
                  Runs every automated check that does not need AI: code scanning, dependency checks, configuration
                  checks and the running-app tests.
                </li>
                <li>Produces a compliance report and a security report from what was actually verified.</li>
              </ul>
              <p>
                <strong>What preview mode does not do:</strong>
              </p>
              <ul>
                <li>It cannot write the custom pages and features you described — only the starting application.</li>
                <li>It skips the independent second-opinion design review.</li>
                <li>It skips the AI code review, so those requirements are honestly marked “not verified” instead of checked.</li>
                <li>It cannot fix findings automatically.</li>
              </ul>
              <p>
                To turn AI on, add your Anthropic API key as <code className="sv-code">ANTHROPIC_API_KEY</code> to a{' '}
                <code className="sv-code">.env</code> file next to SecureVibe (workspace:{' '}
                <code className="sv-code">{status.workspaceDir}</code>), or set it as an environment variable before
                starting SecureVibe. Then restart SecureVibe and reload this page.
              </p>
            </div>
          )}
        </div>
      )}

      {nonBlockingIssues.length > 0 && (
        <Card>
          <h2>Worth checking</h2>
          <ul>
            {nonBlockingIssues.map((p) => (
              <li key={p.id}>
                <strong>{p.title}.</strong> {p.detail}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {pendingStart && (
        <Card>
          <h2>{pendingStart.upload ? 'The app you want to check' : 'Name your app'}</h2>
          <p className="sv-muted">A short, friendly name. You can change this later.</p>
          <div className="sv-field">
            <label className="sv-visually-hidden" htmlFor="newProjectName">
              App name
            </label>
            <input
              id="newProjectName"
              className="sv-input"
              value={newName}
              maxLength={60}
              autoFocus
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && newName.trim()) void confirmStart();
              }}
            />
          </div>
          {pendingStart.upload && (
            <fieldset className="sv-field" style={{ border: 0, padding: 0 }}>
              <legend className="sv-label">Did AI tools help write this app?</legend>
              <p className="sv-help">
                For example Claude, ChatGPT, Copilot or Cursor. If they did, the checks also cover the extra rules for
                AI-assisted development.
              </p>
              <div className="sv-row">
                <label className="sv-checkbox-row">
                  <input type="radio" name="aiAssisted" checked={aiAssisted === true} onChange={() => setAiAssisted(true)} />
                  <span>Yes, or not sure</span>
                </label>
                <label className="sv-checkbox-row">
                  <input type="radio" name="aiAssisted" checked={aiAssisted === false} onChange={() => setAiAssisted(false)} />
                  <span>No, it was written by people</span>
                </label>
              </div>
            </fieldset>
          )}
          {projectsError && <ErrorNotice message={projectsError} />}
          <div className="sv-row">
            <button
              type="button"
              className="sv-btn"
              disabled={!newName.trim() || creating || (pendingStart.upload === true && aiAssisted === null)}
              onClick={() => void confirmStart()}
            >
              {creating ? 'Starting…' : 'Continue'}
            </button>
            <button type="button" className="sv-btn sv-btn-secondary" onClick={() => setPendingStart(null)}>
              Cancel
            </button>
          </div>
        </Card>
      )}

      <Card>
        <div className="sv-row-between">
          <h2 style={{ margin: 0 }}>Start a new app</h2>
          <span className="sv-faint">About 10 minutes</span>
        </div>
        <p className="sv-muted">
          Answer a few plain-language questions and SecureVibe designs, builds and checks a secure web app for you.
        </p>
        <div className="sv-grid">
          <div className="sv-card" style={{ margin: 0 }}>
            <h3>Guided (recommended)</h3>
            <p className="sv-muted">
              We ask one question at a time and explain why. Best the first time, or if you want full control.
            </p>
            <button type="button" className="sv-btn sv-btn-block" onClick={() => openStartPanel('guided')}>
              Start guided
            </button>
          </div>
          <div className="sv-card" style={{ margin: 0 }}>
            <h3>Quick</h3>
            <p className="sv-muted">
              Describe your app in your own words. We guess the rest and show you every guess to confirm — guesses
              can only make the app safer, never less safe.
            </p>
            {status.llm.previewMode ? (
              <p className="sv-muted">
                <strong>{status.llm.switchedOff ? 'Needs AI.' : 'Needs an API key.'}</strong> Quick mode uses AI to read
                your description, so it is not available in Preview without AI. Use the guided questions instead
                {status.llm.switchedOff === 'setting' ? ', or turn AI on in Settings' : ''}.
              </p>
            ) : (
              <button type="button" className="sv-btn sv-btn-secondary sv-btn-block" onClick={() => openStartPanel('quick')}>
                Start quick
              </button>
            )}
          </div>
        </div>
      </Card>

      <Card>
        <h2>Check an app you already have</h2>
        <p className="sv-muted">
          Built an app yourself, or with another AI tool? Upload its folder and SecureVibe checks the code against the same
          OWASP standards and writes the same reports. It scans the code only; it never runs your app.
        </p>
        <button type="button" className="sv-btn sv-btn-secondary" onClick={() => openStartPanel('guided', undefined, '', true)}>
          Check an app I have
        </button>
      </Card>

      {examples && examples.length > 0 && (
        <Card>
          <h2>Or start from an example</h2>
          <p className="sv-muted">Copy a ready-made example and change what you need.</p>
          <div className="sv-grid">
            {examples.map((ex) => (
              <div className="sv-card" style={{ margin: 0 }} key={ex.id}>
                <h3>{ex.title}</h3>
                <p className="sv-muted">{ex.description}</p>
                <button
                  type="button"
                  className="sv-btn sv-btn-secondary sv-btn-block"
                  onClick={() => openStartPanel('guided', ex.id, ex.profile.app.name)}
                >
                  Use this example
                </button>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card>
        <div className="sv-row-between">
          <h2 style={{ margin: 0 }}>Your apps</h2>
        </div>
        {projectsError && !pendingStart && <ErrorNotice message={projectsError} />}
        {!projects && !projectsError && <LoadingScreen label="Loading your apps…" />}
        {projects && <AppList projects={projects} onChanged={reloadProjects} />}
      </Card>
    </div>
  );
}
