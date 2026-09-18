import { useEffect, useState } from 'react';
import { updateSettings } from '../lib/api';
import { useStatus } from '../hooks/useStatus';
import { Card, ErrorNotice, LoadingScreen } from '../components/Bits';
import { AiKeys } from '../components/AiKeys';

const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'] as const;

export function SettingsPage() {
  const { status, loading, error, refresh } = useStatus();
  const [model, setModel] = useState('');
  const [generationEffort, setGenerationEffort] = useState<(typeof EFFORTS)[number]>('high');
  const [reviewEffort, setReviewEffort] = useState<(typeof EFFORTS)[number]>('medium');
  const [cap, setCap] = useState(10);
  const [fixRounds, setFixRounds] = useState(2);
  const [storeFullPrompts, setStoreFullPrompts] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!status) return;
    setModel(status.settings.model);
    setGenerationEffort(status.settings.generationEffort);
    setReviewEffort(status.settings.reviewEffort);
    setCap(status.settings.defaultSpendingCapUsd);
    setFixRounds(status.settings.maxFixRounds);
    setStoreFullPrompts(status.settings.storeFullPrompts);
  }, [status]);

  // Only the first load shows the loading screen; a refresh after saving keeps the page (and its scroll position).
  if (loading && !status) return <LoadingScreen label="Loading settings…" />;
  if (error || !status) return <ErrorNotice message={error ?? 'Could not load settings.'} />;

  async function save(patch: Partial<Parameters<typeof updateSettings>[0]>) {
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    try {
      await updateSettings(patch);
      await refresh();
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Could not save settings.');
    } finally {
      setSaving(false);
    }
  }

  async function resetToRecommended() {
    setSaving(true);
    setSaveError(null);
    try {
      await updateSettings({ reset: true });
      await refresh();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Could not reset settings.');
    } finally {
      setSaving(false);
    }
  }

  const aiOn = status.settings.aiEnabled;
  const lockedOff = status.llm.switchedOff === 'environment';

  return (
    <div className="sv-stack">
      <h1>Settings</h1>
      <Card>
        <h2>Use AI</h2>
        <p className="sv-help">
          With AI on, Claude writes your app&apos;s features and reviews the code, which costs money on your Anthropic
          account. With AI off, SecureVibe still builds the hardened starter app with pages for your records and runs
          every automated check, and nothing is sent to Anthropic.
        </p>
        <label className="sv-checkbox-row">
          <input
            type="checkbox"
            role="switch"
            aria-label="Use AI"
            aria-checked={aiOn}
            checked={aiOn}
            disabled={saving || lockedOff}
            onChange={(e) => void save({ aiEnabled: e.target.checked })}
          />
          <span>
            <strong>{aiOn ? 'AI is on' : 'AI is off'}</strong>
          </span>
        </label>
        <p className="sv-muted" style={{ marginBottom: 0 }}>
          {status.llm.message}
          {lockedOff && ' Restart SecureVibe without SECUREVIBE_AI=off to use this switch.'}
          {aiOn && !status.llm.configured && ' Add an Anthropic API key (see the home page) for AI to work.'}
        </p>
        {saveError && <ErrorNotice message={saveError} />}
      </Card>
      <AiKeys services={status.aiServices} onChanged={() => void refresh()} />

      <Card>
        <h2>Save credits</h2>
        <p className="sv-help">
          On: builds use {status.settings.saveCredits ? status.settings.effectiveModel : 'Claude Sonnet 5'}, which costs about
          2.5 times less than Opus 5, with the lowest effort and at most one round of fixes. Builds may take a little
          longer. Off: builds use the model and effort chosen below.
        </p>
        <label className="sv-checkbox-row">
          <input
            type="checkbox"
            role="switch"
            aria-label="Save credits"
            aria-checked={status.settings.saveCredits}
            checked={status.settings.saveCredits}
            disabled={saving}
            onChange={(e) => void save({ saveCredits: e.target.checked })}
          />
          <span>
            <strong>{status.settings.saveCredits ? 'Save credits is on' : 'Save credits is off'}</strong>
          </span>
        </label>
        <p className="sv-muted" style={{ marginBottom: 0 }}>
          Builds now use <strong>{status.settings.effectiveModel}</strong>. Whatever you choose, a build never spends
          more than its spending limit: writing the app may use up to 55% of it, and the rest is kept for the code
          review and the fixes.
        </p>
      </Card>
      <Card>
        <p className="sv-muted">
          These are advanced options. The defaults work well for most people; only change them if you know what you
          want.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save({
              model,
              generationEffort,
              reviewEffort,
              defaultSpendingCapUsd: cap,
              maxFixRounds: fixRounds,
              storeFullPrompts,
            });
          }}
        >
          <div className="sv-field">
            <label className="sv-label" htmlFor="model">
              AI model
            </label>
            <p className="sv-help">
              The Claude model used to write and review your app.
              {status.settings.saveCredits && ' Not used while Save credits is on.'}
            </p>
            <input id="model" className="sv-input" value={model} onChange={(e) => setModel(e.target.value)} />
          </div>

          <div className="sv-field">
            <label className="sv-label" htmlFor="genEffort">
              How hard the AI works while writing your app
            </label>
            <p className="sv-help">Higher settings usually give better code but take longer and cost more.</p>
            <select
              id="genEffort"
              className="sv-select"
              value={generationEffort}
              onChange={(e) => setGenerationEffort(e.target.value as (typeof EFFORTS)[number])}
            >
              {EFFORTS.map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
          </div>

          <div className="sv-field">
            <label className="sv-label" htmlFor="reviewEffort">
              How hard the AI works while reviewing your app for security problems
            </label>
            <select
              id="reviewEffort"
              className="sv-select"
              value={reviewEffort}
              onChange={(e) => setReviewEffort(e.target.value as (typeof EFFORTS)[number])}
            >
              {EFFORTS.map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
          </div>

          <div className="sv-field">
            <label className="sv-label" htmlFor="cap">
              Default spending cap per build (US dollars)
            </label>
            <p className="sv-help">
              You can change this again on the Build page before each build. SecureVibe stops before going over it.
            </p>
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

          <div className="sv-field">
            <label className="sv-label" htmlFor="fixRounds">
              How many times Claude may try to fix problems it finds
            </label>
            <input
              id="fixRounds"
              type="number"
              min={0}
              max={3}
              className="sv-input"
              value={fixRounds}
              onChange={(e) => setFixRounds(Number(e.target.value))}
            />
          </div>

          <div className="sv-checkbox-row" style={{ marginBottom: 24 }}>
            <input
              id="storeFullPrompts"
              type="checkbox"
              checked={storeFullPrompts}
              onChange={(e) => setStoreFullPrompts(e.target.checked)}
            />
            <label htmlFor="storeFullPrompts">
              <strong>Keep a full copy of every message sent to and received from the AI</strong>
              <div className="sv-help">
                On by default. Keeps more detail on this computer, useful for troubleshooting, but
                uses more disk space.
              </div>
            </label>
          </div>

          {saveError && <ErrorNotice message={saveError} />}

          <div className="sv-row">
            <button type="submit" className="sv-btn" disabled={saving}>
              {saving ? 'Saving…' : 'Save settings'}
            </button>
            <button type="button" className="sv-btn sv-btn-secondary" onClick={() => void resetToRecommended()} disabled={saving}>
              Reset to recommended
            </button>
            {saved && <span className="sv-badge sv-badge-good">Saved</span>}
          </div>
        </form>
      </Card>

      <Card>
        <h2>About this computer</h2>
        <p className="sv-muted">
          SecureVibe {status.version} on Node {status.nodeVersion}. Your apps are stored in{' '}
          <code className="sv-code">{status.workspaceDir}</code>.
        </p>
        <h3>Extra scanners on this computer</h3>
        <ul>
          {status.tools.map((t) => (
            <li key={t.tool}>
              <strong>{t.tool}:</strong> {t.ran ? `available${t.version ? ` (${t.version})` : ''}` : `not installed${t.reason ? ` — ${t.reason}` : ''}`}
              {t.covers ? ` — ${t.covers}` : ''}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
