import { useEffect, useState } from 'react';
import type { StatusResponse } from '@shared/api.js';
import { updateSettings } from '../lib/api';
import { useStatus } from '../hooks/useStatus';
import { Card, ErrorNotice, LoadingScreen } from '../components/Bits';
import { AiKeys } from '../components/AiKeys';

const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'] as const;

type AiServiceFor = StatusResponse['settings']['aiServiceFor'];
type StepGroup = 'write' | 'review' | 'questions';
type StepService = AiServiceFor['write'];

const STEP_CHOICES: { id: StepGroup; label: string; help: string }[] = [
  { id: 'write', label: 'Writing your app', help: 'Writes your features and fixes what the checks find. This is where most of the money goes.' },
  { id: 'review', label: 'Reviewing the code', help: 'Reads the finished code against the security requirements. A service that did not write the code gives an independent opinion.' },
  { id: 'questions', label: 'Questions, plans and second opinions', help: 'The follow-up questions, the build plan, the second opinion on your answers and the threat model. Short, cheap steps.' },
];

function serviceLabel(services: StatusResponse['aiServices'], id: string): string {
  return services.find((s: StatusResponse['aiServices'][number]) => s.service === id)?.label ?? id;
}

/** True when the review step ends up on a different service than the one writing the app. */
function independentReview(settings: StatusResponse['settings']): boolean {
  const resolve = (v: StepService) => (v === 'default' ? settings.aiService : v);
  return resolve(settings.aiServiceFor.review) !== resolve(settings.aiServiceFor.write);
}

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
        <h2>Which AI service does what</h2>
        <p className="sv-help">
          Everything uses the service you pick first. You can then send single steps to another service — for example
          have one service write your app and a different one review it, so the code is checked by something that did
          not write it. Only services with a key can be chosen; add one under "Your AI service" above. Save credits
          picks each service's cheaper model, and the reports record which service did which step.
        </p>
        <h3 style={{ marginTop: 16 }}>Your main service</h3>
        <div className="sv-option-list">
          {status.aiServices.map((s) => (
            <label className="sv-option" key={s.service} data-checked={status.settings.aiService === s.service}>
              <input
                type="radio"
                name="aiService"
                value={s.service}
                checked={status.settings.aiService === s.service}
                disabled={saving || !s.configured}
                onChange={() => void save({ aiService: s.service })}
              />
              <span className="sv-option-label">
                {s.label}
                {s.configured ? '' : ' — add a key first'}
              </span>
            </label>
          ))}
        </div>

        {/* "Steps that can use a different service" read as though some steps were merely eligible, and left an
            owner unsure whether the list was a choice at all. Each step has its own setting; say that. */}
        <h3 style={{ marginTop: 20 }}>Which service does each step</h3>
        <p className="sv-help">
          Each of these can use your main service or a different one — they are set separately, so you can mix them.
          Leave a step on your main service unless you have a reason to change it.
        </p>
        {STEP_CHOICES.map((step) => (
          <div className="sv-field" key={step.id}>
            <label className="sv-label" htmlFor={`aiServiceFor-${step.id}`}>
              {step.label}
            </label>
            <select
              id={`aiServiceFor-${step.id}`}
              className="sv-input"
              value={status.settings.aiServiceFor[step.id]}
              disabled={saving}
              onChange={(e) =>
                void save({
                  aiServiceFor: { ...status.settings.aiServiceFor, [step.id]: e.target.value as StepService },
                })
              }
            >
              <option value="default">Use my main service ({serviceLabel(status.aiServices, status.settings.aiService)})</option>
              {status.aiServices
                .filter((s) => s.configured)
                .map((s) => (
                  <option key={s.service} value={s.service}>
                    {s.label}
                  </option>
                ))}
            </select>
            <p className="sv-help">{step.help}</p>
          </div>
        ))}
        {independentReview(status.settings) && (
          <p className="sv-muted" style={{ marginBottom: 0 }}>
            Your code will be reviewed by a service that did not write it. That is an independent check, and the
            reports say so.
          </p>
        )}
      </Card>

      <Card>
        <h2>Tell me when a build finishes</h2>
        <p className="sv-help">
          A build takes several minutes and keeps running even if you close this page. When it ends, SecureVibe shows a
          notification on this computer saying how it went. Nothing is sent anywhere.
        </p>
        <label className="sv-checkbox-row">
          <input
            type="checkbox"
            role="switch"
            aria-label="Desktop notification when a build finishes"
            aria-checked={status.settings.notifyOnFinish}
            checked={status.settings.notifyOnFinish}
            disabled={saving}
            onChange={(e) => void save({ notifyOnFinish: e.target.checked })}
          />
          <span>
            <strong>{status.settings.notifyOnFinish ? 'Notifications are on' : 'Notifications are off'}</strong>
          </span>
        </label>
      </Card>

      <Card>
        <h2>Virus scan of apps SecureVibe built</h2>
        <p className="sv-help">
          An app you upload is always checked against a database of known viruses and malicious documents (ClamAV,
          if it is installed on this computer). An app SecureVibe built is not, unless you switch this on: source
          code SecureVibe wrote is not where virus signatures find anything, and the scan takes minutes. Switch it
          on if you have put files into an app&apos;s folder yourself.
        </p>
        <label className="sv-checkbox-row">
          <input
            type="checkbox"
            role="switch"
            aria-label="Virus-scan apps SecureVibe built"
            aria-checked={status.settings.scanBuiltAppsForMalware}
            checked={status.settings.scanBuiltAppsForMalware}
            disabled={saving}
            onChange={(e) => void save({ scanBuiltAppsForMalware: e.target.checked })}
          />
          <span>
            <strong>{status.settings.scanBuiltAppsForMalware ? 'Built apps are virus-scanned on each check' : 'Only uploaded apps are virus-scanned'}</strong>
          </span>
        </label>
      </Card>

      <Card>
        <h2>Paper size for PDF reports</h2>
        <p className="sv-help">
          Every report can be downloaded as a PDF. Choose the paper it is laid out for: US Letter (8.5 by 11 inches) or
          A4 (the size used almost everywhere else). A PDF you download from the results page is made in the size chosen
          here, including for older checks. The PDF files stored with each check, which the hand-off pack and the
          all-apps zip carry, keep the size that was set when that check ran.
        </p>
        <label className="sv-label" htmlFor="pdfPageSize">
          Paper size
        </label>
        <select
          id="pdfPageSize"
          className="sv-select"
          value={status.settings.pdfPageSize}
          disabled={saving}
          onChange={(e) => void save({ pdfPageSize: e.target.value as 'letter' | 'a4' })}
        >
          <option value="letter">US Letter (8.5 x 11 in)</option>
          <option value="a4">A4 (210 x 297 mm)</option>
        </select>
      </Card>

      <Card>
        <h2>Extra AI scanner (experimental)</h2>
        <p className="sv-help">
          nano-analyzer is a free program by other people that reads your code with an AI service and says what it
          thinks could be a security problem. It is off, and switching it on is a real decision: your code is sent to
          OpenAI, and the reading is paid for from your own key there, not from your Claude credit. Its authors call it
          a research prototype built for a different kind of software, so much of what it says will be wrong.
        </p>
        <p className="sv-help">
          SecureVibe treats anything it says as a suggestion to look at, never as proof: those items cannot fail a
          build and nothing in your compliance report rests on them. Download it from{' '}
          <a href="https://github.com/weareaisle/nano-analyzer" target="_blank" rel="noreferrer noopener">
            github.com/weareaisle/nano-analyzer
          </a>{' '}
          and put the folder's full path below. It needs Python 3 on this computer.
        </p>
        <label className="sv-checkbox-row">
          <input
            type="checkbox"
            role="switch"
            aria-label="Use the experimental AI scanner"
            aria-checked={status.settings.nanoAnalyzer.enabled}
            checked={status.settings.nanoAnalyzer.enabled}
            disabled={saving}
            onChange={(e) => void save({ nanoAnalyzer: { ...status.settings.nanoAnalyzer, enabled: e.target.checked } })}
          />
          <span>
            <strong>{status.settings.nanoAnalyzer.enabled ? 'The extra AI scanner is on' : 'The extra AI scanner is off'}</strong>
          </span>
        </label>
        {status.settings.nanoAnalyzer.enabled && (
          <>
            <div className="sv-field">
              <label htmlFor="nano-path">Where you put the nano-analyzer folder</label>
              <input
                id="nano-path"
                type="text"
                defaultValue={status.settings.nanoAnalyzer.scriptPath}
                placeholder="/Users/you/nano-analyzer"
                disabled={saving}
                onBlur={(e) => void save({ nanoAnalyzer: { ...status.settings.nanoAnalyzer, scriptPath: e.target.value.trim() } })}
              />
              <p className="sv-help">The full path of the folder, or of its scan.py file.</p>
            </div>
            <div className="sv-field">
              <label htmlFor="nano-model">Which model it should use</label>
              <input
                id="nano-model"
                type="text"
                defaultValue={status.settings.nanoAnalyzer.model}
                disabled={saving}
                onBlur={(e) => void save({ nanoAnalyzer: { ...status.settings.nanoAnalyzer, model: e.target.value.trim() || 'gpt-5.4-nano' } })}
              />
              <p className="sv-help">
                The tool's own default is gpt-5.4-nano. A name with a slash in it is sent through OpenRouter instead,
                which needs an OpenRouter key.
              </p>
            </div>
            <p className={status.settings.nanoAnalyzer.keyPresent ? 'sv-muted' : 'sv-error-text'} style={{ marginBottom: 0 }}>
              {status.settings.nanoAnalyzer.keyPresent
                ? 'A key for that service is set, so the scanner will run with your next check.'
                : 'No key for that service is set yet, so the scanner will be skipped and the report will say so. Add it above under "Your AI service".'}
            </p>
          </>
        )}
      </Card>

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
        <p className="sv-muted">
          Builds now use <strong>{status.settings.effectiveModel}</strong>. Whatever you choose, a build never spends
          more than its spending limit: writing the app may use up to 55% of it, and the rest is kept for the code
          review and the fixes.
        </p>
        <p className="sv-muted" style={{ marginBottom: 0 }}>
          Two small steps always use the cheapest model of whichever service they are set to, whatever you choose
          here: scoring a piece of text for the moderation setting, and rewriting technical wording in plain
          language. Neither decides anything about your app's security, and both are checked by the code around
          them. Writing, reviewing, planning and second opinions always use the model you chose.
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
