import { useState } from 'react';
import { safeExternalHref } from '../lib/links';
import type { StatusResponse } from '@shared/api.js';
import { saveAiKey } from '../lib/api';
import { Card, ErrorNotice } from './Bits';

type Service = StatusResponse['aiServices'][number];

/** Settings → "Your AI service": paste a key, see which services have one, remove one. */
export function AiKeys({ services, onChanged }: { services: Service[]; onChanged: (next: Service[]) => void }) {
  const [chosen, setChosen] = useState<Service['service']>(services.find((s) => s.configured)?.service ?? 'anthropic');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const current = services.find((s) => s.service === chosen);

  async function save(remove = false) {
    setBusy(true);
    setError(null);
    setSaved(null);
    try {
      onChanged(await saveAiKey(remove ? { service: chosen, remove: true } : { service: chosen, key }));
      setKey('');
      setSaved(remove ? 'The key was removed.' : 'The key was saved and is in use straight away.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the key.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <h2>Your AI service</h2>
      <p className="sv-help">
        SecureVibe uses your own account with an AI service, so you pay that service directly for what you use. A key you
        paste here is written to the <code className="sv-code">.env</code> file next to SecureVibe, readable only by you.
        It is never shown again, never written to a log or a report, and never sent to an AI.
      </p>

      <div className="sv-field">
        <span className="sv-label">Service</span>
        <div className="sv-option-list">
          {services.map((s) => (
            <label className="sv-option" key={s.service} data-checked={chosen === s.service}>
              <input type="radio" name="aiService" checked={chosen === s.service} onChange={() => setChosen(s.service)} />
              <span className="sv-option-body">
                <span className="sv-option-label">
                  {s.label}
                  {s.configured ? ` — key ending ${s.endsWith} is in place` : ' — no key yet'}
                </span>
                <span className="sv-help">
                  {s.usableForBuilds
                    ? 'SecureVibe builds and checks apps with this service.'
                    : 'Not used for builds yet: SecureVibe stores the key, and support for building with this service is being added.'}
                  {s.fromEnvironment ? ' This key comes from your environment, so removing it here will not take effect.' : ''}
                </span>
              </span>
            </label>
          ))}
        </div>
      </div>

      <div className="sv-field">
        <label className="sv-label" htmlFor="aiKey">
          {current?.configured ? 'Replace the key' : 'Paste the key'}
        </label>
        <p className="sv-help">
          Get a key from{' '}
          {safeExternalHref(current?.consoleUrl) ? (
            <a href={safeExternalHref(current?.consoleUrl)} target="_blank" rel="noreferrer noopener">
              {current?.label}
            </a>
          ) : (
            current?.label
          )}
          . Treat it like a password: anyone with it can spend money on your account.
        </p>
        <input
          id="aiKey"
          className="sv-input"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={key}
          placeholder={current?.configured ? '••••••••' : 'sk-…'}
          onChange={(e) => setKey(e.target.value)}
        />
      </div>

      {error && <ErrorNotice message={error} />}
      {saved && (
        <div className="sv-banner sv-banner-good">
          <p style={{ marginBottom: 0 }}>{saved}</p>
        </div>
      )}
      <div className="sv-row" style={{ flexWrap: 'wrap' }}>
        <button type="button" className="sv-btn" disabled={busy || key.trim() === ''} onClick={() => void save()}>
          {busy ? 'Saving…' : 'Save the key'}
        </button>
        {current?.configured && !current.fromEnvironment && (
          <button type="button" className="sv-btn sv-btn-secondary" disabled={busy} onClick={() => void save(true)}>
            Remove the key
          </button>
        )}
      </div>
    </Card>
  );
}
