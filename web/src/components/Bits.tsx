import { useState, type ReactNode } from 'react';

export type BadgeTone = 'good' | 'warn' | 'bad' | 'info' | 'neutral';

/** Always pairs an icon shape with a word — status is never color alone. */
export function Badge({ tone, children }: { tone: BadgeTone; children: ReactNode }) {
  const icon: Record<BadgeTone, string> = { good: '✓', warn: '▲', bad: '✕', info: 'ℹ', neutral: '●' };
  return (
    <span className={`sv-badge sv-badge-${tone}`}>
      <span aria-hidden="true">{icon[tone]}</span>
      {children}
    </span>
  );
}

export function LoadingScreen({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="sv-loading-screen" role="status" aria-live="polite">
      <span className="sv-spinner" aria-hidden="true" />
      <span style={{ marginLeft: 12 }}>{label}</span>
    </div>
  );
}

export function ErrorNotice({ title = 'Something went wrong', message }: { title?: string; message: string }) {
  return (
    <div className="sv-banner sv-banner-bad" role="alert">
      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}

export function ProgressBar({ percent, label }: { percent: number; label: string }) {
  const clamped = Math.max(0, Math.min(100, percent));
  return (
    <div>
      <div
        className="sv-progress-track"
        role="progressbar"
        aria-valuenow={Math.round(clamped)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
      >
        <div className="sv-progress-fill" style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="sv-btn sv-btn-secondary sv-btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1800);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? 'Copied' : label}
    </button>
  );
}

export function CopyRow({ text }: { text: string }) {
  return (
    <div className="sv-copy-row">
      <code>{text}</code>
      <CopyButton text={text} />
    </div>
  );
}

export function Card({ children, id }: { children: ReactNode; id?: string }) {
  return (
    <section className="sv-card" id={id}>
      {children}
    </section>
  );
}
