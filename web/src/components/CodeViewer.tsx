import { useEffect, useRef, useState } from 'react';
import type { AppFileResponse } from '@shared/api.js';
import { getAppFile } from '../lib/api';
import { CopyButton, ErrorNotice } from './Bits';

const ORIGIN_LABEL: Record<string, string> = {
  template: 'This file comes from the SecureVibe starter code.',
  expanded: 'This file was made from your answers.',
  'ai-generated': 'Claude wrote this file.',
  'ai-fixed': 'Claude changed this file while fixing something.',
  user: 'This file was changed outside SecureVibe.',
};

/** How many lines of code to show around the line a finding points at. */
const CONTEXT = 20;

/**
 * Shows one file of the generated app, with the line a finding points at marked. The code is read from the app
 * folder on this computer; nothing is sent anywhere and nothing can be edited here.
 */
export function CodeViewer({
  projectId,
  path,
  line,
  onClose,
}: {
  projectId: string;
  path: string;
  line?: number;
  onClose: () => void;
}) {
  const [file, setFile] = useState<AppFileResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [whole, setWhole] = useState(false);
  const marked = useRef<HTMLSpanElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setFile(null);
    getAppFile(projectId, path)
      .then((f) => {
        if (!cancelled) setFile(f);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Could not open that file.');
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, path]);

  useEffect(() => {
    marked.current?.scrollIntoView({ block: 'center' });
  }, [file, whole]);

  if (error) return <ErrorNotice title="Could not show the code" message={error} />;
  if (!file) return <p className="sv-muted">Opening {path}…</p>;

  if (file.notShown) {
    return (
      <div className="sv-codeview">
        <p style={{ margin: 0 }}>{file.notShown}</p>
      </div>
    );
  }

  const lines = file.text.split('\n');
  const focus = line && line <= lines.length ? line : undefined;
  const from = whole || !focus ? 1 : Math.max(1, focus - CONTEXT);
  const to = whole || !focus ? lines.length : Math.min(lines.length, focus + CONTEXT);
  const shown = lines.slice(from - 1, to);
  const hidden = lines.length - shown.length;

  return (
    <div className="sv-codeview">
      <div className="sv-row-between" style={{ flexWrap: 'wrap', gap: 8 }}>
        <div>
          <code className="sv-code">{file.path}</code>
          {focus && <span className="sv-faint"> — line {focus}</span>}
          {file.origin && ORIGIN_LABEL[file.origin] && <div className="sv-faint">{ORIGIN_LABEL[file.origin]}</div>}
        </div>
        <div className="sv-row" style={{ gap: 8 }}>
          <CopyButton text={`${file.appDir}/${file.path}`} label="Copy the full path" />
          <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={onClose}>
            Hide the code
          </button>
        </div>
      </div>

      <pre className="sv-codeview-body" tabIndex={0} aria-label={`The contents of ${file.path}`}>
        <code>
          {shown.map((text, i) => {
            const number = from + i;
            const isFocus = number === focus;
            return (
              <span
                key={number}
                className={isFocus ? 'sv-codeview-line sv-codeview-line-focus' : 'sv-codeview-line'}
                ref={isFocus ? marked : undefined}
              >
                <span className="sv-codeview-number" aria-hidden="true">
                  {number}
                </span>
                <span className="sv-codeview-text">{text === '' ? ' ' : text}</span>
              </span>
            );
          })}
        </code>
      </pre>

      <p className="sv-faint" style={{ margin: '8px 0 0' }}>
        {hidden > 0 && !whole && (
          <>
            {hidden} more line{hidden === 1 ? '' : 's'} in this file.{' '}
            <button type="button" className="sv-link" onClick={() => setWhole(true)}>
              Show the whole file
            </button>
            .{' '}
          </>
        )}
        {whole && focus && (
          <>
            <button type="button" className="sv-link" onClick={() => setWhole(false)}>
              Show just the part around line {focus}
            </button>
            .{' '}
          </>
        )}
        {file.truncated && <>Only the first {lines.length} lines are shown; the file is longer. </>}
        This is the file as it is on this computer right now. To change it, open it in a code editor — SecureVibe does
        not edit it here.
      </p>
    </div>
  );
}
