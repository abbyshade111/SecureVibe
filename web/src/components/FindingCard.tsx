/**
 * One finding, as a person judges it: what it is, why it matters, where it is, the evidence the check actually
 * recorded, and the three things they can do about it — send it to the AI to fix, accept it as it stands, or say it
 * was never a real problem.
 *
 * It lives here rather than in a page because two pages show findings now: the Results page for one app, and the
 * security view across every app. A copy would drift, and the drift would be in the part that decides what an owner
 * is told about a risk.
 */
import { useState } from 'react';
import type { Finding } from '@shared/findings.js';
import { CodeViewer } from './CodeViewer';
import { Badge, CopyButton } from './Bits';

export function FindingCard({
  finding,
  projectId,
  canShowCode,
  onFix,
  onRecheck,
  recheckLabel,
  onAccept,
  onFalsePositive,
  selected,
  onSelect,
  appDir,
}: {
  finding: Finding;
  projectId: string;
  /** False for an app whose code SecureVibe does not hold (nothing to open). */
  canShowCode: boolean;
  onFix?: () => void;
  /**
   * "I have fixed it myself": runs the check that raised this finding again. There is deliberately no button that
   * marks a finding fixed — the check that found it is what decides whether it is gone, and a person saying so
   * would put a claim in the reports that nothing stands behind.
   */
  onRecheck?: () => void;
  recheckLabel?: string;
  onAccept?: (reason: string) => Promise<void>;
  /** Marks the finding as mistaken, with the reason a person gives for saying so. */
  onFalsePositive?: (reason: string) => Promise<void>;
  /** When given, the finding can be ticked and fixed together with the others. */
  selected?: boolean;
  onSelect?: (checked: boolean) => void;
  /** The folder the app is in, so the file can be shown as a full path a developer can open. */
  appDir?: string;
}) {
  const [showCode, setShowCode] = useState(false);
  const [accepting, setAccepting] = useState(false);
  const [disputing, setDisputing] = useState(false);
  const [disputeReason, setDisputeReason] = useState('');
  const [read, setRead] = useState(false);
  const [reason, setReason] = useState('');
  /**
   * A decision that did not save. It used to be swallowed: the promise was voided, the panel stayed open with no
   * explanation, and a person could believe they had recorded something that was never recorded. Saying so is the
   * least a page owes someone who has just made a judgement about a risk.
   */
  const [decisionError, setDecisionError] = useState<string | null>(null);

  /** Runs a decision, closes its panel when it saves, and says so plainly when it does not. */
  const decide = (action: (reason: string) => Promise<void>, value: string, close: () => void): void => {
    setDecisionError(null);
    void action(value).then(
      () => close(),
      (err: unknown) => setDecisionError(err instanceof Error ? err.message : 'That could not be saved.'),
    );
  };
  const severityTone = finding.severity === 'critical' || finding.severity === 'high' ? 'bad' : finding.severity === 'medium' ? 'warn' : 'neutral';

  return (
    <div className="sv-finding">
      <div className="sv-row-between">
        {onSelect ? (
          <label className="sv-checkbox-row" style={{ margin: 0 }}>
            <input type="checkbox" checked={selected ?? false} onChange={(e) => onSelect(e.target.checked)} aria-label={`Include "${finding.title}" in the fixes`} />
            <strong>{finding.title}</strong>
          </label>
        ) : (
          <strong>{finding.title}</strong>
        )}
        <Badge tone={severityTone}>{finding.severity}</Badge>
      </div>
      <p className="sv-muted">{finding.description}</p>
      <p>
        <strong>Why it matters:</strong> {finding.impact}
      </p>
      {finding.location?.file && (
        <p className="sv-faint">
          {finding.location.file}
          {finding.location.line ? `:${finding.location.line}` : ''}
          {canShowCode && (
            <>
              {' '}
              <button type="button" className="sv-link" onClick={() => setShowCode((v) => !v)} aria-expanded={showCode}>
                {showCode ? 'Hide the code' : 'Show me this code'}
              </button>
            </>
          )}
          {/* Two ways to reach the file, for two kinds of reader: the link opens it here; the button hands a developer
              the full path for an editor. Seen live, a full path row under every finding outweighed the finding itself,
              so it is a small button on the same line instead. */}
          {appDir && (
            <>
              {' '}
              <CopyButton text={`${appDir}/${finding.location.file}`} label="Copy the full path" />
            </>
          )}
        </p>
      )}
      {/* Checks that probe the running app report an address rather than a file, and without it a page full of
          these reads as the same problem over and over: nineteen identical cards, no way to tell them apart or
          judge any one of them. */}
      {!finding.location?.file && finding.location?.endpoint && (
        <p className="sv-faint">
          <strong>Where:</strong> {finding.location.endpoint}
        </p>
      )}
      {showCode && finding.location?.file && (
        <CodeViewer
          projectId={projectId}
          path={finding.location.file}
          {...(finding.location.line ? { line: finding.location.line } : {})}
          onClose={() => setShowCode(false)}
        />
      )}
      <p>{finding.remediation.summary}</p>

      {/* Everything the check actually saw. It was all recorded already and none of it was shown, so a person was
          asked to judge a finding from a sentence that reads the same whatever caused it. Folded away by default:
          an owner does not need it, and someone deciding whether a finding is real cannot do without it. */}
      <details className="sv-details">
        <summary>The evidence behind this</summary>
        {finding.evidence && <p className="sv-muted" style={{ whiteSpace: 'pre-wrap' }}>{finding.evidence}</p>}
        {finding.location?.snippet && <pre className="sv-pre">{finding.location.snippet}</pre>}
        {finding.location?.requestExcerpt && (
          <>
            <p className="sv-label" style={{ marginBottom: 4 }}>What was sent to the app</p>
            <pre className="sv-pre">{finding.location.requestExcerpt}</pre>
          </>
        )}
        {finding.location?.responseExcerpt && (
          <>
            <p className="sv-label" style={{ marginBottom: 4 }}>What the app answered</p>
            <pre className="sv-pre">{finding.location.responseExcerpt}</pre>
          </>
        )}
        {finding.remediation.steps.length > 0 && (
          <>
            <p className="sv-label" style={{ marginBottom: 4 }}>How to fix it</p>
            <ol style={{ marginTop: 0 }}>
              {finding.remediation.steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          </>
        )}
        {finding.remediation.example && <pre className="sv-pre">{finding.remediation.example}</pre>}
        <p className="sv-faint" style={{ marginBottom: 0 }}>
          Found by {finding.tool?.name ?? finding.source} ({finding.ruleId}); confidence {finding.confidence}
          {finding.severityBase && finding.severityBase !== finding.severity && (
            <> ; raised from {finding.severityBase}{finding.adjustmentReason ? `: ${finding.adjustmentReason}` : ''}</>
          )}
          {finding.cwe.length > 0 && <> ; {finding.cwe.join(', ')}</>}
          {[...finding.mappings.asvs, ...finding.mappings.aisvs, ...finding.mappings.sbd].length > 0 && (
            <> ; counts against {[...finding.mappings.asvs, ...finding.mappings.aisvs, ...finding.mappings.sbd].join(', ')}</>
          )}
        </p>
        {finding.remediation.references.length > 0 && (
          <p className="sv-faint" style={{ marginBottom: 0 }}>
            {finding.remediation.references.map((href, i) => (
              <span key={href}>
                {i > 0 && ' · '}
                <a href={href} target="_blank" rel="noreferrer noopener">
                  {href.replace(/^https?:\/\//, '').slice(0, 60)}
                </a>
              </span>
            ))}
          </p>
        )}
      </details>

      {decisionError && (
        <p className="sv-error" role="alert">
          That was not saved: {decisionError}
        </p>
      )}
      {(onFix || onRecheck || onAccept || onFalsePositive) && (
        <div className="sv-row">
          {onFix && (
            <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={onFix}>
              Ask AI to fix this one
            </button>
          )}
          {onRecheck && (
            <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={onRecheck}>
              {recheckLabel ?? "I've fixed it — check again"}
            </button>
          )}
          {onAccept && !accepting && (
            <button type="button" className="sv-btn-link" onClick={() => setAccepting(true)}>
              I understand, leave it
            </button>
          )}
          {/* Deliberately a separate button from "leave it". They mean opposite things: one says the finding is
              mistaken, the other says the risk is real and being carried on purpose. Recording a mistake as an
              accepted risk overstates what the app is actually carrying, which the compliance report then repeats. */}
          {onFalsePositive && !disputing && (
            <button type="button" className="sv-btn-link" onClick={() => setDisputing(true)}>
              This is not a real problem
            </button>
          )}
        </div>
      )}
      {disputing && onFalsePositive && (
        <div className="sv-card" style={{ margin: '12px 0 0', background: 'var(--color-bg-subtle)' }}>
          <p style={{ marginTop: 0 }}>
            Marking this as a mistake removes it from your results and from your compliance report. Say why, so the
            next person to read this — or the next check that raises it again — has your reasoning.
          </p>
          <input
            className="sv-input"
            placeholder="Why is this not a real problem?"
            value={disputeReason}
            onChange={(e) => setDisputeReason(e.target.value)}
          />
          <div className="sv-row" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="sv-btn sv-btn-sm"
              disabled={disputeReason.trim().length < 3}
              onClick={() => decide(onFalsePositive, disputeReason, () => setDisputing(false))}
            >
              Mark as not a real problem
            </button>
            <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => setDisputing(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {accepting && onAccept && (
        <div className="sv-card" style={{ margin: '12px 0 0', background: 'var(--color-bg-subtle)' }}>
          <label className="sv-checkbox-row">
            <input type="checkbox" checked={read} onChange={(e) => setRead(e.target.checked)} />
            <span>I have read and accept: {finding.impact}</span>
          </label>
          <input
            className="sv-input"
            style={{ marginTop: 8 }}
            placeholder="Why are you leaving this as-is? (optional)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <div className="sv-row" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="sv-btn sv-btn-sm"
              disabled={!read}
              onClick={() => decide(onAccept, reason, () => setAccepting(false))}
            >
              Confirm
            </button>
            <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => setAccepting(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
