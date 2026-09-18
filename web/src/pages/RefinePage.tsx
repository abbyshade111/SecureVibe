import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import type { Project } from '@shared/project.js';
import { requestRefinement, saveRefinementDecisions } from '../lib/api';
import { useProject } from '../hooks/useProject';
import { useStatus } from '../hooks/useStatus';
import { Card, ErrorNotice, LoadingScreen } from '../components/Bits';

type Refinement = NonNullable<Project['refinement']>;

/**
 * "Let's check a few things": Claude reads the answers, asks what is still unclear and suggests features. Every
 * answer and every suggestion is the owner's choice; nothing is applied until they say so.
 */
export function RefinePage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { project, loading, error, reload } = useProject(id);
  const { status } = useStatus();
  const [refinement, setRefinement] = useState<Refinement | null>(null);
  const [asking, setAsking] = useState(false);
  const [saving, setSaving] = useState(false);
  const [askError, setAskError] = useState<string | null>(null);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [wanted, setWanted] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (project?.refinement && !refinement) setRefinement(project.refinement);
  }, [project, refinement]);

  const summaryHref = `/projects/${id}/summary`;

  async function ask() {
    if (!id) return;
    setAsking(true);
    setAskError(null);
    try {
      const r = await requestRefinement(id);
      setRefinement(r.refinement);
      setAnswers({});
      setWanted({});
    } catch (e) {
      setAskError(e instanceof Error ? e.message : 'Could not prepare the questions.');
    } finally {
      setAsking(false);
    }
  }

  async function apply(dismiss = false) {
    if (!id) return;
    setSaving(true);
    setAskError(null);
    try {
      await saveRefinementDecisions(id, {
        answers: Object.entries(answers)
          .filter(([, v]) => v !== '')
          .map(([questionId, value]) => ({ questionId, value })),
        features: Object.entries(wanted).map(([suggestionId, accepted]) => ({ suggestionId, accepted })),
        ...(dismiss ? { dismiss: true } : {}),
      });
      await reload();
      navigate(summaryHref);
    } catch (e) {
      setAskError(e instanceof Error ? e.message : 'Could not save your answers.');
      setSaving(false);
    }
  }

  if (loading) return <LoadingScreen label="Loading…" />;
  if (error || !project || !id) return <ErrorNotice message={error ?? 'Could not load this app.'} />;

  const previewMode = status?.llm.previewMode === true;
  const questions = refinement?.questions ?? [];
  const features = refinement?.features ?? [];
  const answered = questions.filter((q) => answers[q.id]).length;
  const chosen = Object.values(wanted).filter(Boolean).length;

  return (
    <div className="sv-stack">
      <h1>Let&apos;s check a few things</h1>

      {!refinement && (
        <Card>
          <p>
            Before the design is put together, Claude can read your answers and come back with a few questions about
            anything that is unclear, plus features it thinks your app needs. You decide what to accept.
          </p>
          <ul className="sv-muted">
            <li>Only your answers are sent — the same information the design is built from.</li>
            <li>It costs a few cents of AI credit and takes under a minute.</li>
            <li>Nothing changes unless you choose it.</li>
          </ul>
          {previewMode && (
            <div className="sv-banner sv-banner-warn">
              <p style={{ marginBottom: 0 }}>
                This needs AI, which is switched off. <Link to="/settings">Turn AI on in Settings</Link>, or carry on to
                the design.
              </p>
            </div>
          )}
          {askError && <ErrorNotice message={askError} />}
          <div className="sv-row" style={{ flexWrap: 'wrap' }}>
            <button type="button" className="sv-btn" disabled={asking || previewMode} onClick={() => void ask()}>
              {asking ? 'Reading your answers…' : 'Ask Claude about my answers'}
            </button>
            <Link className="sv-btn sv-btn-secondary" to={summaryHref}>
              Skip, go to the design
            </Link>
          </div>
        </Card>
      )}

      {refinement && refinement.performedBy === 'skipped' && (
        <Card>
          <p>{refinement.summary}</p>
          <div className="sv-row">
            <button type="button" className="sv-btn sv-btn-secondary" disabled={asking} onClick={() => void ask()}>
              Try again
            </button>
            <Link className="sv-btn" to={summaryHref}>
              Go to the design
            </Link>
          </div>
        </Card>
      )}

      {refinement && refinement.performedBy === 'claude' && (
        <>
          <Card>
            <p style={{ marginBottom: 0 }}>{refinement.summary}</p>
          </Card>

          {questions.length > 0 && (
            <Card>
              <h2>Questions about your app</h2>
              <p className="sv-muted">Answer what you can. Anything you leave blank stays as it is.</p>
              {questions.map((q) => (
                <div key={q.id} className="sv-field">
                  <p style={{ marginBottom: 4 }}>
                    <strong>{q.question}</strong>
                  </p>
                  <p className="sv-help">{q.why}</p>
                  {q.options.length > 0 ? (
                    <div className="sv-option-list">
                      {q.options.map((o) => (
                        <label className="sv-option" key={o.value} data-checked={answers[q.id] === o.value}>
                          <input
                            type="radio"
                            name={q.id}
                            checked={answers[q.id] === o.value}
                            onChange={() => setAnswers((prev) => ({ ...prev, [q.id]: o.value }))}
                          />
                          <span className="sv-option-body">
                            <span className="sv-option-label">{o.label}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                  ) : (
                    <input
                      className="sv-input"
                      maxLength={400}
                      placeholder="Your answer (optional)"
                      value={answers[q.id] ?? ''}
                      onChange={(e) => setAnswers((prev) => ({ ...prev, [q.id]: e.target.value }))}
                    />
                  )}
                  {q.field === undefined && q.options.length === 0 && (
                    <p className="sv-faint">This one is for you to think about; your answer is kept with the app as a note.</p>
                  )}
                </div>
              ))}
            </Card>
          )}

          {features.length > 0 && (
            <Card>
              <h2>Features you might want</h2>
              <p className="sv-muted">Tick the ones to add. They become part of what SecureVibe builds.</p>
              {features.map((f) => (
                <label className="sv-checkbox-row" key={f.id} style={{ alignItems: 'flex-start', marginBottom: 12 }}>
                  <input
                    type="checkbox"
                    checked={wanted[f.id] === true}
                    onChange={(e) => setWanted((prev) => ({ ...prev, [f.id]: e.target.checked }))}
                  />
                  <span>
                    <strong>{f.title}</strong>
                    <br />
                    <span className="sv-muted">{f.detail}</span>
                  </span>
                </label>
              ))}
            </Card>
          )}

          {askError && <ErrorNotice message={askError} />}
          <Card>
            <div className="sv-row-between" style={{ flexWrap: 'wrap', gap: 12 }}>
              <p className="sv-muted" style={{ marginBottom: 0 }}>
                {answered} of {questions.length} answered · {chosen} feature{chosen === 1 ? '' : 's'} to add
              </p>
              <div className="sv-row" style={{ flexWrap: 'wrap' }}>
                <button type="button" className="sv-btn" disabled={saving} onClick={() => void apply()}>
                  {saving ? 'Saving…' : 'Save and go to the design'}
                </button>
                <button type="button" className="sv-btn sv-btn-secondary" disabled={saving} onClick={() => void apply(true)}>
                  Leave the rest, go to the design
                </button>
              </div>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
