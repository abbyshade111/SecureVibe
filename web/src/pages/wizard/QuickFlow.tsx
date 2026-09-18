import { useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useProject } from '../../hooks/useProject';
import { useWizardCopy } from '../../hooks/useWizardCopy';
import { deriveDesign, quickInfer } from '../../lib/api';
import { getPath, setPath } from '../../lib/paths';
import { ErrorNotice, LoadingScreen } from '../../components/Bits';
import { QuestionInput, WhyAndChanges } from './QuestionRenderer';
import type { WizardCommonCopy, WizardQuestion } from '../../lib/wizardCopyTypes';
import type { QuickInferResponse } from '@shared/api.js';

type Phase = 'intro' | 'high-consequence' | 'inferring' | 'confirm' | 'needs-confirmation' | 'finishing';

const HIGH_CONSEQUENCE_IDS = ['data.categories', 'users.audience', 'deployment.target'];

function describeValue(value: unknown): string {
  if (value === undefined || value === null || value === '') return 'nothing';
  if (Array.isArray(value)) return value.length ? value.map(String).join(', ') : 'nothing';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return String(value);
}

function ConfirmScreen({
  question,
  fieldId,
  value,
  common,
  index,
  total,
  onConfirm,
  onChangeValue,
}: {
  question: WizardQuestion | undefined;
  fieldId: string;
  value: unknown;
  common: WizardCommonCopy;
  index: number;
  total: number;
  onConfirm: () => void;
  onChangeValue: (v: unknown) => void;
}) {
  const [editing, setEditing] = useState(false);
  return (
    <div className="sv-stack">
      <p className="sv-faint">
        Check what we assumed ({index + 1} of {total})
      </p>
      <div className="sv-card">
        <h2>{question?.title ?? fieldId}</h2>
        <p>
          {common.assumptionPrefix}: <strong>{describeValue(value)}</strong>
        </p>
        {question && !editing && <WhyAndChanges question={question} value={value} common={common} />}
        {editing && question && (
          <div style={{ marginTop: 12 }}>
            <QuestionInput question={question} value={value} onChange={onChangeValue} />
          </div>
        )}
        <div className="sv-row" style={{ marginTop: 16 }}>
          {question && (
            <button type="button" className="sv-btn-link" onClick={() => setEditing((v) => !v)}>
              {editing ? 'Done editing' : 'Change this'}
            </button>
          )}
        </div>
      </div>
      <div className="sv-row-between">
        <span />
        <button type="button" className="sv-btn" onClick={onConfirm}>
          {editing ? 'Use this answer' : 'That is right, continue'}
        </button>
      </div>
    </div>
  );
}

export function QuickFlow({ projectId }: { projectId: string }) {
  const { project, loading, error, replaceProfile } = useProject(projectId);
  const { copy, loading: copyLoading } = useWizardCopy();
  const navigate = useNavigate();

  const [phase, setPhase] = useState<Phase>('intro');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [hcIndex, setHcIndex] = useState(0);
  const [known, setKnown] = useState<{ dataCategories: string[]; audience: string; deploymentTarget: string }>({
    dataCategories: [],
    audience: '',
    deploymentTarget: '',
  });
  const [result, setResult] = useState<QuickInferResponse | null>(null);
  const [confirmIndex, setConfirmIndex] = useState(0);
  const [ncIndex, setNcIndex] = useState(0);
  const [ncAnswers, setNcAnswers] = useState<Record<string, string>>({});
  const [busyError, setBusyError] = useState<string | null>(null);
  const [workingProfile, setWorkingProfile] = useState<QuickInferResponse['profile'] | null>(null);
  const finishStarted = useRef(false);

  if (loading || copyLoading) return <LoadingScreen label="Loading…" />;
  if (error || !project) return <ErrorNotice message={error ?? 'Could not load this app.'} />;
  if (!copy) return <ErrorNotice message="Could not load the wizard questions." />;

  const findQuestion = (id: string) => copy.questions.find((q) => q.id === id);

  async function runInference() {
    setPhase('inferring');
    setBusyError(null);
    try {
      const res = await quickInfer(projectId, {
        description,
        name: name || undefined,
        known: {
          dataCategories: known.dataCategories,
          audience: known.audience,
          deploymentTarget: known.deploymentTarget,
        },
      });
      setResult(res);
      setWorkingProfile(res.profile);
      setConfirmIndex(0);
      setNcIndex(0);
      setPhase(res.inferredFields.length > 0 ? 'confirm' : res.needsConfirmation.length > 0 ? 'needs-confirmation' : 'finishing');
    } catch (e) {
      setBusyError(
        e instanceof Error ? e.message : 'Could not work out the rest of your app from that description.',
      );
      setPhase('high-consequence');
    }
  }

  async function finish(finalProfile: QuickInferResponse['profile']) {
    setPhase('finishing');
    setBusyError(null);
    const inferredFields = result?.inferredFields ?? [];
    const withMeta = {
      ...finalProfile,
      meta: { ...finalProfile.meta, mode: 'quick' as const, confirmed: true, inferredFields },
    };
    const saved = await replaceProfile(withMeta, 5);
    if (!saved) {
      setBusyError('Could not save your app. Please try again.');
      setPhase('needs-confirmation');
      return;
    }
    try {
      await deriveDesign(projectId);
    } catch (e) {
      setBusyError(
        e instanceof Error
          ? e.message
          : 'Could not put together your design. You can try again from the summary page.',
      );
    }
    navigate(`/projects/${projectId}/summary`);
  }

  if (phase === 'intro') {
    const nameQ = findQuestion('app.name');
    const descQ = findQuestion('app.description');
    return (
      <div className="sv-stack">
        <h1>Describe your app</h1>
        <p className="sv-muted">
          Tell us about it in your own words. We will guess the rest and show you every guess so you can confirm or
          change it — guesses can only make the app safer, never less safe.
        </p>
        <div className="sv-card">
          <div className="sv-field">
            <label className="sv-label" htmlFor="qname">
              {nameQ?.title ?? 'Name your app'}
            </label>
            <input
              id="qname"
              className="sv-input"
              value={name}
              maxLength={60}
              placeholder={nameQ?.placeholder}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </div>
          <div className="sv-field">
            <label className="sv-label" htmlFor="qdesc">
              {descQ?.title ?? 'Describe your app'}
            </label>
            <p className="sv-help">{descQ?.helpText}</p>
            <p className="sv-faint">{copy.common.freeTextNotice}</p>
            <textarea
              id="qdesc"
              className="sv-textarea"
              style={{ minHeight: 160 }}
              value={description}
              maxLength={4000}
              placeholder={descQ?.placeholder}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <button
            type="button"
            className="sv-btn"
            disabled={!name.trim() || description.trim().length < 10}
            onClick={() => setPhase('high-consequence')}
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  if (phase === 'high-consequence') {
    const qid = HIGH_CONSEQUENCE_IDS[hcIndex];
    const question = qid ? findQuestion(qid) : undefined;
    if (!question) {
      return <ErrorNotice message="Could not load one of the questions." />;
    }
    const fieldKey = qid === 'data.categories' ? 'dataCategories' : qid === 'users.audience' ? 'audience' : 'deploymentTarget';
    const value = fieldKey === 'dataCategories' ? known.dataCategories : known[fieldKey];
    const answered = fieldKey === 'dataCategories' ? known.dataCategories.length > 0 : !!known[fieldKey];
    return (
      <div className="sv-stack">
        <p className="sv-faint">
          A few important questions ({hcIndex + 1} of {HIGH_CONSEQUENCE_IDS.length})
        </p>
        <div className="sv-card">
          <h2>{question.title}</h2>
          <p>{question.question}</p>
          {question.helpText && <p className="sv-help">{question.helpText}</p>}
          <QuestionInput
            question={question}
            value={value}
            onChange={(v) =>
              setKnown((prev) =>
                fieldKey === 'dataCategories'
                  ? { ...prev, dataCategories: v as string[] }
                  : { ...prev, [fieldKey]: v as string },
              )
            }
          />
          <WhyAndChanges question={question} value={value} common={copy.common} />
        </div>
        {busyError && <ErrorNotice message={busyError} />}
        <div className="sv-row-between">
          <button
            type="button"
            className="sv-btn sv-btn-secondary"
            onClick={() => (hcIndex > 0 ? setHcIndex(hcIndex - 1) : setPhase('intro'))}
          >
            Back
          </button>
          <button
            type="button"
            className="sv-btn"
            disabled={!answered}
            onClick={() => {
              if (hcIndex < HIGH_CONSEQUENCE_IDS.length - 1) setHcIndex(hcIndex + 1);
              else void runInference();
            }}
          >
            {hcIndex < HIGH_CONSEQUENCE_IDS.length - 1 ? 'Next' : 'Work out the rest'}
          </button>
        </div>
      </div>
    );
  }

  if (phase === 'inferring' || !result || !workingProfile) {
    return <LoadingScreen label="Working out the rest of your app from your description…" />;
  }

  if (phase === 'confirm') {
    const fieldId = result.inferredFields[confirmIndex];
    if (!fieldId) {
      return <LoadingScreen label="Almost there…" />;
    }
    const question = findQuestion(fieldId);
    const currentValue = getPath(workingProfile, fieldId);
    return (
      <ConfirmScreen
        key={fieldId}
        fieldId={fieldId}
        question={question}
        value={currentValue}
        common={copy.common}
        index={confirmIndex}
        total={result.inferredFields.length}
        onConfirm={() => {
          if (confirmIndex < result.inferredFields.length - 1) {
            setConfirmIndex(confirmIndex + 1);
          } else {
            setPhase(result.needsConfirmation.length > 0 ? 'needs-confirmation' : 'finishing');
          }
        }}
        onChangeValue={(v) => {
          setWorkingProfile((prev) => (prev ? setPath(prev, fieldId, v) : prev));
        }}
      />
    );
  }

  if (phase === 'needs-confirmation') {
    const nc = result.needsConfirmation[ncIndex];
    if (!nc) {
      return <LoadingScreen label="Putting your design together…" />;
    }
    return (
      <div className="sv-stack">
        <p className="sv-faint">
          We need your answer ({ncIndex + 1} of {result.needsConfirmation.length})
        </p>
        <div className="sv-card">
          <h2>{nc.field}</h2>
          <p>{nc.question}</p>
          {nc.evidence && <p className="sv-faint">From your description: “{nc.evidence}”</p>}
          <textarea
            className="sv-textarea"
            value={ncAnswers[nc.field] ?? ''}
            onChange={(e) => setNcAnswers((prev) => ({ ...prev, [nc.field]: e.target.value }))}
          />
        </div>
        <div className="sv-row-between">
          <button
            type="button"
            className="sv-btn sv-btn-secondary"
            onClick={() => setNcIndex(Math.max(0, ncIndex - 1))}
          >
            Back
          </button>
          <button
            type="button"
            className="sv-btn"
            disabled={!ncAnswers[nc.field]?.trim()}
            onClick={() => {
              if (ncIndex < result.needsConfirmation.length - 1) {
                setNcIndex(ncIndex + 1);
              } else {
                setPhase('finishing');
              }
            }}
          >
            {ncIndex < result.needsConfirmation.length - 1 ? 'Next' : 'Continue'}
          </button>
        </div>
      </div>
    );
  }

  if (phase === 'finishing' && workingProfile && !finishStarted.current) {
    finishStarted.current = true;
    void finish(workingProfile);
  }
  return <LoadingScreen label="Putting your design together…" />;
}
