import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router';
import { useScrollToTop } from '../../hooks/useScrollToTop';
import type { WizardQuestion } from '../../lib/wizardCopyTypes';
import { useProject } from '../../hooks/useProject';
import { useWizardCopy } from '../../hooks/useWizardCopy';
import { getPath } from '../../lib/paths';
import { QUESTION_STEP_IDS } from '../../lib/wizardSteps';
import { ErrorNotice, LoadingScreen } from '../../components/Bits';
import { NotSureButton, QuestionInput, WhyAndChanges } from './QuestionRenderer';
import { QuickFlow } from './QuickFlow';


function isAnswered(question: WizardQuestion, value: unknown): boolean {
  if (!question.required) return true;
  if (value === undefined || value === null) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

export function WizardPage() {
  const { id, step } = useParams<{ id: string; step: string }>();
  const navigate = useNavigate();
  const { project, loading, error, setField, setWizardStep, saving, saveError, savedAt, unsaved, flush } = useProject(id);
  const { copy, loading: copyLoading } = useWizardCopy();
  const [qIndex, setQIndex] = useState(0);

  const stepIndex = QUESTION_STEP_IDS.indexOf((step as (typeof QUESTION_STEP_IDS)[number]) ?? 'about');
  const profile = project?.profile;

  const stepQuestions = useMemo(() => {
    if (!copy || !profile) return [];
    return copy.questions.filter((q) => {
      if (q.step !== step) return false;
      if (!q.showWhen) return true;
      return getPath(profile, q.showWhen.path) === q.showWhen.equals;
    });
  }, [copy, profile, step]);

  // Coming back to a step (or continuing an unfinished app): start at the first question not answered yet.
  const [positionedFor, setPositionedFor] = useState<string | undefined>(undefined);
  useEffect(() => {
    if (!profile || !copy || positionedFor === step) return;
    const firstOpen = stepQuestions.findIndex((q) => !isAnswered(q, getPath(profile, q.id)));
    setQIndex(firstOpen === -1 ? 0 : firstOpen);
    setPositionedFor(step);
  }, [step, profile, copy, stepQuestions, positionedFor]);

  useEffect(() => {
    return () => {
      void flush();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  // A new question (or a new step) starts at the top of the page, not where the last one ended.
  useScrollToTop(`${step}:${qIndex}`);

  if (loading || copyLoading) return <LoadingScreen label="Loading your app…" />;
  if (error || !project) return <ErrorNotice message={error ?? 'Could not load this app.'} />;
  if (!copy) return <ErrorNotice message="Could not load the wizard questions." />;
  if (stepIndex === -1) return <ErrorNotice message="That step does not exist." />;

  if (profile?.meta?.mode === 'quick' && !profile.meta?.confirmed) {
    return <QuickFlow projectId={project.id} />;
  }

  const stepCopy = copy.steps.find((s) => s.id === step);
  const question = stepQuestions[qIndex];

  function goToStep(targetStep: string, index = 0) {
    setWizardStep(QUESTION_STEP_IDS.indexOf(targetStep as (typeof QUESTION_STEP_IDS)[number]));
    navigate(`/projects/${id}/wizard/${targetStep}`);
    setQIndex(index);
    setPositionedFor(targetStep);
  }

  function handleNext() {
    if (qIndex < stepQuestions.length - 1) {
      setQIndex(qIndex + 1);
      return;
    }
    void flush();
    const nextStep = QUESTION_STEP_IDS[stepIndex + 1];
    if (nextStep) {
      goToStep(nextStep, 0);
    } else {
      // The last answer leads into the follow-up questions, which offer a way straight on to the design.
      navigate(`/projects/${id}/refine`);
    }
  }

  function handleBack() {
    if (qIndex > 0) {
      setQIndex(qIndex - 1);
      return;
    }
    const prevStep = QUESTION_STEP_IDS[stepIndex - 1];
    if (prevStep) {
      void flush();
      navigate(`/projects/${id}/wizard/${prevStep}`);
    } else {
      navigate('/');
    }
  }

  const value = question ? getPath(profile, question.id) : undefined;
  const forcedSignIn =
    question?.id === 'users.requiresSignIn' && profile?.users?.audience && profile.users.audience !== 'just-me';

  function answer(path: string, v: unknown, fromNotSure = false) {
    setField(path, v);
    const notSureFields = new Set(profile?.meta?.notSureFields ?? []);
    if (fromNotSure) notSureFields.add(path);
    else notSureFields.delete(path);
    setField('meta.notSureFields', Array.from(notSureFields));
  }

  return (
    <div className="sv-stack">
      <nav aria-label="Wizard progress">
        <ol className="sv-steps">
          {QUESTION_STEP_IDS.map((sid, i) => {
            const sc = copy.steps.find((s) => s.id === sid);
            const state = i < stepIndex ? 'done' : i === stepIndex ? 'current' : 'upcoming';
            return (
              <li key={sid}>
                <button
                  type="button"
                  className="sv-step-pill"
                  data-state={state}
                  style={{ border: 'none', cursor: 'pointer', font: 'inherit' }}
                  onClick={() => goToStep(sid, 0)}
                >
                  {i + 1}. {sc?.title ?? sid}
                </button>
              </li>
            );
          })}
        </ol>
      </nav>

      {stepCopy && (
        <div>
          <h1>{stepCopy.title}</h1>
          <p className="sv-muted">{stepCopy.intro}</p>
        </div>
      )}

      {saveError && <ErrorNotice title="Not saved yet" message={saveError} />}

      {stepQuestions.length === 0 && (
        <div className="sv-card">
          <p>Nothing to answer on this screen yet.</p>
        </div>
      )}

      {question && (
        <div className="sv-card">
          <p className="sv-faint">
            Question {qIndex + 1} of {stepQuestions.length}
          </p>
          <h2>{question.title}</h2>
          <p>{question.question}</p>
          {question.helpText && <p className="sv-help">{question.helpText}</p>}
          {question.screenedForInjection && <p className="sv-faint">{copy.common.freeTextNotice}</p>}

          {forcedSignIn ? (
            <div className="sv-banner">
              <p style={{ marginBottom: 0 }}>
                Because more than one person will use this app, sign-in is already turned on for you.
              </p>
            </div>
          ) : (
            <QuestionInput question={question} value={value} onChange={(v) => answer(question.id, v)} />
          )}

          <NotSureButton
            question={question}
            common={copy.common}
            onUse={() => {
              if (question.notSure.choosesValue !== undefined) {
                answer(question.id, question.notSure.choosesValue, true);
              } else {
                const notSureFields = new Set(profile?.meta?.notSureFields ?? []);
                notSureFields.add(question.id);
                setField('meta.notSureFields', Array.from(notSureFields));
              }
            }}
          />

          <WhyAndChanges question={question} value={value} common={copy.common} />
        </div>
      )}

      <div className="sv-row-between">
        <button type="button" className="sv-btn sv-btn-secondary" onClick={handleBack}>
          Back
        </button>
        <div className="sv-row">
          <span className="sv-faint" aria-live="polite">
            {saving || unsaved ? 'Saving…' : savedAt ? 'All answers saved' : ''}
          </span>
          <button
            type="button"
            className="sv-btn"
            disabled={!!question && !isAnswered(question, value) && !forcedSignIn}
            onClick={handleNext}
          >
            {qIndex < stepQuestions.length - 1 ? 'Next' : stepIndex === QUESTION_STEP_IDS.length - 1 ? 'Finish my answers' : 'Next: ' + (copy.steps.find((s) => s.id === QUESTION_STEP_IDS[stepIndex + 1])?.title ?? '')}
          </button>
        </div>
      </div>
      <p className="sv-faint">
        Your answers are saved as you go. You can close SecureVibe at any time and pick up here later: choose{' '}
        <strong>Continue</strong> next to this app on My apps. <Link to="/">Save and exit</Link>
      </p>
    </div>
  );
}
