import type { WizardCommonCopy, WizardQuestion } from '../../lib/wizardCopyTypes';
import { EntitiesEditor, ExternalApisEditor, ListEditor, RolesEditor } from './editors';

function whatThisChangesFor(question: WizardQuestion, value: unknown): string[] {
  const map = question.whatThisChanges ?? {};
  const lines: string[] = [...(map['*'] ?? [])];
  if (Array.isArray(value)) {
    for (const v of value) {
      const key = String(v);
      if (map[key]) lines.push(...map[key]);
    }
  } else if (value !== undefined && value !== null && value !== '') {
    const key = String(value);
    if (map[key]) lines.push(...map[key]);
  }
  return Array.from(new Set(lines));
}

export function WhyAndChanges({
  question,
  value,
  common,
}: {
  question: WizardQuestion;
  value: unknown;
  common: WizardCommonCopy;
}) {
  const changes = whatThisChangesFor(question, value);
  return (
    <div className="sv-stack-sm" style={{ marginTop: 16 }}>
      <details className="sv-details">
        <summary>{common.whyWeAskLabel}</summary>
        <p style={{ margin: 0 }}>{question.whyWeAsk}</p>
      </details>
      {changes.length > 0 && (
        <div className="sv-banner sv-banner-good" style={{ marginBottom: 0 }}>
          <h3 style={{ fontSize: '1rem' }}>{common.whatThisChangesLabel}</h3>
          <ul style={{ marginBottom: 0 }}>
            {changes.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function NotSureButton({
  question,
  common,
  onUse,
}: {
  question: WizardQuestion;
  common: WizardCommonCopy;
  onUse: () => void;
}) {
  if (!question.notSure.available) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <button type="button" className="sv-btn-link" onClick={onUse}>
        {common.notSureLabel}
      </button>
      {question.notSure.behaviour && <p className="sv-faint">{question.notSure.behaviour}</p>}
    </div>
  );
}

export function QuestionInput({
  question,
  value,
  onChange,
}: {
  question: WizardQuestion;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  switch (question.inputType) {
    case 'text':
      return (
        <input
          className="sv-input"
          aria-label={question.title}
          value={(value as string) ?? ''}
          maxLength={question.maxLength}
          placeholder={question.placeholder}
          onChange={(e) => onChange(e.target.value)}
          autoFocus
        />
      );
    case 'email':
      return (
        <input
          type="email"
          className="sv-input"
          aria-label={question.title}
          value={(value as string) ?? ''}
          maxLength={question.maxLength}
          placeholder={question.placeholder}
          onChange={(e) => onChange(e.target.value)}
          autoFocus
        />
      );
    case 'longtext':
      return (
        <textarea
          className="sv-textarea"
          aria-label={question.title}
          value={(value as string) ?? ''}
          maxLength={question.maxLength}
          placeholder={question.placeholder}
          onChange={(e) => onChange(e.target.value)}
          autoFocus
        />
      );
    case 'number':
      return (
        <input
          type="number"
          className="sv-input"
          aria-label={question.title}
          value={(value as number | undefined) ?? ''}
          min={question.min}
          max={question.max}
          placeholder={question.placeholder}
          onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
        />
      );
    case 'boolean':
    case 'single-choice': {
      const options = question.options ?? [];
      return (
        <div className="sv-option-list" role="radiogroup" aria-label={question.question}>
          {options.map((opt) => {
            const checked = value === opt.value;
            return (
              <label className="sv-option" key={String(opt.value)} data-checked={checked}>
                <input type="radio" checked={checked} onChange={() => onChange(opt.value)} />
                <span className="sv-option-body">
                  <span className="sv-option-label">
                    {opt.label}
                    {opt.recommended && <span className="sv-badge sv-badge-good">Recommended</span>}
                  </span>
                  {opt.description && <span className="sv-option-desc">{opt.description}</span>}
                </span>
              </label>
            );
          })}
        </div>
      );
    }
    case 'multi-choice': {
      const options = question.options ?? [];
      const selected = new Set(((value as unknown[]) ?? []).map(String));
      return (
        <div className="sv-option-list">
          {options.map((opt) => {
            const key = String(opt.value);
            const checked = selected.has(key);
            return (
              <label className="sv-option" key={key} data-checked={checked}>
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={(e) => {
                    const next = new Set(selected);
                    if (e.target.checked) next.add(key);
                    else next.delete(key);
                    onChange(Array.from(next));
                  }}
                />
                <span className="sv-option-body">
                  <span className="sv-option-label">
                    {opt.label}
                    {opt.recommended && <span className="sv-badge sv-badge-good">Recommended</span>}
                  </span>
                  {opt.description && <span className="sv-option-desc">{opt.description}</span>}
                </span>
              </label>
            );
          })}
        </div>
      );
    }
    case 'list':
      return (
        <ListEditor
          value={(value as string[]) ?? []}
          onChange={onChange}
          placeholder={question.placeholder}
          maxItems={question.maxItems}
          maxLength={question.maxLength}
        />
      );
    case 'entities':
      return <EntitiesEditor value={(value as never) ?? []} onChange={onChange} sub={question.sub} />;
    case 'roles':
      return (
        <RolesEditor
          value={(value as never) ?? []}
          onChange={onChange}
          templates={question.templates}
          maxRoles={question.maxRoles}
        />
      );
    case 'external-apis':
      return (
        <ExternalApisEditor
          value={(value as never) ?? []}
          onChange={onChange}
          fields={question.fields}
          maxItems={question.maxItems}
        />
      );
    default:
      return null;
  }
}
