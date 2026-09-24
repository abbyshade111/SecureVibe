import type { EntitySpec, EntityField, RoleSpec, ExternalApiSpec, FieldType } from '@shared/profile.js';
import { checkSavedAnswers } from '@shared/answer-check.js';
import type { WizardEntitySub, WizardExternalApiFields, WizardRoleTemplate } from '../../lib/wizardCopyTypes';

function uid(): string {
  return Math.random().toString(36).slice(2, 8);
}

function slugify(label: string): string {
  const s = label
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return /^[a-z]/.test(s) ? s : `f-${s || uid()}`;
}

// ---- list of short strings (app.keyFeatures) ------------------------------

export function ListEditor({
  value,
  onChange,
  placeholder,
  maxItems,
  maxLength,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  maxItems?: number;
  maxLength?: number;
}) {
  const items = value ?? [];
  return (
    <div className="sv-stack-sm">
      {items.map((item, i) => (
        <div className="sv-row" key={i}>
          <input
            className="sv-input"
            aria-label={`Item ${i + 1}`}
            value={item}
            maxLength={maxLength}
            placeholder={placeholder}
            onChange={(e) => {
              const next = [...items];
              next[i] = e.target.value;
              onChange(next);
            }}
          />
          <button
            type="button"
            className="sv-btn sv-btn-secondary sv-btn-sm"
            onClick={() => onChange(items.filter((_, idx) => idx !== i))}
            aria-label={`Remove item ${i + 1}`}
          >
            Remove
          </button>
        </div>
      ))}
      {(!maxItems || items.length < maxItems) && (
        <button type="button" className="sv-btn sv-btn-secondary" onClick={() => onChange([...items, ''])}>
          + Add another
        </button>
      )}
    </div>
  );
}

// ---- entities editor (app.entities) ---------------------------------------

function emptyField(): EntityField {
  return { name: 'field', label: 'New detail', type: 'text', required: false, sensitive: false };
}

function emptyEntity(): EntitySpec {
  return { name: 'record', label: 'New record', fields: [], access: 'owner-only' };
}

export function EntitiesEditor({
  value,
  onChange,
  sub,
}: {
  value: EntitySpec[];
  onChange: (v: EntitySpec[]) => void;
  sub?: WizardEntitySub;
}) {
  const entities = value ?? [];
  // Damaged answers, named beside the record they are about: a record with no details, a name that reads like
  // a sentence. The owner removes it with the button that is already there, or fixes it; nothing is automatic.
  const problems = checkSavedAnswers({ app: { entities } });
  const fieldTypes: { value: FieldType; label: string }[] =
    (sub?.field.types as { value: FieldType; label: string }[] | undefined) ?? [];
  const accessOptions = sub?.access.options ?? [];

  function updateEntity(i: number, patch: Partial<EntitySpec>) {
    const next = [...entities];
    const current = next[i];
    if (!current) return;
    next[i] = { ...current, ...patch };
    onChange(next);
  }

  return (
    <div className="sv-stack">
      {entities.map((entity, i) => (
        <div className="sv-card" style={{ margin: 0 }} key={i}>
          <div className="sv-row-between">
            <input
              className="sv-input"
              style={{ fontWeight: 700, maxWidth: 320 }}
              value={entity.label}
              onChange={(e) => {
                const label = e.target.value;
                updateEntity(i, { label, name: slugify(label) || entity.name });
              }}
              aria-label="Record name"
            />
            {!entity.label.trim() && (
              <span className="sv-help" style={{ marginLeft: 8 }}>
                Give this kind of record a name to include it.
              </span>
            )}
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              onClick={() => onChange(entities.filter((_, idx) => idx !== i))}
            >
              Remove this record
            </button>
          </div>

          {problems
            .filter((p) => p.entityIndex === i)
            .map((p) => (
              <div className="sv-banner sv-banner-warn" key={p.kind} style={{ marginTop: 12 }}>
                <p style={{ marginBottom: 0 }}>
                  <strong>{p.offerRemoval ? 'This looks like an accident.' : 'Is this really a record?'}</strong> {p.message}
                </p>
              </div>
            ))}

          <div className="sv-field" style={{ marginTop: 16 }}>
            <label className="sv-label">{sub?.access.title ?? 'Who can see these records?'}</label>
            <select
              className="sv-select"
              value={entity.access}
              onChange={(e) => updateEntity(i, { access: e.target.value as EntitySpec['access'] })}
            >
              {(accessOptions.length
                ? accessOptions
                : [
                    { value: 'all-signed-in', label: 'Everyone who is signed in' },
                    { value: 'owner-only', label: 'Only the person who created it' },
                    { value: 'admin-only', label: 'Only administrators' },
                    { value: 'public-read', label: 'Anyone can view, only signed-in people can edit' },
                  ]
              ).map((o) => (
                <option key={String(o.value)} value={String(o.value)}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          <div className="sv-label" style={{ marginBottom: 8 }}>
            {sub?.field.title ?? 'Details of a record'}
          </div>
          <div className="sv-stack-sm">
            {entity.fields.map((field, fi) => (
              <div key={fi} className="sv-card" style={{ margin: 0, background: 'var(--color-bg-subtle)' }}>
                <div className="sv-row">
                  <input
                    className="sv-input"
                    style={{ flex: 2 }}
                    value={field.label}
                    placeholder={sub?.field.namePlaceholder ?? 'detail name'}
                    onChange={(e) => {
                      const label = e.target.value;
                      const nextFields = [...entity.fields];
                      nextFields[fi] = { ...field, label, name: slugify(label) || field.name };
                      updateEntity(i, { fields: nextFields });
                    }}
                    aria-label={sub?.field.nameLabel ?? 'Detail name'}
                  />
                  <select
                    className="sv-select"
                    style={{ flex: 1 }}
                    value={field.type}
                    onChange={(e) => {
                      const nextFields = [...entity.fields];
                      nextFields[fi] = { ...field, type: e.target.value as FieldType };
                      updateEntity(i, { fields: nextFields });
                    }}
                    aria-label={sub?.field.typeLabel ?? 'What kind of value is it?'}
                  >
                    {(fieldTypes.length
                      ? fieldTypes
                      : [
                          { value: 'text', label: 'Short text' },
                          { value: 'longtext', label: 'Long text' },
                          { value: 'number', label: 'Number' },
                          { value: 'money', label: 'Money amount' },
                          { value: 'date', label: 'Date' },
                          { value: 'boolean', label: 'Yes / No' },
                        ]
                    ).map((t) => (
                      <option key={t.value} value={t.value}>
                        {t.label}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="sv-btn sv-btn-secondary sv-btn-sm"
                    onClick={() => updateEntity(i, { fields: entity.fields.filter((_, idx) => idx !== fi) })}
                  >
                    Remove
                  </button>
                </div>
                <div className="sv-row" style={{ marginTop: 8 }}>
                  <label className="sv-checkbox-row" style={{ marginBottom: 0 }}>
                    <input
                      type="checkbox"
                      checked={field.required}
                      onChange={(e) => {
                        const nextFields = [...entity.fields];
                        nextFields[fi] = { ...field, required: e.target.checked };
                        updateEntity(i, { fields: nextFields });
                      }}
                    />
                    <span>{sub?.field.requiredLabel ?? 'Must be filled in'}</span>
                  </label>
                  <label className="sv-checkbox-row" style={{ marginBottom: 0 }}>
                    <input
                      type="checkbox"
                      checked={field.sensitive}
                      onChange={(e) => {
                        const nextFields = [...entity.fields];
                        nextFields[fi] = { ...field, sensitive: e.target.checked };
                        updateEntity(i, { fields: nextFields });
                      }}
                    />
                    <span>{sub?.field.sensitiveLabel ?? 'This is sensitive'}</span>
                  </label>
                </div>
                {field.sensitive && sub?.field.sensitiveHelp && <p className="sv-faint">{sub.field.sensitiveHelp}</p>}
              </div>
            ))}
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              onClick={() => updateEntity(i, { fields: [...entity.fields, emptyField()] })}
            >
              + Add a detail
            </button>
          </div>
        </div>
      ))}
      <button type="button" className="sv-btn sv-btn-secondary" onClick={() => onChange([...entities, emptyEntity()])}>
        + Add a kind of record
      </button>
    </div>
  );
}

// ---- roles editor (users.roles) --------------------------------------------

export function RolesEditor({
  value,
  onChange,
  templates,
  maxRoles,
}: {
  value: RoleSpec[];
  onChange: (v: RoleSpec[]) => void;
  templates?: WizardRoleTemplate[];
  maxRoles?: number;
}) {
  const roles = value ?? [];

  function setAdmin(i: number) {
    onChange(roles.map((r, idx) => ({ ...r, isAdmin: idx === i })));
  }

  function addFromTemplate(t: WizardRoleTemplate) {
    if (roles.some((r) => r.name === t.name)) return;
    onChange([...roles, { name: t.name, label: t.label, description: t.description, isAdmin: t.isAdmin }]);
  }

  return (
    <div className="sv-stack">
      {templates && templates.length > 0 && (
        <div className="sv-row">
          {templates.map((t) => (
            <button
              key={t.name}
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              disabled={roles.some((r) => r.name === t.name)}
              onClick={() => addFromTemplate(t)}
            >
              + {t.label}
            </button>
          ))}
        </div>
      )}
      <div className="sv-stack-sm">
        {roles.map((role, i) => (
          <div className="sv-card" style={{ margin: 0 }} key={i}>
            <div className="sv-row">
              <input
                className="sv-input"
                style={{ flex: 1 }}
                value={role.label}
                onChange={(e) => {
                  const next = [...roles];
                  next[i] = { ...role, label: e.target.value, name: slugify(e.target.value) || role.name };
                  onChange(next);
                }}
                aria-label="Role name"
              />
              <label className="sv-checkbox-row" style={{ marginBottom: 0 }}>
                <input type="radio" name="admin-role" checked={role.isAdmin} onChange={() => setAdmin(i)} />
                <span>Administrator</span>
              </label>
              <button
                type="button"
                className="sv-btn sv-btn-secondary sv-btn-sm"
                onClick={() => onChange(roles.filter((_, idx) => idx !== i))}
              >
                Remove
              </button>
            </div>
            <input
              className="sv-input"
              style={{ marginTop: 8 }}
              value={role.description ?? ''}
              placeholder="What can this kind of user do?"
              onChange={(e) => {
                const next = [...roles];
                next[i] = { ...role, description: e.target.value };
                onChange(next);
              }}
              aria-label="What this kind of user may do"
            />
          </div>
        ))}
      </div>
      {(!maxRoles || roles.length < maxRoles) && (
        <button
          type="button"
          className="sv-btn sv-btn-secondary"
          onClick={() => onChange([...roles, { name: `role-${uid()}`, label: 'New role', isAdmin: roles.length === 0 }])}
        >
          + Add a custom kind of user
        </button>
      )}
      {roles.length > 0 && !roles.some((r) => r.isAdmin) && (
        <p className="sv-error-text">Pick exactly one kind of user as the administrator.</p>
      )}
    </div>
  );
}

// ---- external APIs editor --------------------------------------------------

export function ExternalApisEditor({
  value,
  onChange,
  fields,
  maxItems,
}: {
  value: ExternalApiSpec[];
  onChange: (v: ExternalApiSpec[]) => void;
  fields?: WizardExternalApiFields;
  maxItems?: number;
}) {
  const items = value ?? [];
  return (
    <div className="sv-stack">
      {items.map((item, i) => (
        <div className="sv-card" style={{ margin: 0 }} key={i}>
          <div className="sv-row">
            <input
              className="sv-input"
              style={{ flex: 1 }}
              value={item.name}
              placeholder={fields?.name.placeholder ?? 'Service name'}
              onChange={(e) => {
                const next = [...items];
                next[i] = { ...item, name: e.target.value };
                onChange(next);
              }}
              aria-label={fields?.name.label ?? 'Service name'}
            />
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              onClick={() => onChange(items.filter((_, idx) => idx !== i))}
            >
              Remove
            </button>
          </div>
          <input
            className="sv-input"
            style={{ marginTop: 8 }}
            value={item.purpose}
            placeholder={fields?.purpose.placeholder ?? 'What it is for'}
            onChange={(e) => {
              const next = [...items];
              next[i] = { ...item, purpose: e.target.value };
              onChange(next);
            }}
            aria-label={fields?.purpose.label ?? 'What it is for'}
          />
          {/* The address and whether a key exists: both decide what can actually be built, and neither can be
              guessed. Without them the agent invented a host or left the connection unbuilt in silence. */}
          <input
            className="sv-input"
            style={{ marginTop: 8 }}
            value={item.host ?? ''}
            placeholder={fields?.host?.placeholder ?? 'api.example.com'}
            onChange={(e) => {
              const next = [...items];
              next[i] = { ...item, host: e.target.value.trim() };
              onChange(next);
            }}
            aria-label={fields?.host?.label ?? 'Its web address'}
          />
          <p className="sv-help" style={{ marginTop: 4 }}>
            {fields?.host?.help ?? 'Just the address, no https:// and no path. Leave it empty if you do not know it yet.'}
          </p>
          <label className="sv-label" style={{ marginTop: 8 }} htmlFor={`api-credentials-${i}`}>
            {fields?.credentials?.label ?? 'Do you have an account and key for it?'}
          </label>
          <select
            id={`api-credentials-${i}`}
            className="sv-input"
            value={item.credentials ?? 'not-sure'}
            onChange={(e) => {
              const next = [...items];
              next[i] = { ...item, credentials: e.target.value as typeof item.credentials };
              onChange(next);
            }}
          >
            <option value="have">Yes, I have an account and key</option>
            <option value="not-yet">Not yet</option>
            <option value="not-sure">I am not sure</option>
          </select>
          <p className="sv-help" style={{ marginTop: 4 }}>
            {fields?.credentials?.help ?? 'Without one the connection cannot work, so we build everything else and tell you what is left to do.'}
          </p>
          <label className="sv-checkbox-row" style={{ marginTop: 8, marginBottom: 0 }}>
            <input
              type="checkbox"
              checked={item.sendsPersonalData}
              onChange={(e) => {
                const next = [...items];
                next[i] = { ...item, sendsPersonalData: e.target.checked };
                onChange(next);
              }}
            />
            <span>{fields?.sendsPersonalData.label ?? "It will receive people's personal details"}</span>
          </label>
        </div>
      ))}
      {(!maxItems || items.length < maxItems) && (
        <button
          type="button"
          className="sv-btn sv-btn-secondary"
          onClick={() => onChange([...items, { name: '', purpose: '', sendsPersonalData: false, host: '', credentials: 'not-sure' }])}
        >
          + Add a service
        </button>
      )}
    </div>
  );
}

