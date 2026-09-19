/**
 * Field-type mapping for the record-type recipe: how each `EntityField` type becomes a SQLite column, a zod rule,
 * a form control and a display value. Everything here is deterministic — no model call is involved.
 */
import type { EntityField, EntitySpec } from '@shared/profile.js';

/** `appointment-note` → `AppointmentNote`. */
export function pascal(name: string): string {
  return name
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

/** `appointment-note` → `appointmentNote`. */
export function camel(name: string): string {
  const p = pascal(name);
  return p.charAt(0).toLowerCase() + p.slice(1);
}

/** `appointment-note` → `appointment_note` (a plain SQL identifier). */
export function snake(name: string): string {
  return name.replace(/[-\s]+/g, '_').toLowerCase();
}

/** Very small English pluraliser — enough for table names and URLs; ambiguous cases just get an "s". */
export function plural(name: string): string {
  if (/(s|x|z|ch|sh)$/i.test(name)) return `${name}es`;
  if (/[^aeiou]y$/i.test(name)) return `${name.slice(0, -1)}ies`;
  return `${name}s`;
}

export function tableName(entity: EntitySpec): string {
  return snake(plural(entity.name));
}

/** URL prefix for the entity's pages and API, e.g. `/appointments`. */
export function routeBase(entity: EntitySpec): string {
  return `/${plural(entity.name)}`;
}

export function columnName(field: EntityField): string {
  return snake(field.name);
}

/** The DTO/property name a column is exposed as, e.g. `start_time` → `startTime`. */
export function propName(field: EntityField): string {
  return camel(field.name);
}

export interface FieldPlan {
  field: EntityField;
  column: string;
  prop: string;
  sqlType: 'TEXT' | 'INTEGER' | 'REAL';
  /** Stored encrypted (sensitive text columns only; encrypted columns are never used in WHERE clauses). */
  encrypted: boolean;
  /** zod expression used in the create/update body schema. */
  zod: string;
  /** zod expression for the PATCH schema (always optional). */
  zodOptional: string;
  /** HTML input type for the form, or 'textarea' / 'select' / 'checkbox'. */
  control: 'text' | 'textarea' | 'number' | 'money' | 'date' | 'datetime-local' | 'checkbox' | 'email' | 'url' | 'tel' | 'select';
  /** How the value is written into the database from the validated body. */
  toDb(valueExpr: string): string;
  /** How a row value is turned back into the DTO value. */
  fromDb(valueExpr: string): string;
}

function choiceList(field: EntityField): string {
  const choices = (field.choices ?? []).filter((c) => c.trim() !== '');
  return choices.length > 0 ? `[${choices.map((c) => JSON.stringify(c)).join(', ')}]` : `['']`;
}

/** Wraps a zod rule so an optional field accepts an empty form value (an empty box must not fail the format rule). */
function optionalise(rule: string, required: boolean): string {
  return required ? rule : `z.union([${rule}, z.literal('')]).optional().default('')`;
}

/** Number rule where an empty form box means "not given" (z.coerce alone would turn it into 0). */
function numberRule(rule: string, required: boolean): string {
  return `z.preprocess((v) => (v === '' || v === null ? undefined : v), ${rule}${required ? '' : '.optional()'})`;
}

/** Required free-text fields must not be empty (after trimming). */
function textRule(max: number, required: boolean, trim = true): string {
  return `z.string()${trim ? '.trim()' : ''}${required ? `.min(1, 'Please fill this in.')` : ''}.max(${max})`;
}

export function planField(field: EntityField, entity: EntitySpec, opts: { uploads: boolean }): FieldPlan | undefined {
  const column = columnName(field);
  const prop = propName(field);
  const required = field.required;
  // Sensitive text is stored as ciphertext, so it can never be part of a WHERE clause or an ORDER BY.
  const encrypted = field.sensitive && ['text', 'longtext', 'email', 'phone', 'url'].includes(field.type);

  const base = { field, column, prop, encrypted } as const;
  const plainToDb = (v: string) => (encrypted ? `encryptField(String(${v} ?? ''), TABLE, ${JSON.stringify(column)}, id)` : `${v} ?? null`);
  const plainFromDb = (v: string) => (encrypted ? `decryptOrEmpty(${v}, ${JSON.stringify(column)}, row.id)` : `${v}`);

  switch (field.type) {
    case 'text':
      return { ...base, sqlType: 'TEXT', zod: optionalise(textRule(200, required), required), zodOptional: `${textRule(200, required)}.optional()`, control: 'text', toDb: plainToDb, fromDb: plainFromDb };
    case 'longtext':
      return { ...base, sqlType: 'TEXT', zod: optionalise(textRule(10000, required, false), required), zodOptional: `${textRule(10000, required, false)}.optional()`, control: 'textarea', toDb: plainToDb, fromDb: plainFromDb };
    case 'email':
      return { ...base, sqlType: 'TEXT', zod: optionalise(`schemas.email`, required), zodOptional: required ? `schemas.email.optional()` : `z.union([schemas.email, z.literal('')]).optional()`, control: 'email', toDb: plainToDb, fromDb: plainFromDb };
    case 'url':
      return { ...base, sqlType: 'TEXT', zod: optionalise(`z.string().trim().url().max(500)`, required), zodOptional: required ? `z.string().trim().url().max(500).optional()` : `z.union([z.string().trim().url().max(500), z.literal('')]).optional()`, control: 'url', toDb: plainToDb, fromDb: plainFromDb };
    case 'phone':
      return { ...base, sqlType: 'TEXT', zod: optionalise(textRule(40, required), required), zodOptional: `${textRule(40, required)}.optional()`, control: 'tel', toDb: plainToDb, fromDb: plainFromDb };
    case 'number':
      return {
        ...base,
        encrypted: false,
        sqlType: 'REAL',
        zod: numberRule(`z.coerce.number().finite()`, required),
        zodOptional: numberRule(`z.coerce.number().finite()`, false),
        control: 'number',
        toDb: (v) => `${v} ?? null`,
        fromDb: (v) => v,
      };
    case 'money':
      // Money is stored as whole cents so arithmetic never drifts; forms show and accept a decimal amount.
      return {
        ...base,
        encrypted: false,
        sqlType: 'INTEGER',
        zod: numberRule(`z.coerce.number().finite().min(0).max(99999999)`, required),
        zodOptional: numberRule(`z.coerce.number().finite().min(0).max(99999999)`, false),
        control: 'money',
        toDb: (v) => `${v} === undefined || ${v} === null ? null : Math.round(Number(${v}) * 100)`,
        fromDb: (v) => `${v} === null || ${v} === undefined ? null : Number(${v}) / 100`,
      };
    case 'boolean':
      return {
        ...base,
        encrypted: false,
        sqlType: 'INTEGER',
        zod: `schemas.bool.optional().default(false)`,
        zodOptional: `schemas.bool.optional()`,
        control: 'checkbox',
        toDb: (v) => `${v} ? 1 : 0`,
        fromDb: (v) => `${v} === 1`,
      };
    case 'date':
      return {
        ...base,
        encrypted: false,
        sqlType: 'TEXT',
        zod: optionalise(`z.string().trim().regex(/^\\d{4}-\\d{2}-\\d{2}$/, 'Please use the date picker.')`, required),
        zodOptional: required ? `z.string().trim().regex(/^\\d{4}-\\d{2}-\\d{2}$/, 'Please use the date picker.').optional()` : `z.union([z.string().trim().regex(/^\\d{4}-\\d{2}-\\d{2}$/, 'Please use the date picker.'), z.literal('')]).optional()`,
        control: 'date',
        toDb: (v) => `${v} || null`,
        fromDb: (v) => v,
      };
    case 'datetime':
      return {
        ...base,
        encrypted: false,
        sqlType: 'TEXT',
        zod: optionalise(`z.string().trim().regex(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}/, 'Please use the date and time picker.')`, required),
        zodOptional: required ? `z.string().trim().regex(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}/, 'Please use the date and time picker.').optional()` : `z.union([z.string().trim().regex(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}/, 'Please use the date and time picker.'), z.literal('')]).optional()`,
        control: 'datetime-local',
        toDb: (v) => `${v} || null`,
        fromDb: (v) => v,
      };
    case 'choice':
      return {
        ...base,
        encrypted: false,
        sqlType: 'TEXT',
        zod: required ? `z.enum(${choiceList(field)})` : `z.union([z.enum(${choiceList(field)}), z.literal('')]).optional()`,
        zodOptional: required ? `z.enum(${choiceList(field)}).optional()` : `z.union([z.enum(${choiceList(field)}), z.literal('')]).optional()`,
        control: 'select',
        toDb: (v) => `${v} || null`,
        fromDb: (v) => v,
      };
    case 'file':
      // A file is never part of the record's own form or interface: it is added by attaching one, which the
      // record-attachment recipe builds on top of the template's uploads module (see attachmentFieldsOf). That way
      // the column can only ever hold a file the person attaching it just uploaded, rather than any id they typed.
      return undefined;
    default:
      return undefined;
  }
}

/**
 * One file attached to a record. The record's own schema has no such field (see `planField`); the column is added
 * and written only by the record-attachment recipe, through the template's uploads module.
 */
export interface AttachmentField {
  field: EntityField;
  /** Database column on the record's table. */
  column: string;
  /** The name the column is exposed under. */
  prop: string;
  /** What the owner calls it ("Photo"). */
  label: string;
}

/**
 * The file fields of a record type that become attachments — none when the uploads feature is off, because there
 * is then nothing to attach and nowhere safe to put it. Both recipes read this, so they cannot disagree about
 * which fields exist.
 */
export function attachmentFieldsOf(entity: EntitySpec, opts: { uploads: boolean }): AttachmentField[] {
  if (!opts.uploads) return [];
  return entity.fields
    .filter((f) => f.type === 'file')
    .map((f) => ({ field: f, column: columnName(f), prop: propName(f), label: f.label }));
}

/**
 * One field a summary page can add up. A field marked sensitive is never summarised: a total or a breakdown can
 * say as much as the values themselves, and the summary is read by a wider audience than the record's owner.
 */
export interface SummaryField {
  field: EntityField;
  column: string;
  prop: string;
  label: string;
  kind: 'number' | 'money' | 'choice' | 'boolean';
  /** For a choice field, the options as the person described them. */
  choices: string[];
}

const SUMMARY_KINDS: Record<string, SummaryField['kind'] | undefined> = {
  number: 'number',
  money: 'money',
  choice: 'choice',
  boolean: 'boolean',
};

/**
 * The fields of a record type worth summarising — amounts to total, choices to count by, yes/no fields to tally.
 * Both the record-type recipe (which links to the page) and the record-summary recipe (which builds it) read this,
 * so they cannot disagree about what the page contains.
 */
export function summaryFieldsOf(entity: EntitySpec): SummaryField[] {
  const out: SummaryField[] = [];
  for (const field of entity.fields) {
    if (field.sensitive) continue;
    const kind = SUMMARY_KINDS[field.type];
    if (!kind) continue;
    const choices = (field.choices ?? []).filter((c) => c.trim() !== '');
    if (kind === 'choice' && choices.length === 0) continue;
    out.push({ field, column: columnName(field), prop: propName(field), label: field.label, kind, choices });
  }
  return out;
}

/**
 * One date on a record, and how precise it is. A date field is the only thing in a described record type that is
 * unambiguously a point in time, which is what both the reminder job and the what-is-coming-up page need.
 *
 * It says nothing about what the date *means*. "The date the person described first" is a rule; "the deadline" is a
 * guess. A page built on this must not call a record overdue, because the date may as easily be a birthday or the
 * day something was recorded, and a system that calls a birthday overdue has stopped being trustworthy about the
 * things it says more carefully.
 */
export interface DateField {
  field: EntityField;
  column: string;
  prop: string;
  label: string;
  granularity: 'date' | 'datetime';
}

/**
 * The first date or date-and-time field the person described, or nothing when the record type has none. The
 * record-reminder recipe and the needs-attention recipe both read this, so they cannot disagree about which date a
 * record type is about, and a field marked sensitive is never offered: a page that lists dates alongside names is
 * read by a wider audience than the record itself.
 */
export function dateFieldOf(entity: EntityPlan): DateField | undefined {
  const field = entity.fields.find((f) => !f.field.sensitive && (f.control === 'date' || f.control === 'datetime-local'));
  if (!field) return undefined;
  return {
    field: field.field,
    column: field.column,
    prop: field.prop,
    label: field.field.label,
    granularity: field.control === 'date' ? 'date' : 'datetime',
  };
}

export interface EntityPlan {
  entity: EntitySpec;
  table: string;
  base: string;
  moduleDir: string;
  pascalName: string;
  camelName: string;
  rowType: string;
  fields: FieldPlan[];
  /** Files attached to this record type, built by the record-attachment recipe rather than by this one. */
  attachments: AttachmentField[];
  /** Fields a summary page can add up, built by the record-summary recipe rather than by this one. */
  summaries: SummaryField[];
  droppedFields: { name: string; reason: string }[];
  /** The first required text-like field, used as the record's display title. */
  titleField: FieldPlan | undefined;
  ownerScoped: boolean;
  publicRead: boolean;
  adminOnly: boolean;
  /** `auth` value for read routes. */
  readAuth: string;
  /** `auth` value for create/update/delete routes. */
  writeAuth: string;
  hasEncrypted: boolean;
  quota: number;
}

export function planEntity(entity: EntitySpec, opts: { uploads: boolean }): EntityPlan {
  const fields: FieldPlan[] = [];
  const droppedFields: { name: string; reason: string }[] = [];
  const attachments = attachmentFieldsOf(entity, opts);
  const summaries = summaryFieldsOf(entity);
  for (const field of entity.fields) {
    const plan = planField(field, entity, opts);
    if (plan) fields.push(plan);
    // A file field is handled by the attachment recipe when there is an uploads feature to handle it with, and is
    // left out with a reason the owner can read when there is not.
    else if (field.type === 'file' && opts.uploads) continue;
    else if (field.type === 'file') droppedFields.push({ name: field.name, reason: 'files need the uploads feature, which is switched off for this app' });
    else droppedFields.push({ name: field.name, reason: `the field type "${field.type}" is not one the standard building blocks can add` });
  }
  const titleField = fields.find((f) => f.field.required && (f.control === 'text' || f.control === 'email')) ?? fields.find((f) => f.control === 'text') ?? fields[0];
  const ownerScoped = entity.access === 'owner-only';
  const adminOnly = entity.access === 'admin-only';
  const publicRead = entity.access === 'public-read';
  return {
    entity,
    table: tableName(entity),
    base: routeBase(entity),
    moduleDir: entity.name,
    pascalName: pascal(entity.name),
    camelName: camel(entity.name),
    rowType: `${pascal(entity.name)}Row`,
    fields,
    attachments,
    summaries,
    droppedFields,
    titleField,
    ownerScoped,
    publicRead,
    adminOnly,
    readAuth: publicRead ? "'public'" : adminOnly ? "'role:admin'" : "'user'",
    writeAuth: adminOnly ? "'role:admin'" : "'user'",
    hasEncrypted: fields.some((f) => f.encrypted),
    quota: 500,
  };
}
