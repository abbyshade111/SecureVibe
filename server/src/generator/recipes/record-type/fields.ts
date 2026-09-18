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
      // Files are stored by reference to the uploads feature. Without that feature there is nothing to point at,
      // so the field is dropped and the expander records the reason for the report.
      if (!opts.uploads) return undefined;
      return {
        ...base,
        encrypted: false,
        sqlType: 'TEXT',
        zod: required ? `schemas.id` : `schemas.id.optional()`,
        zodOptional: `schemas.id.optional()`,
        control: 'text',
        toDb: (v) => `${v} ?? null`,
        fromDb: (v) => v,
      };
    default:
      return undefined;
  }
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
  for (const field of entity.fields) {
    const plan = planField(field, entity, opts);
    if (plan) fields.push(plan);
    else if (field.type === 'file') droppedFields.push({ name: field.name, reason: 'file fields need the uploads feature, which is switched off for this app' });
    else droppedFields.push({ name: field.name, reason: `the field type "${field.type}" is not supported by the expander` });
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
