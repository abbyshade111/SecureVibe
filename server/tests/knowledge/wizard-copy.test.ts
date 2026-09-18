import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { WIZARD_STEPS } from '@shared/api.js';
import {
  AppCategorySchema,
  AudienceSchema,
  BusinessImpactSchema,
  CapabilitiesSchema,
  DataCategorySchema,
  DataSectionSchema,
  DeploymentTargetSchema,
  EntitySpecSchema,
  FieldTypeSchema,
  UsersSectionSchema,
  AiAssistantSpecSchema,
} from '@shared/profile.js';
import { plainLanguageProblems, readKnowledge } from './helpers.js';

const OptionSchema = z
  .object({
    value: z.union([z.string(), z.boolean(), z.number()]),
    label: z.string().min(1),
    description: z.string().min(1),
    recommended: z.boolean().optional(),
  })
  .strict();

const NotSureSchema = z
  .object({
    available: z.boolean(),
    choosesValue: z.unknown().optional(),
    behaviour: z.string().optional(),
  })
  .strict();

const QuestionSchema = z
  .object({
    id: z.string().regex(/^[a-z]+(\.[a-zA-Z]+)+$/),
    step: z.enum(['about', 'users', 'data', 'features', 'deployment']),
    inputType: z.enum([
      'text',
      'longtext',
      'number',
      'email',
      'boolean',
      'single-choice',
      'multi-choice',
      'list',
      'entities',
      'roles',
      'external-apis',
    ]),
    required: z.boolean(),
    showWhen: z.object({ path: z.string(), equals: z.unknown() }).optional(),
    title: z.string().min(1),
    question: z.string().min(1).regex(/\?$/, 'question must end with a question mark'),
    helpText: z.string().min(1),
    whyWeAsk: z.string().min(1),
    options: z.array(OptionSchema).optional(),
    templates: z.array(z.object({ name: z.string(), label: z.string(), description: z.string(), isAdmin: z.boolean() })).optional(),
    fields: z.record(z.string(), z.object({ label: z.string(), placeholder: z.string().optional(), help: z.string().optional() })).optional(),
    sensitiveValues: z.array(z.string()).optional(),
    placeholder: z.string().optional(),
    example: z.string().optional(),
    maxLength: z.number().int().optional(),
    maxItems: z.number().int().optional(),
    maxEntities: z.number().int().optional(),
    maxFieldsPerEntity: z.number().int().optional(),
    maxRoles: z.number().int().optional(),
    min: z.number().optional(),
    max: z.number().optional(),
    screenedForInjection: z.boolean().optional(),
    notSure: NotSureSchema,
    whatThisChanges: z.record(z.string(), z.array(z.string().min(1))),
    sub: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

const WizardCopySchema = z
  .object({
    version: z.string(),
    description: z.string(),
    common: z.record(z.string(), z.string()),
    steps: z.array(
      z.object({ id: z.string(), title: z.string(), intro: z.string(), sbdStep: z.number().int().min(1).max(10), estimatedMinutes: z.number().int() }).strict(),
    ),
    questions: z.array(QuestionSchema),
    summary: z.object({
      headline: z.string(),
      sections: z.record(z.string(), z.string()),
      extraCareLevels: z.record(z.string(), z.object({ label: z.string(), text: z.string() })),
      approveButton: z.string(),
      approveNote: z.string(),
      quickModeNote: z.string(),
    }),
    whatThisChanges: z.record(z.string(), z.array(z.string().min(1))),
  })
  .strict();

/** Every DesignProfile answer the wizard collects must have a question (profile paths). */
const EXPECTED_QUESTION_IDS = [
  'app.name',
  'app.tagline',
  'app.description',
  'app.category',
  'app.entities',
  'app.keyFeatures',
  'users.audience',
  'users.requiresSignIn',
  'users.roles',
  'users.expectedUserCount',
  'users.registration',
  'users.adminMfa',
  'data.categories',
  'data.aboutOtherPeople',
  'data.retention',
  'data.retentionMonths',
  'data.region',
  'capabilities.fileUploads',
  'capabilities.uploadKinds',
  'capabilities.aiAssistant.enabled',
  'capabilities.aiAssistant.purpose',
  'capabilities.aiAssistant.dataItCanSee',
  'capabilities.aiAssistant.canTakeActions',
  'capabilities.aiAssistant.storesHistory',
  'capabilities.aiAssistant.canSearchWeb',
  'capabilities.aiAssistant.webSearchSites',
  'capabilities.email',
  'capabilities.externalApis',
  'capabilities.scheduledJobs',
  'capabilities.publicApi',
  'capabilities.payments',
  'deployment.target',
  'deployment.owner.name',
  'deployment.owner.contactEmail',
  'deployment.businessImpact',
];

/** Option values must match the closed enums in shared/src/profile.ts exactly. */
const ENUM_OPTIONS: Record<string, readonly (string | boolean)[]> = {
  'app.category': AppCategorySchema.options,
  'users.audience': AudienceSchema.options,
  'users.requiresSignIn': [true, false],
  'users.expectedUserCount': UsersSectionSchema.shape.expectedUserCount.unwrap().options,
  'users.registration': UsersSectionSchema.shape.registration.unwrap().options,
  'users.adminMfa': [true, false],
  'data.categories': DataCategorySchema.options,
  'data.aboutOtherPeople': [true, false],
  'data.retention': DataSectionSchema.shape.retention.unwrap().options,
  'data.region': DataSectionSchema.shape.region.unwrap().options,
  'capabilities.fileUploads': [true, false],
  'capabilities.uploadKinds': CapabilitiesSchema.shape.uploadKinds.unwrap().element.options,
  'capabilities.aiAssistant.enabled': [true, false],
  'capabilities.aiAssistant.dataItCanSee': AiAssistantSpecSchema.shape.dataItCanSee.unwrap().options,
  'capabilities.aiAssistant.canTakeActions': [true, false],
  'capabilities.aiAssistant.storesHistory': [true, false],
  'capabilities.aiAssistant.canSearchWeb': [true, false],
  'capabilities.email': [true, false],
  'capabilities.scheduledJobs': [true, false],
  'capabilities.publicApi': [true, false],
  'capabilities.payments': [true, false],
  'deployment.target': DeploymentTargetSchema.options,
  'deployment.businessImpact': BusinessImpactSchema.options,
};

/** Condition ids the design engine may look up (server/src/design/conditions.ts facts and pattern `when` values). */
const EXPECTED_CONDITIONS = [
  'always',
  'auth',
  'no-auth',
  'level2',
  'personal-data',
  'sensitive-data',
  'field-encryption',
  'admin-mfa',
  'user-mfa',
  'uploads',
  'ai',
  'ai-actions',
  'ai-history',
  'ai-moderation',
  'email',
  'external-apis',
  'public-api',
  'payments',
  'scheduler',
  'retention',
  'local-only',
  'lan',
  'internet',
  'public-audience',
  'high-impact',
];

const raw = readKnowledge<unknown>('wizard-copy.json');

describe('data/knowledge/wizard-copy.json', () => {
  const copy = WizardCopySchema.parse(raw);
  const questions = new Map(copy.questions.map((q) => [q.id, q]));

  it('lists the five answer-collecting wizard steps in WIZARD_STEPS order plus summary/build/results', () => {
    expect(copy.steps.map((s) => s.id)).toEqual(WIZARD_STEPS.map((s) => s.id));
    for (const step of copy.steps) {
      const shared = WIZARD_STEPS.find((s) => s.id === step.id)!;
      expect(step.title, step.id).toBe(shared.title);
    }
  });

  it('has exactly one question per DesignProfile answer', () => {
    expect([...questions.keys()].sort()).toEqual([...EXPECTED_QUESTION_IDS].sort());
    expect(questions.size).toBe(copy.questions.length);
  });

  it('every question has title, question, help text, why-we-ask and what-this-changes', () => {
    for (const q of copy.questions) {
      expect(q.whyWeAsk.length, `${q.id} whyWeAsk`).toBeGreaterThan(40);
      expect(q.helpText.length, `${q.id} helpText`).toBeGreaterThan(20);
      expect(Object.keys(q.whatThisChanges).length > 0 || q.inputType === 'text', `${q.id} whatThisChanges`).toBe(true);
    }
  });

  it('choice questions offer exactly the enum values from shared/src/profile.ts', () => {
    for (const [id, expected] of Object.entries(ENUM_OPTIONS)) {
      const q = questions.get(id)!;
      expect(q.options, `${id} needs options`).toBeDefined();
      expect([...q.options!.map((o) => o.value)].sort(), id).toEqual([...expected].sort());
    }
    expect(questions.get('app.entities')!.sub).toBeDefined();
    const sub = questions.get('app.entities')!.sub as { field: { types: Array<{ value: string }> }; access: { options: Array<{ value: string }> } };
    expect(sub.field.types.map((t) => t.value).sort()).toEqual([...FieldTypeSchema.options].sort());
    expect(sub.access.options.map((o) => o.value).sort()).toEqual([...EntitySpecSchema.shape.access.unwrap().options].sort());
  });

  it('what-this-changes keys are option values (or "*") and every choice has consequences', () => {
    for (const q of copy.questions) {
      if (!q.options) continue;
      const values = new Set(q.options.map((o) => String(o.value)));
      for (const key of Object.keys(q.whatThisChanges)) {
        expect(values.has(key) || key === '*', `${q.id}: whatThisChanges key "${key}" is not an option value`).toBe(true);
      }
      for (const v of values) {
        expect(q.whatThisChanges[v] ?? q.whatThisChanges['*'], `${q.id}: no consequences for "${v}"`).toBeDefined();
      }
    }
  });

  it('"Not sure" picks the safer answer and says so', () => {
    for (const q of copy.questions) {
      if (!q.notSure.available) {
        expect(['app.name', 'app.tagline', 'app.description', 'deployment.owner.name', 'deployment.owner.contactEmail'], `${q.id} must offer Not sure`).toContain(q.id);
        continue;
      }
      expect(q.notSure.behaviour, `${q.id} Not sure behaviour`).toMatch(/^We will /);
      expect(q.notSure.behaviour, `${q.id} Not sure records an assumption`).toMatch(/note it|assumption/);
      if (q.options && q.notSure.choosesValue !== undefined) {
        const chosen = Array.isArray(q.notSure.choosesValue) ? q.notSure.choosesValue : [q.notSure.choosesValue];
        const values = q.options.map((o) => o.value);
        for (const c of chosen) expect(values, `${q.id} Not sure chooses "${String(c)}"`).toContain(c);
      }
    }
    // The high-consequence questions must fall to the safer side.
    expect(questions.get('users.audience')!.notSure.choosesValue).toBe('customers');
    expect(questions.get('users.adminMfa')!.notSure.choosesValue).toBe(true);
    expect(questions.get('deployment.target')!.notSure.choosesValue).toBe('internet-later');
    expect(questions.get('deployment.businessImpact')!.notSure.choosesValue).toBe('high');
    expect(questions.get('capabilities.aiAssistant.canTakeActions')!.notSure.choosesValue).toBe(false);
    expect(questions.get('capabilities.aiAssistant.dataItCanSee')!.notSure.choosesValue).toBe('nothing');
  });

  it('situational questions declare what they depend on, and the dependency exists', () => {
    const situational = copy.questions.filter((q) => q.showWhen);
    expect(situational.map((q) => q.id).sort()).toEqual(
      [
        'data.retentionMonths',
        'capabilities.uploadKinds',
        'capabilities.aiAssistant.purpose',
        'capabilities.aiAssistant.dataItCanSee',
        'capabilities.aiAssistant.canTakeActions',
        'capabilities.aiAssistant.storesHistory',
        'capabilities.aiAssistant.canSearchWeb',
        'capabilities.aiAssistant.webSearchSites',
      ].sort(),
    );
    for (const q of situational) expect(questions.has(q.showWhen!.path), `${q.id} depends on ${q.showWhen!.path}`).toBe(true);
  });

  it('uses the required plain phrasings for deployment and business impact', () => {
    const target = questions.get('deployment.target')!.options!.map((o) => o.label);
    expect(target).toEqual(['Only on this computer', 'On computers in my shop or office network', 'On the internet for customers']);
    expect(questions.get('deployment.businessImpact')!.question).toContain('If this app were down for a day');
  });

  it('data category options each give concrete examples', () => {
    for (const o of questions.get('data.categories')!.options!) {
      expect(o.description.length, `${String(o.value)} examples`).toBeGreaterThan(25);
    }
    expect(questions.get('data.categories')!.sensitiveValues).toEqual(['financial', 'payment-card', 'health', 'government-id', 'children']);
    expect(questions.get('data.categories')!.whatThisChanges['health']!.join(' ')).toMatch(/encrypt/);
    expect(questions.get('data.categories')!.whatThisChanges['health']!.join(' ')).toMatch(/authenticator app/);
  });

  it('role templates are Owner, Staff and Customers with exactly one administrator', () => {
    const templates = questions.get('users.roles')!.templates!;
    expect(templates.map((t) => t.label)).toEqual(['Owner', 'Staff', 'Customers']);
    expect(templates.filter((t) => t.isAdmin)).toHaveLength(1);
  });

  it('tells the user up front when an authenticator app will be needed', () => {
    expect(copy.common['authenticatorNotice']).toMatch(/authenticator app/);
    expect(questions.get('users.adminMfa')!.helpText).toMatch(/authenticator app/);
  });

  it('never shows scores or the word "escalate" in wizard copy', () => {
    const text = JSON.stringify(copy);
    expect(text).not.toMatch(/escalat/i);
    expect(text).not.toMatch(/\bscore\b/i);
  });

  it('top-level whatThisChanges covers every design-engine condition', () => {
    expect(Object.keys(copy.whatThisChanges).sort()).toEqual([...EXPECTED_CONDITIONS].sort());
  });

  it('all copy is plain language: short sentences and no unexplained acronyms', () => {
    const problems: string[] = [];
    const visit = (value: unknown, path: string) => {
      if (typeof value === 'string') {
        for (const p of plainLanguageProblems(value, { checkAcronyms: true })) problems.push(`${path}: ${p}`);
      } else if (Array.isArray(value)) value.forEach((v, i) => visit(v, `${path}[${i}]`));
      else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) visit(v, `${path}.${k}`);
    };
    visit(copy, 'copy');
    expect(problems).toEqual([]);
  });
});
