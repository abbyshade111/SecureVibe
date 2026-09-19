/**
 * Quick mode (DESIGN §3, §13 item 5): the person writes a description, Claude turns it into a design profile.
 *
 * Two rules make this safe to hand to someone who is not going to check it:
 *  - **Monotonic.** An inferred value is only used when it keeps the security posture the same or makes it stricter.
 *    A suggestion that would loosen anything (no sign-in, open registration, an assistant that can act, wider data
 *    access, lower business impact) is never applied; it becomes a question on the summary screen.
 *  - **Evidence.** Every field the model fills in must come with a short quote from the description that really
 *    appears in it. A field without a quote is still offered, but is marked as needing confirmation.
 */
import type { QuickInferResponse } from '@shared/api.js';
import {
  AppCategorySchema,
  DataCategorySchema,
  DesignProfileSchema,
  FieldTypeSchema,
  type Audience,
  type DataCategory,
  type DeploymentTarget,
  type DesignProfile,
} from '@shared/profile.js';
import { z } from 'zod';
import { quickInferSystem, wrapUntrusted } from '../prompts/index.js';
import { loadDefaultInjectionPatterns, screenText, type InjectionPatterns } from '../screening.js';
import { emptyUsageDelta, type Effort, type LlmProvider, type StructuredFailureReason, type UsageDelta } from '../types.js';

const IDENTIFIER_MAX = 40;

const InferredFieldSchema = z.strictObject({
  name: z.string().max(60),
  label: z.string().max(60),
  type: FieldTypeSchema,
  required: z.boolean(),
  sensitive: z.boolean(),
  description: z.string().max(200),
});

const InferredEntitySchema = z.strictObject({
  name: z.string().max(60),
  label: z.string().max(60),
  pluralLabel: z.string().max(60),
  description: z.string().max(300),
  access: z.enum(['all-signed-in', 'owner-only', 'admin-only', 'public-read']),
  fields: z.array(InferredFieldSchema).max(40),
});

const InferredRoleSchema = z.strictObject({
  name: z.string().max(60),
  label: z.string().max(60),
  description: z.string().max(200),
  isAdmin: z.boolean(),
});

/** Strict output schema (no optionals, no defaults) so the JSON schema sent to the model is exact. */
export const QuickInferOutputSchema = z.strictObject({
  name: z.string().max(60),
  tagline: z.string().max(120),
  summary: z.string().max(2000),
  category: AppCategorySchema,
  entities: z.array(InferredEntitySchema).max(20),
  keyFeatures: z.array(z.string().max(200)).max(30),
  roles: z.array(InferredRoleSchema).max(8),
  requiresSignIn: z.boolean(),
  expectedUserCount: z.enum(['1', '2-20', '21-500', '500+']),
  registration: z.enum(['invite-only', 'admin-created', 'open']),
  adminMfa: z.boolean(),
  fileUploads: z.boolean(),
  email: z.boolean(),
  scheduledJobs: z.boolean(),
  publicApi: z.boolean(),
  payments: z.boolean(),
  externalApis: z
    .array(z.strictObject({ name: z.string().max(80), purpose: z.string().max(300), sendsPersonalData: z.boolean() }))
    .max(10),
  aiAssistant: z.strictObject({
    enabled: z.boolean(),
    purpose: z.string().max(500),
    dataItCanSee: z.enum(['nothing', 'users-own-records', 'all-records']),
    canTakeActions: z.boolean(),
    storesHistory: z.boolean(),
  }),
  dataCategories: z.array(DataCategorySchema).max(11),
  aboutOtherPeople: z.boolean(),
  businessImpact: z.enum(['low', 'normal', 'high']),
  ownerName: z.string().max(80),
  evidence: z.array(z.strictObject({ field: z.string().max(80), quote: z.string().max(300) })).max(80),
});
export type QuickInferOutput = z.infer<typeof QuickInferOutputSchema>;

export interface QuickInferInput {
  description: string;
  name?: string;
  known: { dataCategories?: string[]; audience?: string; deploymentTarget?: string };
  projectId?: string;
  correlationId?: string;
  effort?: Effort;
  injectionPatterns?: InjectionPatterns;
}

export interface QuickInferOutcome extends QuickInferResponse {
  usage: UsageDelta;
  /** Set when the AI step did not run; the profile is then the safe baseline built from the known answers. */
  failure?: { reason: StructuredFailureReason; message: string };
}

/** Placeholder that parses as an email but can never reach anyone (RFC 2606 reserved TLD). */
export const OWNER_EMAIL_PLACEHOLDER = 'owner@example.invalid';

export async function quickInfer(provider: LlmProvider, input: QuickInferInput): Promise<QuickInferOutcome> {
  const patterns = input.injectionPatterns ?? loadDefaultInjectionPatterns();
  const screening = screenText(input.description, patterns);
  const baseline = baselineProfile(input);

  if (screening.blocked) {
    return {
      profile: baseline,
      inferredFields: [],
      needsConfirmation: [
        {
          field: 'app.description',
          question: 'Please describe your app again in your own words, without instructions aimed at the AI.',
        },
      ],
      assumptions: baselineAssumptions(baseline),
      screening: { flagged: true, note: screening.note },
      usage: emptyUsageDelta(provider.model),
      failure: { reason: 'error', message: screening.note },
    };
  }

  const user = [
    'The person described their application like this:',
    '',
    wrapUntrusted('user-description', input.description, { maxChars: 8000 }),
    '',
    `They already told us: audience = ${baseline.users.audience}; where it runs = ${baseline.deployment.target}; ` +
      `information it handles = ${baseline.data.categories.join(', ') || 'none stated'}.`,
    input.name ? `They called the project "${input.name}".` : '',
    '',
    'Fill in the plan. Give a quote for every field you fill in. Do not propose weaker security settings.',
  ]
    .filter((line) => line !== '')
    .join('\n');

  const result = await provider.structured({
    purpose: 'quick-infer',
    system: quickInferSystem(),
    user,
    schema: QuickInferOutputSchema,
    effort: input.effort ?? 'medium',
    maxTokens: 16_000,
    correlationId: input.correlationId ?? 'quick-infer',
    projectId: input.projectId ?? 'unknown',
  });

  if (!result.ok) {
    return {
      profile: baseline,
      inferredFields: [],
      needsConfirmation: [
        { field: 'app.entities', question: 'What information should the app keep track of? List the main records.' },
      ],
      assumptions: baselineAssumptions(baseline),
      screening: { flagged: screening.flagged, ...(screening.note ? { note: screening.note } : {}) },
      usage: result.usage,
      failure: { reason: result.reason, message: result.message },
    };
  }

  const merged = applyInference(baseline, result.data, input.description);
  return {
    profile: merged.profile,
    inferredFields: merged.inferredFields,
    needsConfirmation: merged.needsConfirmation,
    assumptions: merged.assumptions,
    screening: { flagged: screening.flagged, ...(screening.note ? { note: screening.note } : {}) },
    usage: result.usage,
  };
}

/** The safest profile consistent with the three answers the person always gives explicitly. */
export function baselineProfile(input: QuickInferInput): DesignProfile {
  const audience = pickEnum<Audience>(input.known.audience, ['just-me', 'my-team', 'customers', 'public'], 'my-team');
  const target = pickEnum<DeploymentTarget>(
    input.known.deploymentTarget,
    ['local-only', 'local-network', 'internet-later'],
    'local-only',
  );
  const categories = uniqueCategories(input.known.dataCategories ?? []);

  return DesignProfileSchema.parse({
    app: {
      name: (input.name ?? 'My application').slice(0, 60),
      description: input.description.slice(0, 4000),
      category: 'other',
      entities: [],
      keyFeatures: [],
    },
    users: {
      audience,
      requiresSignIn: true,
      roles: [
        { name: 'admin', label: 'Administrator', description: 'Can manage everything, including other people.', isAdmin: true },
        { name: 'member', label: 'Member', description: 'Can use the app day to day.', isAdmin: false },
      ],
      expectedUserCount: audience === 'just-me' ? '1' : '2-20',
      registration: 'admin-created',
      adminMfa: true,
    },
    data: {
      categories: categories.includes('credentials') ? categories : [...categories, 'credentials'],
      aboutOtherPeople: categories.some((c) => c !== 'business-confidential' && c !== 'files' && c !== 'credentials'),
      retention: 'keep-until-deleted',
      region: 'unsure',
    },
    capabilities: {},
    deployment: {
      target,
      owner: { name: 'Owner', contactEmail: OWNER_EMAIL_PLACEHOLDER },
      businessImpact: 'normal',
    },
    meta: { mode: 'quick', inferredFields: [], notSureFields: [], confirmed: false },
  });
}

function baselineAssumptions(profile: DesignProfile): string[] {
  return [
    'We assumed people need to sign in, because that is the safer choice when we are not sure.',
    'We assumed only an administrator can create accounts.',
    'We assumed administrators use a second step to sign in (an authenticator app).',
    `We assumed the app runs ${profile.deployment.target === 'local-only' ? 'only on your own computer' : 'where you told us'}.`,
  ];
}

export interface AppliedInference {
  profile: DesignProfile;
  inferredFields: string[];
  needsConfirmation: { field: string; question: string; evidence?: string }[];
  assumptions: string[];
}

/** Rank of a security-relevant value: higher = stricter. An inference is only applied when it does not lower a rank. */
const RANKS = {
  registration: { open: 0, 'invite-only': 1, 'admin-created': 2 } as Record<string, number>,
  businessImpact: { low: 0, normal: 1, high: 2 } as Record<string, number>,
  dataItCanSee: { 'all-records': 0, 'users-own-records': 1, nothing: 2 } as Record<string, number>,
  retention: { 'keep-until-deleted': 0, 'auto-delete-after-period': 1 } as Record<string, number>,
};

export function applyInference(baseline: DesignProfile, inferred: QuickInferOutput, description: string): AppliedInference {
  const profile: DesignProfile = structuredClone(baseline);
  const inferredFields: string[] = [];
  const needsConfirmation: AppliedInference['needsConfirmation'] = [];
  const assumptions = baselineAssumptions(baseline);
  const quotes = evidenceIndex(inferred.evidence, description);

  const take = (field: string, apply: () => void): void => {
    apply();
    inferredFields.push(field);
    const quote = quotes.get(field);
    if (quote) return;
    needsConfirmation.push({ field, question: confirmationQuestion(field) });
  };

  const refuse = (field: string, question: string, suggestion: string): void => {
    needsConfirmation.push({ field, question, evidence: suggestion });
  };

  if (inferred.name.trim() !== '') take('app.name', () => (profile.app.name = inferred.name.trim().slice(0, 60)));
  if (inferred.tagline.trim() !== '') take('app.tagline', () => (profile.app.tagline = inferred.tagline.slice(0, 120)));
  take('app.category', () => (profile.app.category = inferred.category));
  if (inferred.entities.length > 0) {
    take('app.entities', () => (profile.app.entities = normalizeEntities(inferred.entities)));
  }
  if (inferred.keyFeatures.length > 0) {
    take('app.keyFeatures', () => (profile.app.keyFeatures = inferred.keyFeatures.slice(0, 30)));
  }
  if (inferred.roles.length > 0) take('users.roles', () => (profile.users.roles = normalizeRoles(inferred.roles)));
  take('users.expectedUserCount', () => (profile.users.expectedUserCount = inferred.expectedUserCount));

  // Monotonic guards: only apply a value that keeps or raises the posture.
  if (!inferred.requiresSignIn) {
    refuse(
      'users.requiresSignIn',
      'Should people have to sign in to use this app? We have switched sign-in on, which is the safer choice.',
      'The description suggested the app might be open to everyone.',
    );
  }
  if (rank('registration', inferred.registration) >= rank('registration', profile.users.registration)) {
    take('users.registration', () => (profile.users.registration = inferred.registration));
  } else {
    refuse(
      'users.registration',
      'How should people get an account: you create it for them, you invite them, or anyone can sign up?',
      `The description suggested "${inferred.registration}"; we kept the stricter setting.`,
    );
  }
  if (!inferred.adminMfa) {
    refuse(
      'users.adminMfa',
      'Administrators will need an authenticator app to sign in. Is that alright?',
      'The description did not mention two-step sign-in; we switched it on anyway.',
    );
  }

  const categories = uniqueCategories([...profile.data.categories, ...inferred.dataCategories]);
  if (categories.length !== profile.data.categories.length) {
    take('data.categories', () => (profile.data.categories = categories));
  }
  if (inferred.aboutOtherPeople && !profile.data.aboutOtherPeople) {
    take('data.aboutOtherPeople', () => (profile.data.aboutOtherPeople = true));
  }
  if (rank('businessImpact', inferred.businessImpact) > rank('businessImpact', profile.deployment.businessImpact)) {
    take('deployment.businessImpact', () => (profile.deployment.businessImpact = inferred.businessImpact));
  } else if (rank('businessImpact', inferred.businessImpact) < rank('businessImpact', profile.deployment.businessImpact)) {
    refuse(
      'deployment.businessImpact',
      'If this app stopped working or leaked information for a day, how bad would that be for your business?',
      `The description suggested "${inferred.businessImpact}"; we kept the higher setting.`,
    );
  }

  if (inferred.fileUploads) take('capabilities.fileUploads', () => (profile.capabilities.fileUploads = true));
  if (inferred.email) take('capabilities.email', () => (profile.capabilities.email = true));
  if (inferred.scheduledJobs) take('capabilities.scheduledJobs', () => (profile.capabilities.scheduledJobs = true));
  if (inferred.publicApi) take('capabilities.publicApi', () => (profile.capabilities.publicApi = true));
  if (inferred.payments) take('capabilities.payments', () => (profile.capabilities.payments = true));
  if (inferred.externalApis.length > 0) {
    // The model may name a service from the description, but it does not know the owner's account or the address
    // they will use: those two are asked, never guessed. An invented host would be added to the allow-list and an
    // invented "they have a key" would have the agent build a call that cannot work.
    take(
      'capabilities.externalApis',
      () =>
        (profile.capabilities.externalApis = inferred.externalApis.slice(0, 10).map((api) => ({ ...api, host: '', credentials: 'not-sure' as const }))),
    );
  }

  if (inferred.aiAssistant.enabled) {
    take('capabilities.aiAssistant.enabled', () => {
      profile.capabilities.aiAssistant.enabled = true;
      profile.capabilities.aiAssistant.purpose = inferred.aiAssistant.purpose.slice(0, 500);
    });
    if (rank('dataItCanSee', inferred.aiAssistant.dataItCanSee) < rank('dataItCanSee', profile.capabilities.aiAssistant.dataItCanSee)) {
      refuse(
        'capabilities.aiAssistant.dataItCanSee',
        'What should the assistant be able to look at when it answers: nothing, only the records the person can already see, or everything?',
        `The description suggested "${inferred.aiAssistant.dataItCanSee}"; for now the assistant sees nothing.`,
      );
    }
    if (inferred.aiAssistant.canTakeActions) {
      refuse(
        'capabilities.aiAssistant.canTakeActions',
        'Should the assistant be allowed to change your records, or only answer questions? If it may change things, you will confirm each change.',
        'The description suggested the assistant could do things on its own; we left that switched off.',
      );
    }
    if (inferred.aiAssistant.storesHistory) {
      refuse(
        'capabilities.aiAssistant.storesHistory',
        'Should the assistant remember past conversations between visits?',
        'The description suggested it should; keeping conversations means keeping more personal information.',
      );
    }
  }

  if (inferred.ownerName.trim() !== '') {
    take('deployment.owner.name', () => (profile.deployment.owner.name = inferred.ownerName.trim().slice(0, 80)));
  }
  needsConfirmation.push({
    field: 'deployment.owner.contactEmail',
    question: 'What email address should we put in the security contact and the incident plan?',
  });

  profile.meta.mode = 'quick';
  profile.meta.inferredFields = inferredFields;
  profile.app.description = description.slice(0, 4000);
  if (inferred.summary.trim() !== '') assumptions.push(`We understood your app as: ${inferred.summary.trim()}`);

  return { profile: DesignProfileSchema.parse(profile), inferredFields, needsConfirmation, assumptions };
}

function rank(kind: keyof typeof RANKS, value: string): number {
  return RANKS[kind][value] ?? 0;
}

function confirmationQuestion(field: string): string {
  const questions: Record<string, string> = {
    'app.name': 'Is this the right name for your app?',
    'app.tagline': 'Does this one-line description sound right?',
    'app.category': 'Is this the kind of app you meant?',
    'app.entities': 'Are these the records your app should keep, with the right fields?',
    'app.keyFeatures': 'Are these the main things the app should do?',
    'users.roles': 'Are these the kinds of people who will use the app?',
    'users.expectedUserCount': 'Roughly how many people will use it?',
    'users.registration': 'How should people get an account?',
    'data.categories': 'Does the app handle this kind of information?',
    'data.aboutOtherPeople': 'Does the app hold information about other people?',
    'deployment.businessImpact': 'How bad would a day of downtime or a leak be for your business?',
    'deployment.owner.name': 'Who is responsible for this app?',
    'capabilities.fileUploads': 'Will people upload files?',
    'capabilities.email': 'Should the app send emails?',
    'capabilities.scheduledJobs': 'Should the app do things on a schedule?',
    'capabilities.publicApi': 'Should other software be able to connect to this app?',
    'capabilities.payments': 'Will you take payments?',
    'capabilities.externalApis': 'Should the app connect to these other services?',
    'capabilities.aiAssistant.enabled': 'Should the app include an AI assistant?',
  };
  return questions[field] ?? `We guessed this from your description. Is it right? (${field})`;
}

/** A quote counts only when it really appears in the description (whitespace-normalised, case-insensitive). */
export function evidenceIndex(evidence: { field: string; quote: string }[], description: string): Map<string, string> {
  const haystack = normalizeForMatch(description);
  const map = new Map<string, string>();
  for (const item of evidence) {
    const quote = item.quote.trim();
    if (quote.length < 3) continue;
    if (!haystack.includes(normalizeForMatch(quote))) continue;
    if (!map.has(item.field)) map.set(item.field, quote);
  }
  return map;
}

function normalizeForMatch(text: string): string {
  return text.normalize('NFKC').replace(/\s+/g, ' ').trim().toLowerCase();
}

function pickEnum<T extends string>(value: string | undefined, allowed: readonly T[], fallback: T): T {
  return allowed.includes((value ?? '') as T) ? ((value as T) ?? fallback) : fallback;
}

function uniqueCategories(values: string[]): DataCategory[] {
  const out: DataCategory[] = [];
  for (const value of values) {
    const parsed = DataCategorySchema.safeParse(value);
    if (parsed.success && !out.includes(parsed.data)) out.push(parsed.data);
  }
  return out;
}

export function slugify(value: string, fallback: string): string {
  const slug = value
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/^[^a-z]+/, '')
    .slice(0, IDENTIFIER_MAX);
  return slug === '' ? fallback : slug;
}

function normalizeEntities(entities: QuickInferOutput['entities']): DesignProfile['app']['entities'] {
  const used = new Set<string>();
  return entities.slice(0, 20).map((e, i) => {
    let name = slugify(e.name || e.label, `record-${i + 1}`);
    while (used.has(name)) name = `${name}-${i + 1}`.slice(0, IDENTIFIER_MAX);
    used.add(name);
    const fieldNames = new Set<string>();
    return {
      name,
      label: (e.label || e.name || `Record ${i + 1}`).slice(0, 60),
      pluralLabel: (e.pluralLabel || `${e.label || name}s`).slice(0, 60),
      description: e.description.slice(0, 300),
      access: e.access,
      fields: e.fields.slice(0, 40).map((f, j) => {
        let fname = slugify(f.name || f.label, `field-${j + 1}`);
        while (fieldNames.has(fname)) fname = `${fname}-${j + 1}`.slice(0, IDENTIFIER_MAX);
        fieldNames.add(fname);
        return {
          name: fname,
          label: (f.label || f.name || `Field ${j + 1}`).slice(0, 60),
          type: f.type,
          required: f.required,
          sensitive: f.sensitive,
          description: f.description.slice(0, 200),
        };
      }),
    };
  });
}

function normalizeRoles(roles: QuickInferOutput['roles']): DesignProfile['users']['roles'] {
  const used = new Set<string>();
  const out: DesignProfile['users']['roles'] = [];
  let adminSeen = false;
  for (const [i, role] of roles.slice(0, 8).entries()) {
    let name = slugify(role.name || role.label, `role-${i + 1}`);
    while (used.has(name)) name = `${name}-${i + 1}`.slice(0, IDENTIFIER_MAX);
    used.add(name);
    const isAdmin = role.isAdmin && !adminSeen;
    if (isAdmin) adminSeen = true;
    out.push({
      name,
      label: (role.label || role.name || `Role ${i + 1}`).slice(0, 60),
      description: role.description.slice(0, 200),
      isAdmin,
    });
  }
  if (!adminSeen) {
    out.unshift({
      name: used.has('admin') ? 'administrator' : 'admin',
      label: 'Administrator',
      description: 'Can manage everything, including other people.',
      isAdmin: true,
    });
  }
  return out.slice(0, 8);
}
