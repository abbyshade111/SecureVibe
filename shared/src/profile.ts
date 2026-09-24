/**
 * The Design Profile is the complete set of plain-language answers a user gives in the wizard.
 * It is the ONLY input to every security decision SecureVibe makes (SbD step 1: capture security requirements).
 *
 * Rules for this file:
 *  - every field has a plain-language meaning; the wizard copy lives in data/knowledge, not here
 *  - zod schemas are the source of truth; TypeScript types are inferred from them
 *  - keep enums closed: security decisions are keyed on these values
 */
import { z } from 'zod';

export const AudienceSchema = z.enum(['just-me', 'my-team', 'customers', 'public']);
export type Audience = z.infer<typeof AudienceSchema>;

/**
 * The look of the generated app. Color only: each name matches a set of color values in the template's stylesheet,
 * every one of which is checked against the WCAG AA contrast ratios by the template's own tests. A theme can never
 * hide a control, change a message or weaken a security setting, so this answer has no security consequences.
 */
export const ThemeSchema = z.enum(['calm', 'warm', 'forest', 'contrast']);
export type Theme = z.infer<typeof ThemeSchema>;

export const AppCategorySchema = z.enum([
  'tracker', // e.g. task/issue/habit tracker
  'booking', // appointments, reservations
  'inventory', // stock, assets, equipment
  'content', // blog, wiki, documentation, CMS
  'dashboard', // reporting over data
  'intake-form', // forms, applications, surveys
  'crm', // customers, contacts, deals
  'ai-assistant', // chat/assistant style app
  'marketplace', // listings + buyers/sellers
  'internal-tool',
  'other',
]);
export type AppCategory = z.infer<typeof AppCategorySchema>;

export const DataCategorySchema = z.enum([
  'contact', // names, emails, phone numbers, addresses
  'financial', // bank details, salaries, invoices, account balances
  'payment-card', // card numbers (never stored; provider-hosted checkout)
  'health', // medical, wellbeing, disability
  'government-id', // passport, national id, tax numbers
  'credentials', // passwords / secrets belonging to users (always present when sign-in is on)
  'children', // data about people under 16
  'location', // precise location / movement
  'files', // uploaded documents, images
  'business-confidential', // internal business data, pricing, plans
  'other-personal', // anything else about identifiable people
]);
export type DataCategory = z.infer<typeof DataCategorySchema>;

/** Data categories that raise the ASVS target level to 2 and trigger SbD threat modeling. */
export const SENSITIVE_DATA_CATEGORIES: readonly DataCategory[] = [
  'financial',
  'payment-card',
  'health',
  'government-id',
  'children',
] as const;

export const DeploymentTargetSchema = z.enum(['local-only', 'local-network', 'internet-later']);
export type DeploymentTarget = z.infer<typeof DeploymentTargetSchema>;

export const BusinessImpactSchema = z.enum(['low', 'normal', 'high']);
export type BusinessImpact = z.infer<typeof BusinessImpactSchema>;

export const FieldTypeSchema = z.enum([
  'text',
  'longtext',
  'number',
  'money',
  'date',
  'datetime',
  'boolean',
  'email',
  'url',
  'phone',
  'choice',
  'file',
]);
export type FieldType = z.infer<typeof FieldTypeSchema>;

export const IdentifierSchema = z
  .string()
  .min(1)
  .max(40)
  .regex(/^[a-z][a-z0-9-]*$/, 'lowercase letters, numbers and dashes only');

export const EntityFieldSchema = z.object({
  name: IdentifierSchema,
  label: z.string().min(1).max(60),
  type: FieldTypeSchema,
  required: z.boolean().default(false),
  choices: z.array(z.string().min(1).max(60)).max(30).optional(),
  /** Marked when the field holds sensitive data (drives field-level encryption + redaction in logs). */
  sensitive: z.boolean().default(false),
  description: z.string().max(200).optional(),
});
export type EntityField = z.infer<typeof EntityFieldSchema>;

export const EntitySpecSchema = z.object({
  name: IdentifierSchema, // singular, e.g. "appointment"
  label: z.string().min(1).max(60), // "Appointment"
  pluralLabel: z.string().min(1).max(60).optional(),
  description: z.string().max(300).optional(),
  fields: z.array(EntityFieldSchema).max(40).default([]),
  /** Who may see/edit records: everyone signed in, only the owner (+admins), or only admins. */
  access: z.enum(['all-signed-in', 'owner-only', 'admin-only', 'public-read']).default('all-signed-in'),
});
export type EntitySpec = z.infer<typeof EntitySpecSchema>;

export const RoleSpecSchema = z.object({
  name: IdentifierSchema, // "admin", "staff", "member"
  label: z.string().min(1).max(60),
  description: z.string().max(200).optional(),
  /** Admin-like roles get MFA and stricter logging. Exactly one role must be the administrator. */
  isAdmin: z.boolean().default(false),
});
export type RoleSpec = z.infer<typeof RoleSpecSchema>;

export const AiAssistantSpecSchema = z.object({
  enabled: z.boolean().default(false),
  /** Plain-language purpose, e.g. "help staff draft replies to customer questions". */
  purpose: z.string().max(500).default(''),
  /** What application data the assistant may read when answering (always through the signed-in user's own permissions). */
  dataItCanSee: z.enum(['nothing', 'users-own-records', 'all-records']).default('nothing'),
  /** Whether the assistant may change data (create/update records). Off by default; adds AISVS C9.2/C9.3 controls. */
  canTakeActions: z.boolean().default(false),
  /** Whether conversation history is kept between visits (adds AISVS C8 memory controls). */
  storesHistory: z.boolean().default(false),
  /**
   * Whether the assistant may look things up on the web. The search runs at the AI provider, so the app itself
   * still contacts nothing else; answers carry the sources the search used (AISVS C7.4).
   */
  canSearchWeb: z.boolean().default(false),
  /**
   * Sites the web search may return results from (host names, subdomains included). Empty means the whole web.
   * Written to the app's AI_WEB_SEARCH_DOMAINS setting.
   */
  webSearchSites: z
    .array(
      z
        .string()
        .trim()
        .toLowerCase()
        .regex(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/, 'Use a site address such as "who.int" or "health.harvard.edu".')
        .max(253),
    )
    .max(40)
    .default([]),
});
export type AiAssistantSpec = z.infer<typeof AiAssistantSpecSchema>;

export const ExternalApiSpecSchema = z.object({
  name: z.string().min(1).max(80),
  purpose: z.string().max(300),
  /** Whether the app sends personal data to this service (drives data-flow classification). */
  sendsPersonalData: z.boolean().default(false),
  /**
   * The address the app will call, host only ("api.example.com"). The agent is told to add it to
   * OUTBOUND_ALLOWED_HOSTS, and without it there was nothing to add: it guessed a host or left the connection
   * unbuilt, and an owner was told her app "only talks to the outside services you named" about calls that were
   * never written. Empty means the owner does not know it yet, which is a thing to tell them, not to invent.
   */
  host: z.string().max(253).default(''),
  /** Whether the owner already has an account and key for it. "no" and "not sure" both leave the call unbuilt. */
  credentials: z.enum(['have', 'not-yet', 'not-sure']).default('not-sure'),
});
export type ExternalApiSpec = z.infer<typeof ExternalApiSpecSchema>;

export const CapabilitiesSchema = z.object({
  fileUploads: z.boolean().default(false),
  uploadKinds: z.array(z.enum(['images', 'documents', 'spreadsheets', 'other'])).default([]),
  aiAssistant: AiAssistantSpecSchema.prefault({}),
  email: z.boolean().default(false),
  externalApis: z.array(ExternalApiSpecSchema).max(10).default([]),
  scheduledJobs: z.boolean().default(false),
  /** Machine-to-machine access with API keys (adds ASVS V4/V9-adjacent controls). */
  publicApi: z.boolean().default(false),
  /** Payments are always delegated to a provider-hosted checkout; card data is never stored. */
  payments: z.boolean().default(false),
});
export type Capabilities = z.infer<typeof CapabilitiesSchema>;

export const AppSectionSchema = z.object({
  name: z.string().min(1).max(60),
  tagline: z.string().max(120).optional(),
  description: z.string().min(1).max(4000),
  category: AppCategorySchema,
  /** The color scheme the app is built with. Defaulted so designs saved before themes existed still load. */
  theme: ThemeSchema.default('calm'),
  entities: z.array(EntitySpecSchema).max(20).default([]),
  keyFeatures: z.array(z.string().min(1).max(200)).max(30).default([]),
});

export const UsersSectionSchema = z.object({
  audience: AudienceSchema,
  requiresSignIn: z.boolean(),
  roles: z.array(RoleSpecSchema).max(8).default([]),
  expectedUserCount: z.enum(['1', '2-20', '21-500', '500+']).default('2-20'),
  registration: z.enum(['invite-only', 'admin-created', 'open']).default('admin-created'),
  /** Two-factor authentication for administrator accounts (recommended; forced on for sensitive data). */
  adminMfa: z.boolean().default(true),
  /**
   * Whether the owner's organization runs a central sign-in system (Microsoft Entra, Google Workspace, Okta).
   * The Secure by Design control AC-02 begins "if your organization has a central sign-in system": an owner with
   * no organization was rated at risk on it for ever. "no" lets the rules mark AC-02 not applicable; "yes" and
   * "not-sure" keep it as an action for a developer.
   */
  centralSignIn: z.enum(['yes', 'no', 'not-sure']).default('not-sure'),
});

export const DataSectionSchema = z.object({
  categories: z.array(DataCategorySchema).default([]),
  aboutOtherPeople: z.boolean().default(false),
  retention: z.enum(['keep-until-deleted', 'auto-delete-after-period']).default('keep-until-deleted'),
  retentionMonths: z.number().int().min(1).max(120).optional(),
  /** Region hint used only to suggest applicable regulations in plain language (GDPR, HIPAA...). */
  region: z.enum(['eu-uk', 'us', 'other', 'unsure']).default('unsure'),
});

export const DeploymentSectionSchema = z.object({
  target: DeploymentTargetSchema,
  owner: z.object({
    name: z.string().min(1).max(80),
    contactEmail: z.string().email().max(120),
  }),
  businessImpact: BusinessImpactSchema.default('normal'),
});

export const MetaSectionSchema = z.object({
  mode: z.enum(['guided', 'quick']).default('guided'),
  /** Fields that were inferred by Claude in quick mode and still need user confirmation. */
  inferredFields: z.array(z.string()).default([]),
  /** Questions answered with "Not sure": the safer default was chosen and this records it (shown in the summary and report). */
  notSureFields: z.array(z.string()).default([]),
  /** Example project the profile was started from, if any. */
  startedFromExample: z.string().optional(),
  confirmed: z.boolean().default(false),
});

export const DesignProfileSchema = z.object({
  app: AppSectionSchema,
  users: UsersSectionSchema,
  data: DataSectionSchema,
  capabilities: CapabilitiesSchema.prefault({}),
  deployment: DeploymentSectionSchema,
  meta: MetaSectionSchema,
});
export type DesignProfile = z.infer<typeof DesignProfileSchema>;

/** A partially completed profile as saved between wizard steps (each section optional and partial). */
/**
 * A record or field as it is while the owner is still typing it. The saved answers are autosaved on every
 * keystroke, and the moment someone cleared "New record" to type their own name the save was refused for an
 * empty label — a red "Not saved yet" about the thing they were in the middle of doing. Drafts may be blank
 * here; the strict schema above still applies when the design is made, and the wizard says which record needs
 * a name before then.
 */
const DraftEntityFieldSchema = EntityFieldSchema.extend({ name: z.string().max(40), label: z.string().max(60) });
const DraftEntitySpecSchema = EntitySpecSchema.extend({
  name: z.string().max(40),
  label: z.string().max(60),
  fields: z.array(DraftEntityFieldSchema).max(40).default([]),
});

export const PartialDesignProfileSchema = z.object({
  app: AppSectionSchema.partial().extend({ entities: z.array(DraftEntitySpecSchema).max(20).optional() }).optional(),
  users: UsersSectionSchema.partial().optional(),
  data: DataSectionSchema.partial().optional(),
  capabilities: CapabilitiesSchema.partial().optional(),
  deployment: DeploymentSectionSchema.partial()
    .extend({ owner: DeploymentSectionSchema.shape.owner.partial().optional() })
    .optional(),
  meta: MetaSectionSchema.partial().optional(),
});
export type PartialDesignProfile = z.infer<typeof PartialDesignProfileSchema>;

export function profileHasSensitiveData(profile: Pick<DesignProfile, 'data'>): boolean {
  return profile.data.categories.some((c) => SENSITIVE_DATA_CATEGORIES.includes(c));
}

/** Any category that identifies people (drives the SbD "sensitive/regulated data" trigger and the target level). */
export function profileHasPersonalData(profile: Pick<DesignProfile, 'data'>): boolean {
  return (
    profile.data.aboutOtherPeople ||
    profile.data.categories.some((c) => c !== 'business-confidential' && c !== 'files' && c !== 'credentials')
  );
}

/**
 * Single target level used for ASVS and AISVS (AISVS level N assumes ASVS level N). Never L3 automatically.
 * L1 only when the audience is just-me / my-team AND no personal data is handled AND impact is not high
 * AND the app stays on this computer or the local network AND there is no AI assistant.
 */
export function targetLevel(
  profile: Pick<DesignProfile, 'data' | 'users' | 'deployment' | 'capabilities'>,
): { level: 1 | 2; rule: string } {
  const reasons: string[] = [];
  if (profileHasSensitiveData(profile)) reasons.push('it handles sensitive or regulated information');
  else if (profileHasPersonalData(profile)) reasons.push('it handles information about people');
  if (profile.users.audience === 'public' || profile.users.audience === 'customers')
    reasons.push('people outside your team will use it');
  if (profile.deployment.businessImpact === 'high') reasons.push('an outage or breach would seriously hurt your business');
  if (profile.deployment.target === 'internet-later') reasons.push('it is intended to go on the internet');
  if (profile.capabilities.aiAssistant.enabled) reasons.push('it includes an AI assistant that accepts untrusted input');
  if (reasons.length === 0) {
    return {
      level: 1,
      rule: 'Level 1 (baseline) because only you or your team use it, it stores no information about people, and it stays on your own computer or network.',
    };
  }
  return { level: 2, rule: `Level 2 (standard) because ${reasons.join('; ')}.` };
}
