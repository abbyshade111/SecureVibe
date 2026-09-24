/**
 * Every security decision is keyed on a small set of facts derived from the profile. This file is the single
 * place where those facts are computed, so the requirements, patterns, checklist, triage, threat model, build
 * spec and wizard copy all agree.
 */
import type { PatternCatalogEntry, SbdRule } from '@shared/knowledge.js';
import {
  profileHasPersonalData,
  profileHasSensitiveData,
  targetLevel,
  type DataCategory,
  type DeploymentTarget,
  type DesignProfile,
  type RoleSpec,
} from '@shared/profile.js';

export type TlsMode = 'off' | 'selfsigned' | 'proxy';
export type PatternWhen = PatternCatalogEntry['when'];
export type SbdWhen = SbdRule['outcomes'][number]['when'];

export interface ProfileFacts {
  appName: string;
  /** Sign-in is on. See `needsAccounts` for the reasons. */
  auth: boolean;
  /** Why sign-in is on (plain language fragments), empty when sign-in is off. */
  authReasons: string[];
  /** Whether the owner's organisation runs a central sign-in system, as answered in the wizard. */
  centralSignIn: 'yes' | 'no' | 'not-sure';
  level: 1 | 2;
  levelRule: string;
  personalData: boolean;
  sensitiveData: boolean;
  /** At least one entity field is marked sensitive. */
  sensitiveFields: boolean;
  fieldEncryption: boolean;
  adminMfa: boolean;
  userMfa: boolean;
  uploads: boolean;
  ai: boolean;
  aiActions: boolean;
  aiWebSearch: boolean;
  aiModeration: boolean;
  aiHistory: boolean;
  email: boolean;
  scheduler: boolean;
  publicApi: boolean;
  payments: boolean;
  retentionJobs: boolean;
  externalApis: boolean;
  deployment: DeploymentTarget;
  tlsMode: TlsMode;
  lanBinding: boolean;
  internet: boolean;
  lan: boolean;
  tls: boolean;
  /** Customers or the public use the app (people outside the owner's team). */
  publicAudience: boolean;
  highImpact: boolean;
  /** Effective roles: the profile's roles with exactly one administrator guaranteed when sign-in is on. */
  roles: RoleSpec[];
  adminRole: RoleSpec | undefined;
  personalCategories: DataCategory[];
  sensitiveCategories: DataCategory[];
}

export const TLS_MODE_BY_DEPLOYMENT: Record<DeploymentTarget, TlsMode> = {
  'local-only': 'off',
  'local-network': 'selfsigned',
  'internet-later': 'proxy',
};

const SENSITIVE: readonly DataCategory[] = ['financial', 'payment-card', 'health', 'government-id', 'children'];
const NON_PERSONAL: readonly DataCategory[] = ['business-confidential', 'files', 'credentials'];

export function profileFacts(profile: DesignProfile): ProfileFacts {
  const caps = profile.capabilities;
  const users = profile.users;
  const ai = caps.aiAssistant.enabled;
  const entities = profile.app.entities;
  const sensitiveFields = entities.some((e) => e.fields.some((f) => f.sensitive));
  const hasFileField = entities.some((e) => e.fields.some((f) => f.type === 'file'));
  const uploads = caps.fileUploads || hasFileField || profile.data.categories.includes('files');
  const payments = caps.payments || profile.data.categories.includes('payment-card');

  // Sign-in is on when the user asked for it, when anyone beyond the owner uses the app, or when a feature needs
  // accounts to attribute records, quotas and budgets to a person (uploads, AI assistant, API keys, payments).
  const authReasons: string[] = [];
  if (users.requiresSignIn) authReasons.push('you asked for sign-in');
  if (users.audience !== 'just-me') authReasons.push('more than one person will use it');
  if (uploads) authReasons.push('uploaded files need an owner');
  if (ai) authReasons.push('the AI assistant works per signed-in person');
  if (caps.publicApi) authReasons.push('API keys belong to a person');
  if (payments) authReasons.push('payments need an account to belong to');
  const auth = authReasons.length > 0;

  const sensitiveData = profileHasSensitiveData(profile);
  const personalData = profileHasPersonalData(profile);
  const level = targetLevel(profile);
  const fieldEncryption = sensitiveData || sensitiveFields;
  const publicAudience = users.audience === 'customers' || users.audience === 'public';
  const retentionJobs = profile.data.retention === 'auto-delete-after-period';
  const email = caps.email || (auth && (users.registration === 'open' || users.registration === 'invite-only'));
  const tlsMode = TLS_MODE_BY_DEPLOYMENT[profile.deployment.target];

  return {
    appName: profile.app.name,
    auth,
    authReasons,
    centralSignIn: users.centralSignIn,
    level: level.level,
    levelRule: level.rule,
    personalData,
    sensitiveData,
    sensitiveFields,
    fieldEncryption,
    adminMfa: auth && (users.adminMfa || sensitiveData || sensitiveFields),
    userMfa: auth && level.level === 2,
    uploads,
    ai,
    aiActions: ai && caps.aiAssistant.canTakeActions,
    aiWebSearch: ai && caps.aiAssistant.canSearchWeb === true,
    aiModeration: ai && publicAudience,
    aiHistory: ai && caps.aiAssistant.storesHistory,
    email,
    scheduler: caps.scheduledJobs || retentionJobs,
    publicApi: caps.publicApi,
    payments,
    retentionJobs,
    externalApis: caps.externalApis.length > 0,
    deployment: profile.deployment.target,
    tlsMode,
    lanBinding: profile.deployment.target === 'local-network',
    internet: profile.deployment.target === 'internet-later',
    lan: profile.deployment.target === 'local-network',
    tls: tlsMode !== 'off',
    publicAudience,
    highImpact: profile.deployment.businessImpact === 'high',
    roles: effectiveRoles(profile, auth),
    adminRole: effectiveRoles(profile, auth).find((r) => r.isAdmin),
    personalCategories: profile.data.categories.filter((c) => !NON_PERSONAL.includes(c)),
    sensitiveCategories: profile.data.categories.filter((c) => SENSITIVE.includes(c)),
  };
}

/** The profile's roles with exactly one administrator role guaranteed; a "member" role when others need one. */
export function effectiveRoles(profile: DesignProfile, auth: boolean): RoleSpec[] {
  if (!auth) return [];
  const roles: RoleSpec[] = [];
  let adminSeen = false;
  for (const role of profile.users.roles) {
    if (role.isAdmin) {
      if (adminSeen) {
        roles.push({ ...role, isAdmin: false });
        continue;
      }
      adminSeen = true;
    }
    roles.push({ ...role });
  }
  if (!adminSeen) {
    roles.unshift({
      name: 'admin',
      label: 'Administrator',
      description: 'Manages accounts, settings and the audit log.',
      isAdmin: true,
    });
  }
  const hasNonAdmin = roles.some((r) => !r.isAdmin);
  if (!hasNonAdmin && profile.users.audience !== 'just-me') {
    roles.push({ name: 'member', label: 'Member', description: 'A regular signed-in person.', isAdmin: false });
  }
  return roles;
}

export function matchesPatternWhen(when: PatternWhen, f: ProfileFacts): boolean {
  switch (when) {
    case 'always':
      return true;
    case 'auth':
      return f.auth;
    case 'sensitive-data':
      return f.sensitiveData || f.sensitiveFields;
    case 'personal-data':
      return f.personalData;
    case 'uploads':
      return f.uploads;
    case 'ai':
      return f.ai;
    case 'ai-actions':
      return f.aiActions;
    case 'email':
      return f.email;
    case 'external-apis':
      // For patterns, "external-apis" means any outbound connection (CONTRACTS §5: PAT-EGRESS-ALLOWLIST
      // applies to external APIs, the AI provider and the mail server alike).
      return f.externalApis || f.ai || f.email;
    case 'public-api':
      return f.publicApi;
    case 'payments':
      return f.payments;
    case 'internet':
      return f.internet;
    case 'lan':
      return f.lan;
    case 'scheduler':
      return f.scheduler;
    case 'level2':
      return f.level === 2;
  }
}

export function matchesSbdWhen(when: SbdWhen, f: ProfileFacts, attested: boolean): boolean {
  switch (when) {
    case 'always':
      return true;
    case 'local-only':
      return f.deployment === 'local-only';
    case 'local-network':
      return f.deployment === 'local-network';
    case 'internet-later':
      return f.deployment === 'internet-later';
    case 'auth':
      return f.auth;
    case 'no-auth':
      return !f.auth;
    case 'no-central-sign-in':
      // Answered in the wizard: there is no organisation-wide sign-in system to connect the app to.
      return f.centralSignIn === 'no';
    case 'sensitive-data':
      return f.sensitiveData || f.sensitiveFields;
    case 'personal-data':
      return f.personalData;
    case 'ai':
      return f.ai;
    case 'external-apis':
      return f.externalApis;
    case 'email':
      return f.email;
    case 'scheduler':
      return f.scheduler;
    case 'uploads':
      return f.uploads;
    case 'attested':
      return attested;
  }
}

/** Plain-language labels for data categories (used in sentences shown to the owner). */
export const DATA_CATEGORY_LABELS: Record<DataCategory, string> = {
  contact: 'contact details',
  financial: 'financial information',
  'payment-card': 'payment card details',
  health: 'health information',
  'government-id': 'government ID numbers',
  credentials: 'passwords',
  children: 'information about children',
  location: 'location data',
  files: 'uploaded files',
  'business-confidential': 'confidential business information',
  'other-personal': 'other personal information',
};

export function listWords(items: string[]): string {
  if (items.length === 0) return '';
  if (items.length === 1) return items[0] ?? '';
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

export function audiencePhrase(profile: DesignProfile): string {
  switch (profile.users.audience) {
    case 'just-me':
      return 'only you';
    case 'my-team':
      return 'you and your team';
    case 'customers':
      return 'your customers';
    case 'public':
      return 'anyone on the internet';
  }
}

export function deploymentPhrase(profile: DesignProfile): string {
  switch (profile.deployment.target) {
    case 'local-only':
      return 'on this computer only';
    case 'local-network':
      return 'on your local network';
    case 'internet-later':
      return 'on this computer now, and on the internet later';
  }
}
