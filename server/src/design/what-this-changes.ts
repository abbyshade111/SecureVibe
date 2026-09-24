/**
 * "What this changes": the plain-language controls each wizard answer turns on. Works on a partial profile so the
 * wizard can show it live while the person is still answering. Sentences come from data/knowledge/wizard-copy.json
 * (`whatThisChanges` keyed by condition id) when present, otherwise from the built-in catalog below.
 *
 * Output keys are the wizard step ids from shared/src/api.ts WIZARD_STEPS: about, users, data, features, deployment.
 */
import { SENSITIVE_DATA_CATEGORIES, type DataCategory, type PartialDesignProfile } from '@shared/profile.js';
import { DATA_CATEGORY_LABELS, listWords } from './conditions.js';
import type { WizardCopyView } from './types.js';

export type WhatThisChangesKey = 'about' | 'users' | 'data' | 'features' | 'deployment';

/** Condition ids (the keys wizard-copy.json may override). Placeholders: {appName} {months} {roles} {dataWords} {apis} {owner}. */
export const WHAT_THIS_CHANGES_BUILTIN: Record<string, string> = {
  always:
    'Every app we build gets the same base: strict browser security headers, every input checked on the server, rate limits, safe error pages, and a tamper-evident log.',
  'sensitive-fields': 'Fields you marked sensitive are encrypted in the database and never written to logs or web addresses.',
  auth: 'People must sign in with a password (12 characters or more) before using {appName}. Repeated wrong guesses lock the account for a while.',
  'no-auth': 'No sign-in: {appName} only answers on this computer, so only someone using this computer can open it.',
  'needs-accounts': 'Because of the features you chose (uploads, an AI assistant, API keys or payments), people must sign in so records, quotas and budgets belong to someone.',
  roles: 'Each role ({roles}) only sees the pages and records it needs. An administrator role always exists.',
  'admin-mfa': 'Administrators need an authenticator app on their phone (a second code at sign-in).',
  'admin-mfa-forced': 'Because {appName} handles sensitive information, administrators must use an authenticator app (a second code at sign-in).',
  'user-mfa': 'Every person can turn on an authenticator app for their own account.',
  'registration-open': 'Anyone can create an account. Sign-ups are limited per address so robots cannot flood {appName}.',
  'registration-invite': 'People join only through an invitation link sent by an administrator.',
  'registration-admin': 'An administrator creates every account. Nobody can sign up on their own.',
  'public-audience': 'Because people outside your team will use it, {appName} gets stricter rate limits and targets verification level 2 (standard).',
  'personal-data': 'Because {appName} holds information about people ({dataWords}), it lists what is kept and why, names {owner} as the person responsible, and can export or delete a person\'s data on request.',
  'sensitive-data': 'Because {appName} handles {dataWords}, sensitive fields are encrypted in the database, administrators must use an authenticator app, and the app targets verification level 2 (standard).',
  'business-only': '{appName} stores only business information, nothing about people, so no privacy notice or retention job is needed.',
  'retention-auto': 'Records about people are deleted automatically after {months} months by a scheduled job.',
  'retention-manual': 'Records are kept until deleted. Administrators can export or delete a person\'s data on request.',
  region: 'The privacy rules that may apply in your region (for example GDPR, CCPA or HIPAA) are named in the data protection note for your developer.',
  uploads: 'Uploaded files are checked for type and size (images and PDFs up to 10 MB), renamed, stored outside the web folder, and downloaded as attachments.',
  ai: 'The AI assistant treats every message as untrusted, screens it for trickery, checks every answer before showing it, logs its cost, and can be switched off by an administrator.',
  'ai-data': 'The assistant only sees {aiData}, always through the signed-in person\'s own permissions.',
  'ai-actions': 'The assistant can propose a change, but nothing happens until the person confirms it.',
  'ai-moderation': 'Because customers or the public use the assistant, messages to and from it are screened for harmful content.',
  'ai-history': 'Conversation history belongs to one person, is never shown to others, and can be cleared.',
  'ai-key': 'The assistant needs an Anthropic API key and costs money per use. Each person gets a daily budget.',
  email: 'Emails are cleaned before sending so nobody can add hidden recipients. Until an email server is set up, emails are saved to a local outbox folder.',
  'external-apis': '{appName} only talks to the outside services you named ({apis}). Each call has a time limit, and a failure never takes the app down.',
  'external-apis-personal': 'Personal data sent to {apis} is kept to the minimum and listed in the data protection note.',
  scheduler: 'Scheduled jobs run one at a time, never overlap, and record what they did.',
  'public-api': 'Other programs connect with API keys that a signed-in person creates and can revoke. Keys are never accepted in a web address.',
  payments: '{appName} never sees or stores card numbers. Payments happen on the provider\'s own page. You will need a provider account before payments work.',
  'local-only': '{appName} listens on this computer only. Nothing else on the network can reach it, so no HTTPS certificate is needed.',
  'local-network': '{appName} is reachable on your local network over an encrypted (HTTPS) connection with its own certificate. Browsers will warn about that certificate the first time.',
  'internet-later': '{appName} stays on this computer until it is put behind an HTTPS proxy. We include a step-by-step "going online" guide, and some checks stay marked "before going online".',
  'high-impact': 'Because an outage or breach would seriously hurt your business, every missing protection is treated as more serious and the design gets extra care.',
  owner: '{owner} is named as the security contact in the incident plan and the reports.',
};

type Partial_ = PartialDesignProfile;

interface PartialFacts {
  appName: string;
  owner: string;
  hasUsers: boolean;
  hasData: boolean;
  hasCaps: boolean;
  hasDeployment: boolean;
  uploads: boolean;
  ai: boolean;
  aiActions: boolean;
  aiHistory: boolean;
  aiData: string;
  payments: boolean;
  publicApi: boolean;
  email: boolean;
  scheduler: boolean;
  externalApis: { name: string; sendsPersonalData: boolean }[];
  featureNeedsAccounts: boolean;
  auth: boolean;
  publicAudience: boolean;
  sensitiveData: boolean;
  sensitiveFields: boolean;
  personalData: boolean;
  personalWords: string;
  sensitiveWords: string;
  retentionAuto: boolean;
  retentionMonths: number;
  highImpact: boolean;
  target: string | undefined;
  level2: boolean;
  roles: string[];
}

function partialFacts(p: Partial_): PartialFacts {
  const app = p.app;
  const users = p.users;
  const data = p.data;
  const caps = p.capabilities;
  const dep = p.deployment;
  const categories: DataCategory[] = data?.categories ?? [];
  const entities = app?.entities ?? [];
  const uploads = caps?.fileUploads === true || categories.includes('files') || entities.some((e) => e.fields.some((f) => f.type === 'file'));
  const ai = caps?.aiAssistant?.enabled === true;
  const payments = caps?.payments === true || categories.includes('payment-card');
  const publicApi = caps?.publicApi === true;
  const featureNeedsAccounts = uploads || ai || payments || publicApi;
  const askedForSignIn = users?.requiresSignIn === true || (users?.audience !== undefined && users.audience !== 'just-me');
  const auth = askedForSignIn || featureNeedsAccounts;
  const publicAudience = users?.audience === 'customers' || users?.audience === 'public';
  const sensitiveCategories = categories.filter((c) => SENSITIVE_DATA_CATEGORIES.includes(c));
  const personalCategories = categories.filter((c) => c !== 'business-confidential' && c !== 'files' && c !== 'credentials');
  const sensitiveFields = entities.some((e) => e.fields.some((f) => f.sensitive));
  const personalData = data?.aboutOtherPeople === true || personalCategories.length > 0;
  const highImpact = dep?.businessImpact === 'high';
  const target = dep?.target;
  const registration = users?.registration;
  const email = caps?.email === true || (auth && (registration === 'open' || registration === 'invite-only'));
  const retentionAuto = data?.retention === 'auto-delete-after-period';
  const level2 = sensitiveCategories.length > 0 || personalData || publicAudience || highImpact || target === 'internet-later' || ai;
  const aiData = {
    nothing: 'the message a person types (no stored records)',
    'users-own-records': "the signed-in person's own records",
    'all-records': 'the records the signed-in person is allowed to see',
  }[caps?.aiAssistant?.dataItCanSee ?? 'nothing'];
  const roleLabels = (users?.roles ?? []).map((r) => r.label);
  return {
    appName: app?.name?.trim() || 'Your app',
    owner: dep?.owner?.name?.trim() || 'the owner',
    hasUsers: users !== undefined,
    hasData: data !== undefined,
    hasCaps: caps !== undefined,
    hasDeployment: dep !== undefined,
    uploads,
    ai,
    aiActions: ai && caps?.aiAssistant?.canTakeActions === true,
    aiHistory: ai && caps?.aiAssistant?.storesHistory === true,
    aiData,
    payments,
    publicApi,
    email,
    scheduler: caps?.scheduledJobs === true || retentionAuto,
    externalApis: (caps?.externalApis ?? []).map((a) => ({ name: a.name, sendsPersonalData: a.sendsPersonalData })),
    featureNeedsAccounts,
    auth,
    publicAudience,
    sensitiveData: sensitiveCategories.length > 0,
    sensitiveFields,
    personalData,
    personalWords: listWords(personalCategories.map((c) => DATA_CATEGORY_LABELS[c])) || 'personal details',
    sensitiveWords: listWords(sensitiveCategories.map((c) => DATA_CATEGORY_LABELS[c])),
    retentionAuto,
    retentionMonths: data?.retentionMonths ?? 12,
    highImpact,
    target,
    level2,
    roles: roleLabels.length ? roleLabels : ['Administrator', 'Member'],
  };
}

function sentenceFor(id: string, f: PartialFacts, copy?: WizardCopyView): string[] {
  const override = copy?.whatThisChanges?.[id];
  const raw = override === undefined ? WHAT_THIS_CHANGES_BUILTIN[id] : override;
  if (raw === undefined) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  const apis = listWords(f.externalApis.map((a) => a.name));
  const personalApis = listWords(f.externalApis.filter((a) => a.sendsPersonalData).map((a) => a.name));
  return list.map((s) =>
    s
      .replaceAll('{appName}', f.appName)
      .replaceAll('{owner}', f.owner)
      .replaceAll('{months}', String(f.retentionMonths))
      .replaceAll('{roles}', listWords(f.roles))
      .replaceAll('{dataWords}', id === 'sensitive-data' ? f.sensitiveWords : f.personalWords)
      .replaceAll('{apis}', id === 'external-apis-personal' ? personalApis : apis)
      .replaceAll('{aiData}', f.aiData),
  );
}

/**
 * Plain-language statements per wizard step for the answers given so far. Missing sections produce empty lists,
 * so the wizard can call this after every keystroke.
 */
export function whatThisChanges(
  partial: PartialDesignProfile,
  wizardCopy?: WizardCopyView | Record<string, unknown>,
): Record<WhatThisChangesKey, string[]> {
  const copy = wizardCopy as WizardCopyView | undefined;
  const f = partialFacts(partial);
  const out: Record<WhatThisChangesKey, string[]> = { about: [], users: [], data: [], features: [], deployment: [] };
  const push = (key: WhatThisChangesKey, id: string) => out[key].push(...sentenceFor(id, f, copy));

  if (partial.app !== undefined) {
    push('about', 'always');
    if (f.sensitiveFields) push('about', 'sensitive-fields');
  }

  if (f.hasUsers) {
    if (f.auth) {
      push('users', 'auth');
      if (partial.users?.roles?.length) push('users', 'roles');
      if (partial.users?.registration === 'open') push('users', 'registration-open');
      else if (partial.users?.registration === 'invite-only') push('users', 'registration-invite');
      else if (partial.users?.registration === 'admin-created') push('users', 'registration-admin');
      if (f.sensitiveData || f.sensitiveFields) push('users', 'admin-mfa-forced');
      else if (partial.users?.adminMfa !== false) push('users', 'admin-mfa');
      if (f.level2) push('users', 'user-mfa');
    } else {
      push('users', 'no-auth');
    }
    if (f.publicAudience) push('users', 'public-audience');
  }

  if (f.hasData) {
    if (f.sensitiveData) push('data', 'sensitive-data');
    if (f.personalData) {
      push('data', 'personal-data');
      push('data', f.retentionAuto ? 'retention-auto' : 'retention-manual');
      push('data', 'region');
    } else if (!f.sensitiveData) {
      push('data', 'business-only');
    }
    if (partial.data?.categories?.includes('payment-card')) push('data', 'payments');
  }

  if (f.hasCaps) {
    if (f.featureNeedsAccounts && partial.users !== undefined && !(partial.users.requiresSignIn === true) && (partial.users.audience === 'just-me' || partial.users.audience === undefined)) {
      push('features', 'needs-accounts');
    }
    if (f.uploads) push('features', 'uploads');
    if (f.ai) {
      push('features', 'ai');
      push('features', 'ai-data');
      if (f.aiActions) push('features', 'ai-actions');
      if (f.publicAudience) push('features', 'ai-moderation');
      if (f.aiHistory) push('features', 'ai-history');
      push('features', 'ai-key');
    }
    if (f.email) push('features', 'email');
    if (f.externalApis.length) {
      push('features', 'external-apis');
      if (f.externalApis.some((a) => a.sendsPersonalData)) push('features', 'external-apis-personal');
    }
    if (f.scheduler) push('features', 'scheduler');
    if (f.publicApi) push('features', 'public-api');
    if (partial.capabilities?.payments) push('features', 'payments');
  }

  if (f.hasDeployment) {
    if (f.target === 'local-only') push('deployment', 'local-only');
    else if (f.target === 'local-network') push('deployment', 'local-network');
    else if (f.target === 'internet-later') push('deployment', 'internet-later');
    if (f.highImpact) push('deployment', 'high-impact');
    if (partial.deployment?.owner?.name) push('deployment', 'owner');
  }

  return out;
}
