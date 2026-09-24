/**
 * "Here is what we will build": a 3-6 sentence plain-language summary, one bullet per consequence for the owner,
 * and the assumptions made on their behalf ("Not sure" answers and quick-mode inferences).
 */
import type { RiskTriage, ThreatModel } from '@shared/design.js';
import type { DesignProfile } from '@shared/profile.js';
import { DATA_CATEGORY_LABELS, audiencePhrase, deploymentPhrase, listWords, type ProfileFacts } from './conditions.js';
import { aiDataPhrase } from './requirements.js';

const CATEGORY_PHRASES: Record<DesignProfile['app']['category'], string> = {
  tracker: 'a tracking app',
  booking: 'a booking app',
  inventory: 'an inventory app',
  content: 'a content app',
  dashboard: 'a reporting dashboard',
  'intake-form': 'a forms app',
  crm: 'a customer records app',
  'ai-assistant': 'an AI assistant app',
  marketplace: 'a marketplace app',
  'internal-tool': 'an internal tool',
  other: 'a web app',
};

export function plainLanguageSummary(profile: DesignProfile, f: ProfileFacts, triage: RiskTriage, threatModel: ThreatModel): string {
  const name = f.appName;
  const sentences: string[] = [];

  sentences.push(`${name} is ${CATEGORY_PHRASES[profile.app.category]} for ${audiencePhrase(profile)} that runs ${deploymentPhrase(profile)}.`);

  if (f.auth) {
    sentences.push(
      `People sign in with a password${f.adminMfa ? ' (administrators also confirm with an authenticator app)' : ''}, and each role (${listWords(f.roles.map((r) => r.label.toLowerCase()))}) only sees what it needs.`,
    );
  } else {
    sentences.push('There is no sign-in: only someone using this computer can open it.');
  }

  if (f.personalData || f.fieldEncryption) {
    const words = listWords([...new Set([...f.personalCategories, ...f.sensitiveCategories])].map((c) => DATA_CATEGORY_LABELS[c])) || 'information about people';
    const kept =
      profile.data.retention === 'auto-delete-after-period'
        ? `records are deleted automatically after ${profile.data.retentionMonths ?? 12} months`
        : 'records are kept until an administrator deletes them';
    sentences.push(`It handles ${words}, so ${f.fieldEncryption ? 'sensitive fields are encrypted and ' : ''}${kept}.`);
  } else {
    sentences.push('It stores only business information, nothing about people.');
  }

  const extras: string[] = [];
  if (f.uploads) extras.push('accepts uploaded files that are checked before they are stored');
  if (f.ai) extras.push(`has an AI assistant that only sees ${aiDataPhrase(profile)}${f.aiActions ? ' and must ask before changing anything' : ''}`);
  if (f.payments) extras.push("takes payments on the provider's own page so card numbers never touch it");
  if (f.publicApi) extras.push('lets other programs connect with API keys');
  if (extras.length) sentences.push(`It also ${listWords(extras)}.`);

  sentences.push(
    'Standard protections (checked input, safe error pages, rate limits and a tamper-evident log) are built in and will be tested after the build.',
  );

  if (triage.extraCareLabel === 'Extra care') {
    const open = threatModel.threats.filter((t) => t.status !== 'mitigated').length;
    sentences.push(
      `This design gets extra care: a threat model lists ${threatModel.threats.length} ways things could go wrong${open === 0 ? ', all covered by built-in protections' : `, and ${open} of them ${open === 1 ? 'needs' : 'need'} an action from you`}.`,
    );
  }

  return sentences.slice(0, 6).join(' ');
}

/**
 * SecureVibe describing itself (`npm run self-assess`): the generic sentences assume a generated web app with
 * accounts and an in-app assistant, which is not what SecureVibe is.
 */
export function selfAssessmentSummary(threatModel: ThreatModel): string {
  const open = threatModel.threats.filter((t) => t.status !== 'mitigated').length;
  return [
    'SecureVibe is a local tool for one person that runs on this computer only and listens on 127.0.0.1.',
    'It has no accounts: a browser gets a session only by opening the private startup link SecureVibe prints, and every request is checked for its host, its origin and a security token.',
    'Designs, generated applications and reports stay on this computer; only what is needed to design, write and review code is sent to the Anthropic API, and only when a key is configured.',
    "Code it generates runs under Node's permission model, limited to that project's folder, with time limits and a minimal environment.",
    `A threat model lists ${threatModel.threats.length} ways things could go wrong${open === 0 ? ', all covered by built-in protections' : `, and ${open} of them ${open === 1 ? 'needs' : 'need'} an action from the owner`}.`,
  ].join(' ');
}

export function consequencesFor(profile: DesignProfile, f: ProfileFacts): string[] {
  const out: string[] = [];
  const name = f.appName;
  if (f.auth) {
    out.push('People must sign in');
    out.push('The first administrator gets a one-time password that must be changed at first sign-in');
    if (f.adminMfa) out.push('Administrators need an authenticator app on their phone');
    if (f.userMfa) out.push('Every person can turn on an authenticator app for their own account');
    if (profile.users.registration === 'open') out.push('Anyone can create an account (limited to a few sign-ups per hour per address)');
    if (profile.users.registration === 'invite-only') out.push('New people join only through an invitation from an administrator');
    if (profile.users.registration === 'admin-created') out.push('An administrator creates every account');
    out.push(`Sessions end after ${f.level === 2 ? 15 : 30} minutes without activity and after ${f.level === 2 ? 8 : 12} hours at most`);
  } else {
    out.push('No sign-in: anyone who can use this computer can open the app');
  }
  if (f.fieldEncryption) out.push('Sensitive fields are encrypted; the key lives in the .env file, which must be backed up safely');
  if (f.personalData) {
    out.push(
      profile.data.retention === 'auto-delete-after-period'
        ? `Records about people are deleted automatically after ${profile.data.retentionMonths ?? 12} months and cannot be recovered afterwards`
        : "Someone must act on requests to export or delete a person's data (the admin pages make this a few clicks)",
    );
    out.push('A data protection note lists what is stored, why, and which privacy rules may apply');
  }
  if (f.uploads) out.push('Uploads are limited to images and PDFs up to 10 MB each, with a storage quota per person');
  if (f.ai) {
    out.push('The AI assistant needs an Anthropic API key and costs money per use (each person has a daily budget)');
    out.push('Messages to the assistant leave this computer and go to the AI provider');
    if (f.aiActions) out.push('The assistant can suggest changes, but a person must confirm each one');
    if (f.aiModeration) out.push('Messages to and from the assistant are screened for harmful content');
  }
  if (f.email) out.push('Emails are saved to a local outbox folder until an email server is set up');
  if (f.scheduler) out.push('Background jobs run inside the app while it is running');
  if (f.publicApi) out.push('Other programs need an API key, created by a signed-in person, to connect');
  if (f.payments) out.push('Payments need a provider account before they work; until then the checkout page is a placeholder');
  if (f.externalApis) out.push(`${name} talks to ${listWords(profile.capabilities.externalApis.map((a) => a.name))}; their addresses must be listed in the configuration file`);
  if (f.deployment === 'local-only') out.push('The app only works on this computer; sharing it later means changing that answer and rebuilding');
  if (f.deployment === 'local-network') out.push('Browsers will warn about the app\'s own certificate the first time; the guide explains how to trust it');
  if (f.deployment === 'internet-later') out.push('Before going online you must set up an HTTPS proxy and follow the "going online" checklist');
  if (f.highImpact) out.push('Because an outage would seriously hurt the business, every missing protection is treated as more serious');
  out.push(`${profile.deployment.owner.name} is the security contact named in the incident plan`);
  return out;
}

interface FieldPhrase {
  question: string;
  value: (p: DesignProfile) => string;
}

/** Plain words for the look that was chosen; the colors are all a theme changes. */
const THEME_PHRASES: Record<DesignProfile['app']['theme'], string> = {
  calm: 'the calm look (quiet grays and blue)',
  warm: 'the warm look (cream and amber)',
  forest: 'the forest look (greens)',
  contrast: 'the high-contrast look (black on white)',
};

const yesNo = (v: boolean, yes: string, no: string) => (v ? yes : no);

const FIELD_PHRASES: Record<string, FieldPhrase> = {
  'app.category': { question: 'what kind of app it is', value: (p) => CATEGORY_PHRASES[p.app.category] },
  'app.entities': { question: 'which records it keeps', value: (p) => listWords(p.app.entities.map((e) => e.pluralLabel ?? e.label)) || 'no records yet' },
  'app.keyFeatures': { question: 'which features it needs', value: (p) => listWords(p.app.keyFeatures) || 'no extra features' },
  'app.theme': { question: 'how it should look', value: (p) => THEME_PHRASES[p.app.theme] },
  'users.audience': { question: 'who will use it', value: (p) => audiencePhrase(p) },
  'users.requiresSignIn': { question: 'whether people should sign in', value: (p) => yesNo(p.users.requiresSignIn, 'people must sign in', 'no sign-in') },
  'users.roles': { question: 'which roles exist', value: (p) => listWords(p.users.roles.map((r) => r.label)) || 'administrator only' },
  'users.expectedUserCount': { question: 'how many people will use it', value: (p) => `${p.users.expectedUserCount} people` },
  'users.registration': {
    question: 'how people get an account',
    value: (p) => ({ 'invite-only': 'by invitation', 'admin-created': 'created by an administrator', open: 'open sign-up' })[p.users.registration],
  },
  'users.adminMfa': { question: 'whether administrators use an authenticator app', value: (p) => yesNo(p.users.adminMfa, 'yes, they do', 'no') },
  'data.categories': {
    question: 'what kinds of information it handles',
    value: (p) => listWords(p.data.categories.map((c) => DATA_CATEGORY_LABELS[c])) || 'business records only',
  },
  'data.aboutOtherPeople': { question: 'whether it holds information about other people', value: (p) => yesNo(p.data.aboutOtherPeople, 'yes, it does', 'no') },
  'data.retention': {
    question: 'how long records are kept',
    value: (p) => (p.data.retention === 'auto-delete-after-period' ? `deleted after ${p.data.retentionMonths ?? 12} months` : 'kept until deleted'),
  },
  'data.retentionMonths': { question: 'how many months records are kept', value: (p) => `${p.data.retentionMonths ?? 12} months` },
  'data.region': { question: 'which region the people are in', value: (p) => ({ 'eu-uk': 'EU or UK', us: 'United States', other: 'another region', unsure: 'unknown region' })[p.data.region] },
  'capabilities.fileUploads': { question: 'whether people upload files', value: (p) => yesNo(p.capabilities.fileUploads, 'yes', 'no uploads') },
  'capabilities.uploadKinds': { question: 'which kinds of files are uploaded', value: (p) => listWords(p.capabilities.uploadKinds) || 'documents' },
  'capabilities.aiAssistant': { question: 'whether it has an AI assistant', value: (p) => yesNo(p.capabilities.aiAssistant.enabled, 'yes', 'no AI assistant') },
  'capabilities.aiAssistant.enabled': { question: 'whether it has an AI assistant', value: (p) => yesNo(p.capabilities.aiAssistant.enabled, 'yes', 'no AI assistant') },
  'capabilities.aiAssistant.dataItCanSee': { question: 'what the assistant may see', value: (p) => aiDataPhrase(p) },
  'capabilities.aiAssistant.canTakeActions': { question: 'whether the assistant may change data', value: (p) => yesNo(p.capabilities.aiAssistant.canTakeActions, 'yes, with confirmation', 'no, answers only') },
  'capabilities.aiAssistant.storesHistory': { question: 'whether the assistant remembers conversations', value: (p) => yesNo(p.capabilities.aiAssistant.storesHistory, 'yes', 'no') },
  'capabilities.email': { question: 'whether it sends email', value: (p) => yesNo(p.capabilities.email, 'yes', 'no') },
  'capabilities.externalApis': { question: 'which outside services it uses', value: (p) => listWords(p.capabilities.externalApis.map((a) => a.name)) || 'none' },
  'capabilities.scheduledJobs': { question: 'whether it runs scheduled jobs', value: (p) => yesNo(p.capabilities.scheduledJobs, 'yes', 'no') },
  'capabilities.publicApi': { question: 'whether other programs connect to it', value: (p) => yesNo(p.capabilities.publicApi, 'yes, with API keys', 'no') },
  'capabilities.payments': { question: 'whether it takes payments', value: (p) => yesNo(p.capabilities.payments, 'yes, through a provider', 'no') },
  'deployment.target': { question: 'where it will run', value: (p) => deploymentPhrase(p) },
  'deployment.businessImpact': {
    question: 'how bad a day of downtime would be',
    value: (p) => ({ low: 'a minor inconvenience', normal: 'a real problem', high: 'a serious hit to the business' })[p.deployment.businessImpact],
  },
};

function lookup(profile: DesignProfile, path: string): unknown {
  return path.split('.').reduce<unknown>((cur, key) => (cur && typeof cur === 'object' ? (cur as Record<string, unknown>)[key] : undefined), profile);
}

function describe(profile: DesignProfile, field: string): { question: string; value: string } {
  const known = FIELD_PHRASES[field];
  if (known) return { question: known.question, value: known.value(profile) };
  const raw = lookup(profile, field);
  const value = raw === undefined ? 'the default' : typeof raw === 'string' ? raw : JSON.stringify(raw);
  return { question: `"${field.split('.').pop() ?? field}"`, value };
}

/** One sentence per "Not sure" answer and per quick-mode inference (a field in both lists gets one sentence). */
export function assumptionsMade(profile: DesignProfile): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const field of profile.meta.notSureFields) {
    if (seen.has(field)) continue;
    seen.add(field);
    const d = describe(profile, field);
    out.push(`You were not sure about ${d.question}, so we chose the safer option: ${d.value}.`);
  }
  for (const field of profile.meta.inferredFields) {
    if (seen.has(field)) continue;
    seen.add(field);
    const d = describe(profile, field);
    out.push(`From your description we assumed ${d.question}: ${d.value}. Please check this.`);
  }
  return out;
}
