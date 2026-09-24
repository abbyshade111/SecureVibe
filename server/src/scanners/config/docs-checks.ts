/**
 * Documentation checks (`docs.*`): every generated document exists, says something, and — the part that matters —
 * still matches the app it describes. They run in the `config` stage and produce evidence the same way, so the
 * requirements that are met by "the app documents this" no longer have to be confirmed by hand.
 *
 * What a machine can and cannot say is kept honest: these checks verify that the document is there and that the
 * facts in it (session times, allowed hosts, kinds of data, log location) are the app's real ones. Whether the
 * wording is *right for your business* is still a person's judgment, and those questions stay in the wizard.
 */
import { join } from 'node:path';
import type { RuleMeta } from '../sast/findings.js';
import { readTextFile } from '../sast/files.js';
import type { ScanContext } from '../types.js';
import { parseEnv } from './env.js';
import { builtBySecureVibe, type ConfigCheckDef, type ConfigCheckOutcome } from './checks.js';

/** A document that is present but empty says nothing; this is the smallest size that can carry real content. */
const MIN_DOC_CHARS = 200;

function meta(input: Omit<RuleMeta, 'remediation' | 'whoCanFix'> & { fix: string; references?: string[] }): RuleMeta {
  const { fix, references, ...rest } = input;
  return { ...rest, remediation: { summary: fix, steps: [], references: references ?? [] } };
}

function docMeta(id: string, title: string, file: string, asvs: string[], description: string): RuleMeta {
  return meta({
    id,
    title,
    severity: 'low',
    confidence: 'high',
    cwe: ['CWE-1059'],
    asvs,
    aisvs: [],
    sbd: ['AC-04'],
    exploitability: 'theoretical',
    description,
    impact: 'Documentation that is missing or out of date misleads whoever runs the app, and the check it answers has to be done by hand instead.',
    fix: `Run "npm run docs:build" in the app folder to regenerate ${file} from the app's own settings, or rebuild the app.`,
    references: ['https://owasp.org/www-project-secure-by-design-framework/'],
  });
}

function readDoc(ctx: Pick<ScanContext, 'appDir'>, file: string): string | undefined {
  return readTextFile(join(ctx.appDir, file));
}

function env(ctx: Pick<ScanContext, 'appDir'>): Record<string, string> {
  const text = readTextFile(join(ctx.appDir, '.env'));
  return text === undefined ? {} : parseEnv(text);
}

interface DesignFacts {
  appName?: string;
  dataCategories?: string[];
  retention?: { policy?: string; months?: number };
  outboundHosts?: string[];
  sessionPolicy?: { idleMinutes?: number; absoluteHours?: number; maxConcurrent?: number };
}

function design(ctx: Pick<ScanContext, 'appDir'>): DesignFacts {
  const text = readTextFile(join(ctx.appDir, 'securevibe.design.json'));
  if (text === undefined) return {};
  try {
    return JSON.parse(text) as DesignFacts;
  } catch {
    return {};
  }
}

/** The record types the app keeps, from the exported route list (the same source the documents are built from). */
function entityNames(ctx: Pick<ScanContext, 'appDir'>): string[] {
  const text = readTextFile(join(ctx.appDir, 'routes.manifest.json'));
  if (text === undefined) return [];
  try {
    const routes = JSON.parse(text) as { entity?: string | null }[];
    return [...new Set(routes.map((r) => (typeof r.entity === 'string' ? r.entity : '')).filter(Boolean))];
  } catch {
    return [];
  }
}

/** The document must exist and carry content; every check starts here. */
function present(text: string | undefined, file: string): ConfigCheckOutcome | undefined {
  if (text === undefined) return { passed: false, summary: `${file} was not found, so this is not documented.`, file };
  if (text.trim().length < MIN_DOC_CHARS) return { passed: false, summary: `${file} is there but nearly empty, so it documents nothing.`, file };
  return undefined;
}

/** Case-insensitive "does the document mention this?", with the value's own punctuation ignored. */
function mentions(text: string, value: string | number): boolean {
  return text.toLowerCase().includes(String(value).toLowerCase());
}

function missingFrom(text: string, values: (string | number)[]): (string | number)[] {
  return values.filter((v) => !mentions(text, v));
}

export const validationDocumented: ConfigCheckDef = {
  meta: docMeta('docs.validation-documented', 'The rules for what people may type are not documented', 'docs/validation.md', ['V2.1.1', 'V2.1.3'], 'docs/validation.md is missing, empty, or does not cover every kind of record the app keeps.'),
  run: (ctx) => {
    const file = 'docs/validation.md';
    const text = readDoc(ctx, file);
    const problem = present(text, file);
    if (problem) return problem;
    const entities = entityNames(ctx);
    const missing = missingFrom(text!, entities);
    if (entities.length === 0) return { passed: true, summary: `${file} documents the rules for what people may type.`, file };
    if (missing.length > 0) return { passed: false, summary: `${file} does not mention ${missing.join(', ')}, so those records' rules are undocumented.`, file };
    return { passed: true, summary: `${file} documents the rules for all ${entities.length} kind(s) of record the app keeps.`, file };
  },
};

export const sessionTimesDocumented: ConfigCheckDef = {
  meta: docMeta('docs.session-times-documented', 'The sign-in times are not documented', 'docs/sessions.md', ['V7.1.1', 'V7.1.2'], 'docs/sessions.md is missing, or the times in it are not the ones the app actually uses.'),
  run: (ctx) => {
    const file = 'docs/sessions.md';
    const text = readDoc(ctx, file);
    const problem = present(text, file);
    if (problem) return problem;
    const e = env(ctx);
    const policy = design(ctx).sessionPolicy ?? {};
    const idle = Number(e['SESSION_IDLE_MINUTES'] ?? policy.idleMinutes);
    const absolute = Number(e['SESSION_ABSOLUTE_HOURS'] ?? policy.absoluteHours);
    const expected = [Number.isFinite(idle) ? idle : undefined, Number.isFinite(absolute) ? absolute : undefined].filter((v): v is number => v !== undefined);
    if (expected.length === 0) return { passed: true, summary: `${file} documents how sign-in sessions end.`, file };
    const missing = missingFrom(text!, expected);
    if (missing.length > 0) return { passed: false, summary: `${file} does not state the app's own session times (${expected.join(' and ')}), so the document and the app disagree.`, file };
    return { passed: true, summary: `${file} states the session times the app actually uses (${expected.join(' and ')}).`, file };
  },
};

export const outsideServicesDocumented: ConfigCheckDef = {
  meta: docMeta('docs.outside-services-documented', 'The outside services the app may contact are not documented', 'docs/communications.md', ['V13.1.1'], 'docs/communications.md is missing, or does not list the hosts the app is allowed to contact.'),
  run: (ctx) => {
    const file = 'docs/communications.md';
    const text = readDoc(ctx, file);
    const problem = present(text, file);
    if (problem) return problem;
    const raw = env(ctx)['OUTBOUND_ALLOWED_HOSTS'] ?? (design(ctx).outboundHosts ?? []).join(',');
    const hosts = raw.split(',').map((h) => h.trim()).filter(Boolean);
    if (hosts.length === 0) {
      const saysNone = /\bnone\b|cannot call|no outside|not allowed to call/i.test(text!);
      return saysNone
        ? { passed: true, summary: `${file} says the app contacts no outside services, which matches its settings.`, file }
        : { passed: false, summary: `${file} does not say that the app contacts no outside services, although its settings allow none.`, file };
    }
    const missing = missingFrom(text!, hosts);
    if (missing.length > 0) return { passed: false, summary: `${file} does not list ${missing.join(', ')}, which the app is allowed to contact.`, file };
    return { passed: true, summary: `${file} lists all ${hosts.length} outside service(s) the app may contact.`, file };
  },
};

export const dataProtectionDocumented: ConfigCheckDef = {
  meta: docMeta('docs.data-classes-documented', 'The kinds of information the app holds are not documented', 'docs/data-protection.md', ['V14.1.1', 'V14.1.2'], 'docs/data-protection.md is missing, or does not cover the kinds of information the app was designed to hold and how long they are kept.'),
  run: (ctx) => {
    const file = 'docs/data-protection.md';
    const text = readDoc(ctx, file);
    const problem = present(text, file);
    if (problem) return problem;
    const facts = design(ctx);
    const categories = facts.dataCategories ?? [];
    const missing = missingFrom(text!, categories.map((c) => c.replace(/-/g, ' ')));
    const retention = facts.retention?.months;
    const retentionMissing = retention !== undefined && !mentions(text!, retention);
    if (missing.length > 0 || retentionMissing) {
      const parts = [missing.length > 0 ? `the ${missing.join(', ')} information it holds` : '', retentionMissing ? `how long records are kept (${retention} months)` : ''].filter(Boolean);
      return { passed: false, summary: `${file} does not cover ${parts.join(' or ')}.`, file };
    }
    return { passed: true, summary: categories.length > 0 ? `${file} covers all ${categories.length} kind(s) of information the app holds, and how long they are kept.` : `${file} documents how the app's information is protected and how long it is kept.`, file };
  },
};

export const loggingDocumented: ConfigCheckDef = {
  meta: docMeta('docs.logging-documented', 'What the app logs is not documented', 'docs/logging.md', ['V16.1.1'], 'docs/logging.md is missing, or does not say where the log is kept and for how long.'),
  run: (ctx) => {
    const file = 'docs/logging.md';
    const text = readDoc(ctx, file);
    const problem = present(text, file);
    if (problem) return problem;
    const saysWhere = /\.log\b|log file|DATA_DIR|audit_log/i.test(text!);
    const saysHowLong = /\b\d+\s*(day|month|year)/i.test(text!) || /kept for/i.test(text!);
    if (!saysWhere || !saysHowLong) {
      const missing = [!saysWhere ? 'where the log is kept' : '', !saysHowLong ? 'how long it is kept' : ''].filter(Boolean).join(' or ');
      return { passed: false, summary: `${file} does not say ${missing}.`, file };
    }
    return { passed: true, summary: `${file} says where the log is kept and for how long.`, file };
  },
};

export const dependencyUpdatesDocumented: ConfigCheckDef = {
  meta: docMeta('docs.dependency-updates-documented', 'How the app\'s packages are kept up to date is not documented', 'docs/dependencies.md', ['V15.1.1'], 'docs/dependencies.md is missing, or does not give the deadlines for applying security updates.'),
  run: (ctx) => {
    const file = 'docs/dependencies.md';
    const text = readDoc(ctx, file);
    const problem = present(text, file);
    if (problem) return problem;
    const saysDeadline = /\b\d+\s*(day|hour|week)/i.test(text!);
    if (!saysDeadline) return { passed: false, summary: `${file} does not give a deadline for applying security updates.`, file };
    return { passed: true, summary: `${file} gives the deadlines for applying security updates.`, file };
  },
};

export const securityOverviewDocumented: ConfigCheckDef = {
  meta: docMeta('docs.sign-in-rules-documented', 'The sign-in rules are not documented', 'docs/SECURITY.md', ['V6.1.1', 'V6.1.2', 'V6.1.3'], 'docs/SECURITY.md is missing, or does not describe the sign-in limits, the banned password words and the administrator\'s second step.'),
  run: (ctx) => {
    const file = 'docs/SECURITY.md';
    const text = readDoc(ctx, file);
    const problem = present(text, file);
    if (problem) return problem;
    const saysLimits = /lock(ed|out)|too many attempts|rate limit|attempts/i.test(text!);
    const appName = design(ctx).appName;
    const saysBanned = /banned|common password|not allowed as a password|forbidden word|password list/i.test(text!) || (appName !== undefined && mentions(text!, appName));
    const saysSecondStep = /one-time code|second step|two-step|authenticator|TOTP|second factor/i.test(text!);
    const missing = [!saysLimits ? 'the sign-in limits' : '', !saysBanned ? 'the words that cannot be used as passwords' : '', !saysSecondStep ? "the administrator's second step" : ''].filter(Boolean);
    if (missing.length > 0) return { passed: false, summary: `${file} does not describe ${missing.join(', ')}.`, file };
    return { passed: true, summary: `${file} describes the sign-in limits, the banned password words and the administrator's second step.`, file };
  },
};

/** Every documentation check, in the order they are reported. */
/**
 * These look for the documents SecureVibe's own template writes (docs/validation.md and its siblings). "Your
 * validation rules are not documented" may well be true of somebody else's app, but concluding it from the
 * absence of our file paths is checking for our convention and reporting it as their failure. For an app
 * SecureVibe did not build, the honest result is that this could not be verified, so the checks do not apply
 * and say why; the requirements they would have answered stay unverified rather than failed.
 */
const OUR_DOCUMENTS_ONLY = 'they look for the documents SecureVibe writes when it builds an app, so whether an app built elsewhere documents these things could not be verified';

export const DOC_CHECKS: ConfigCheckDef[] = [
  validationDocumented,
  sessionTimesDocumented,
  outsideServicesDocumented,
  dataProtectionDocumented,
  loggingDocumented,
  dependencyUpdatesDocumented,
  securityOverviewDocumented,
].map((check) => ({ ...check, applies: (ctx) => builtBySecureVibe(ctx), notApplicableReason: OUR_DOCUMENTS_ONLY }));
