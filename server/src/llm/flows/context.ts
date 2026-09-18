/**
 * Compact renderings of the design and the profile that the flows put into prompts. Everything here is produced by
 * SecureVibe from its own data structures, so it is trusted content; anything that came from the person (names,
 * descriptions, free text) is wrapped as untrusted data by the caller.
 */
import type { DesignArtifacts } from '@shared/design.js';
import type { Finding } from '@shared/findings.js';
import type { DesignProfile, PartialDesignProfile } from '@shared/profile.js';

/** The answers so far, for a profile the owner may not have finished. Only what they actually answered is listed. */
export function renderPartialProfile(profile: PartialDesignProfile): string {
  const lines: string[] = [];
  const add = (label: string, value: unknown): void => {
    if (value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0)) return;
    lines.push(`  ${label}: ${Array.isArray(value) ? value.join(', ') : String(value)}`);
  };
  const app = profile.app ?? {};
  const users = profile.users ?? {};
  const data = profile.data ?? {};
  const caps = profile.capabilities ?? {};
  const deployment = profile.deployment ?? {};
  lines.push('App:');
  add('name', app.name);
  add('what it is for', app.tagline);
  add('category', app.category);
  add('records it keeps', (app.entities ?? []).map((e) => e?.label ?? e?.name).filter(Boolean));
  add('features asked for', app.keyFeatures);
  lines.push('People:');
  add('who uses it', users.audience);
  add('sign-in', users.requiresSignIn === undefined ? undefined : users.requiresSignIn ? 'yes' : 'no');
  add('roles', (users.roles ?? []).map((r) => r?.label ?? r?.name).filter(Boolean));
  lines.push('Information:');
  add('kinds of information', data.categories);
  add('about other people', data.aboutOtherPeople === undefined ? undefined : data.aboutOtherPeople ? 'yes' : 'no');
  add('keeping records', data.retention);
  lines.push('What it can do:');
  add('file uploads', caps.fileUploads === undefined ? undefined : caps.fileUploads ? 'yes' : 'no');
  add('email', caps.email === undefined ? undefined : caps.email ? 'yes' : 'no');
  add('scheduled jobs', caps.scheduledJobs === undefined ? undefined : caps.scheduledJobs ? 'yes' : 'no');
  add('machine access with API keys', caps.publicApi === undefined ? undefined : caps.publicApi ? 'yes' : 'no');
  add('payments', caps.payments === undefined ? undefined : caps.payments ? 'yes' : 'no');
  const ai = caps.aiAssistant;
  if (ai?.enabled) {
    add('AI assistant', `yes (purpose: ${ai.purpose || 'not said'}; sees: ${ai.dataItCanSee ?? 'not said'}; may search the web: ${ai.canSearchWeb ? 'yes' : 'no'})`);
  } else if (ai?.enabled === false) {
    add('AI assistant', 'no');
  }
  lines.push('Where it runs:');
  add('where', deployment.target);
  add('if it were down for a day', deployment.businessImpact);
  return lines.join('\n');
}

export function renderProfile(profile: DesignProfile): string {
  const caps = profile.capabilities;
  const on: string[] = [];
  if (caps.fileUploads) on.push('file uploads');
  if (caps.email) on.push('email');
  if (caps.scheduledJobs) on.push('scheduled jobs');
  if (caps.publicApi) on.push('machine access with API keys');
  if (caps.payments) on.push('payments (provider-hosted checkout)');
  if (caps.aiAssistant.enabled) {
    on.push(
      `an AI assistant (sees: ${caps.aiAssistant.dataItCanSee}; can change data: ${caps.aiAssistant.canTakeActions ? 'yes' : 'no'}; keeps history: ${caps.aiAssistant.storesHistory ? 'yes' : 'no'})`,
    );
  }
  for (const api of caps.externalApis) on.push(`connects to ${api.name} (${api.sendsPersonalData ? 'sends personal data' : 'no personal data'})`);

  return [
    `Category: ${profile.app.category}`,
    `Audience: ${profile.users.audience}; sign-in required: ${profile.users.requiresSignIn ? 'yes' : 'no'}; ` +
      `roles: ${profile.users.roles.map((r) => `${r.name}${r.isAdmin ? ' (admin)' : ''}`).join(', ') || 'none'}; ` +
      `accounts: ${profile.users.registration}; admin two-step sign-in: ${profile.users.adminMfa ? 'yes' : 'no'}`,
    `Information handled: ${profile.data.categories.join(', ') || 'none stated'}; about other people: ${profile.data.aboutOtherPeople ? 'yes' : 'no'}; ` +
      `retention: ${profile.data.retention}${profile.data.retentionMonths ? ` (${profile.data.retentionMonths} months)` : ''}; region: ${profile.data.region}`,
    `Where it runs: ${profile.deployment.target}; impact of an outage or breach: ${profile.deployment.businessImpact}`,
    `Capabilities: ${on.length > 0 ? on.join('; ') : 'none beyond the basics'}`,
    `Records: ${profile.app.entities.map((e) => `${e.name} [${e.access}] (${e.fields.map((f) => `${f.name}:${f.type}${f.sensitive ? ' sensitive' : ''}`).join(', ')})`).join(' | ') || 'none yet'}`,
  ].join('\n');
}

export function renderArchitecture(design: DesignArtifacts): string {
  const a = design.architecture;
  return [
    'Trust zones:',
    ...a.trustZones.map((z) => `  ${z.id} (${z.level}): ${z.description}`),
    'Components:',
    ...a.components.map((c) => `  ${c.id} [${c.kind}] in ${c.trustZone}: ${c.description}`),
    'Data flows:',
    ...a.dataFlows.map(
      (f) =>
        `  ${f.id}: ${f.from} -> ${f.to} over ${f.protocol}${f.crossesTrustBoundary ? ' (crosses a trust boundary)' : ''}; ` +
        `data: ${f.data.join(', ') || 'none'}; controls: ${f.controls.join(', ') || 'none'}`,
    ),
    'External dependencies:',
    ...a.externalDependencies.map((d) => `  ${d.name} (${d.trust}): ${d.purpose}; shares: ${d.dataShared.join(', ') || 'nothing'}`),
    'Assumptions:',
    ...a.assumptions.map((s) => `  ${s}`),
  ].join('\n');
}

export function renderControls(design: DesignArtifacts): string {
  const implemented = new Set<string>();
  for (const p of design.patterns) for (const c of p.implementedBy) implemented.add(c);
  return [
    `Target level: ${design.applicability.targetLevel} — ${design.applicability.targetLevelRule}`,
    `Patterns in the design: ${design.patterns.map((p) => p.id).join(', ')}`,
    `Template controls already implemented and tested: ${[...implemented].sort().join(', ')}`,
  ].join('\n');
}

export function renderChecklistGaps(design: DesignArtifacts): string {
  const gaps = design.checklist.filter((c) => c.status === 'no');
  if (gaps.length === 0) return 'Secure by Design checklist: no open items.';
  return [
    'Secure by Design checklist items answered "no" (with their planned action):',
    ...gaps.map((c) => `  ${c.id}${c.critical ? ' (critical)' : ''}: ${c.statement} — ${c.justification}`),
  ].join('\n');
}

export function renderSecurityRequirements(design: DesignArtifacts): string {
  return [
    'Security requirements derived from the answers:',
    ...design.securityRequirements.map((r) => `  ${r.id} [${r.category}] ${r.statement}`),
  ].join('\n');
}

/** One finding as the fix agent sees it. Location and evidence come from SecureVibe's scanners, not from the model. */
export function renderFinding(finding: Finding, index: number): string {
  const loc = finding.location;
  const where = loc?.file ? `${loc.file}${loc.line ? `:${loc.line}` : ''}` : (loc?.endpoint ?? 'not tied to one file');
  return [
    `${index}. [${finding.id}] ${finding.title}`,
    `   rule: ${finding.ruleId} (${finding.source}); severity: ${finding.severity}; confidence: ${finding.confidence}`,
    `   where: ${where}`,
    `   what it is: ${finding.description}`,
    `   why it matters: ${finding.impact}`,
    `   what the check saw: ${finding.evidence}`,
    `   how to fix it: ${finding.remediation.summary}`,
    ...finding.remediation.steps.map((s) => `     - ${s}`),
  ].join('\n');
}
