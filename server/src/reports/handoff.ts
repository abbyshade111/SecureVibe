/**
 * HANDOFF.md — the one document a developer or hosting provider reads first when they receive an app from
 * SecureVibe (docs/CONTRACTS.md "Hand-off pack"). Plain language, written from the run record: how to run the
 * app, how the checks came out, what is still open and who can fix it, what people confirmed by hand, and what
 * has to happen before the app is exposed to more than one computer.
 */
import { isOpen, type Finding } from '@shared/findings.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { DesignProfileSchema, type DesignProfile } from '@shared/profile.js';
import type { Project } from '@shared/project.js';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const WHO_LABEL: Record<Finding['whoCanFix'], string> = {
  securevibe: 'SecureVibe (rebuild or "Ask Claude to fix")',
  developer: 'a developer',
  owner: 'the app owner (a setting or a decision)',
  'hosting-provider': 'the hosting provider',
};
const TARGET_LABEL: Record<string, string> = {
  'local-only': 'on one computer only',
  'local-network': 'on a local network (an office or home network)',
  'internet-later': 'on the internet, later',
};

export interface HandoffInput {
  project: Project;
  run: PipelineRun;
  securevibeVersion: string;
  /** Files the pack contains, for the "what is in this pack" list. */
  contents: { path: string; what: string }[];
  now?: Date;
}

function pct(n: number | undefined): string {
  return n === undefined ? 'not assessed' : `${Math.round(n * 10) / 10}%`;
}

function profileOf(project: Project): DesignProfile | undefined {
  const parsed = DesignProfileSchema.safeParse(project.profile);
  return parsed.success ? parsed.data : undefined;
}

export function handoffMarkdown(input: HandoffInput): string {
  const { project, run } = input;
  const now = (input.now ?? new Date()).toISOString().slice(0, 10);
  const profile = profileOf(project);
  const features = project.design?.buildSpec.features;
  const compliance = run.compliance;
  const tests = run.stages.find((s) => s.id === 'unit-tests')?.details as { total?: number; passed?: number; failed?: number } | undefined;
  const open = run.findings.filter(isOpen).sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  const attestations = project.attestations ?? [];
  const yes = attestations.filter((a) => a.result === 'yes').length;
  const no = attestations.filter((a) => a.result === 'no').length;
  const unsure = attestations.filter((a) => a.result === 'not-sure').length;

  const lines: string[] = [];
  lines.push(`# ${project.name} — hand-off pack`, '');
  lines.push(`Prepared by SecureVibe ${input.securevibeVersion} on ${now} from build \`${run.id}\`${run.finishedAt ? ` (finished ${run.finishedAt.slice(0, 16).replace('T', ' ')})` : ''}.`, '');
  lines.push(
    'This pack is for whoever takes the app further: a developer, or the people who will host it. It holds the',
    'application itself, every report SecureVibe produced, a record of where each file came from, and the checks',
    'people confirmed by hand. Nothing in it contains a secret: whoever runs the app creates fresh secrets with',
    '`npm run setup`.',
    '',
  );

  lines.push('## What this app is', '');
  if (profile) {
    lines.push(`- **Purpose:** ${profile.app.description || '(not described)'}`);
    lines.push(`- **Records it keeps:** ${profile.app.entities.map((e) => e.label || e.name).join(', ') || 'none'}`);
    lines.push(`- **Who uses it:** ${profile.users.audience}; sign-in ${profile.users.requiresSignIn ? 'required' : 'not required'}; roles: ${profile.users.roles.map((r) => r.label || r.name).join(', ')}`);
    lines.push(`- **Kinds of data:** ${profile.data.categories.join(', ') || 'none flagged'}${profile.data.aboutOtherPeople ? ' (about other people)' : ''}`);
    lines.push(`- **Meant to run:** ${TARGET_LABEL[profile.deployment.target] ?? profile.deployment.target}`);
    lines.push(`- **Owner contact:** ${profile.deployment.owner.name} <${profile.deployment.owner.contactEmail}>`);
  } else {
    lines.push('- The design answers were not available when this pack was written.');
  }
  lines.push('');

  lines.push('## How to run it', '');
  lines.push('In the `app/` folder, with Node.js 22.13 or newer:', '');
  lines.push('```', 'npm install', 'npm run setup      # creates .env with fresh secrets, the database and the first administrator', 'npm start', '```', '');
  lines.push('`app/README.md` explains every folder and setting. The one-time administrator password is printed by `npm run setup`.', '');

  if (run.ownerTasks && run.ownerTasks.length > 0) {
    lines.push('## What only the owner can do', '');
    lines.push('Worked out from the app itself and the answers, not from prose. Each says what stays switched off until it is done.', '');
    for (const t of run.ownerTasks) lines.push(`- **${t.title}** ${t.because} ${t.staysOff}`);
    lines.push('');
  }

  lines.push('## How the checks came out', '');
  if (compliance) {
    lines.push(`**${compliance.overall.rating.replace('-', ' ').toUpperCase()}** — ${compliance.overall.headline}`, '');
    if (compliance.overall.ratingReason) lines.push(compliance.overall.ratingReason, '');
    lines.push(compliance.overall.canIUseIt, '');
    lines.push(`- OWASP ASVS ${compliance.asvs.summary.version}, level ${compliance.asvs.summary.targetLevel}: **${pct(compliance.asvs.summary.verifiedPassPercent)}** of applicable requirements verified by automated checks (${compliance.asvs.summary.counts.pass} of ${compliance.asvs.summary.applicableCount}).`);
    if (compliance.aisvs) lines.push(`- OWASP AISVS ${compliance.aisvs.summary.version}: **${pct(compliance.aisvs.summary.verifiedPassPercent)}** verified (${compliance.aisvs.summary.counts.pass} of ${compliance.aisvs.summary.applicableCount}).`);
  } else {
    lines.push('- The compliance evaluation did not run for this build.');
  }
  if (tests && typeof tests.total === 'number') lines.push(`- Built-in security and feature tests: ${tests.passed ?? 0} of ${tests.total} passed${tests.failed ? `, ${tests.failed} failed` : ''}.`);
  const failedStages = run.stages.filter((s) => s.status === 'failed');
  if (failedStages.length) lines.push(`- Steps that did not pass: ${failedStages.map((s) => s.id).join(', ')} (see \`reports/run-log.txt\`).`);
  lines.push('', 'The full detail is in `reports/compliance-report.html` and `reports/security-report.html`. "Verified" means an automated check passed; anything assessed only by AI or confirmed only by a person is labeled as such in those reports and never counted as verified.', '');

  lines.push('## What is still open', '');
  if (open.length === 0) {
    lines.push('No open problems were found by the checks.', '');
  } else {
    lines.push(`${open.length} open problem(s), most serious first. "Who can fix it" says whose decision or work it is.`, '');
    lines.push('| Seriousness | Problem | Who can fix it | What to do |', '|---|---|---|---|');
    for (const f of open.slice(0, 60)) {
      const where = f.location?.file ? ` (\`${f.location.file}${f.location.line ? `:${f.location.line}` : ''}\`)` : '';
      const cell = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
      lines.push(`| ${f.severity} | ${cell(f.title)}${where} | ${WHO_LABEL[f.whoCanFix] ?? f.whoCanFix} | ${cell(f.remediation.summary)} |`);
    }
    if (open.length > 60) lines.push(`| … | ${open.length - 60} more in \`reports/security-report.html\` | | |`);
    lines.push('');
  }

  lines.push('## What people confirmed by hand', '');
  if (attestations.length === 0) {
    lines.push('Nobody has answered the human checks yet (in SecureVibe: My apps → Human checks). The reports treat those requirements as not verified.', '');
  } else {
    lines.push(`${attestations.length} human check(s) answered: ${yes} yes, ${no} no, ${unsure} not sure. A "yes" is recorded as the person's word, not as a verified control; a "not sure" adds nothing. The answers are in \`human-checks.json\`.`, '');
    const nos = attestations.filter((a) => a.result === 'no');
    if (nos.length) {
      lines.push('Answered **no** (these need work or a decision):', '');
      for (const a of nos) lines.push(`- ${a.requirementId}${a.note ? ` — ${a.note}` : ''}`);
      lines.push('');
    }
  }
  if (project.humanCodeReview) lines.push(`A human code review was recorded by ${project.humanCodeReview.reviewedBy} on ${project.humanCodeReview.reviewedAt.slice(0, 10)}.`, '');

  lines.push('## Before this app is used by more than one person', '');
  const todo: string[] = [];
  todo.push('Run `npm run setup` on the machine that will host it, so it has its own secrets and first administrator; never copy a `.env` between machines.');
  if (features) {
    if (features.tlsMode === 'proxy') todo.push('It expects to sit behind a reverse proxy that terminates HTTPS (TLS_MODE=proxy, TRUST_PROXY_HOPS=1). Put it behind one; do not expose port 3000 directly.');
    else if (features.tlsMode === 'selfsigned') todo.push('It serves HTTPS with a self-signed certificate (TLS_MODE=selfsigned). Browsers will warn; for anything beyond a small trusted group, use a real certificate or a reverse proxy.');
    else todo.push('It runs over plain HTTP, which is only safe on one computer. Before it is reachable from other machines, set TLS_MODE=proxy behind an HTTPS reverse proxy (or selfsigned for a small trusted network).');
    if (features.lanBinding) todo.push('It is set to listen on the local network (BIND_LAN=1). Make sure the network is one you trust, and keep the firewall rules tight.');
  }
  if (profile?.data.retention === 'auto-delete-after-period' && profile.data.retentionMonths) todo.push(`Records are set to be deleted after ${profile.data.retentionMonths} months (RETENTION_MONTHS); confirm that matches what people were told.`);
  todo.push('Decide who owns backups of `data/` (the database) and how they are restored; SecureVibe does not set this up.');
  todo.push('Keep Node.js and the packages updated; `reports/sbom.cdx.json` lists every package in this build.');
  if (open.some((f) => f.severity === 'critical' || f.severity === 'high')) todo.push('Fix or formally accept the critical/high problems listed above first.');
  for (const t of todo) lines.push(`- ${t}`);
  lines.push('');

  lines.push('## Where every file came from', '');
  const prov = run.provenance;
  if (prov) {
    const counts = new Map<string, number>();
    for (const f of prov.generatedFiles) counts.set(f.origin, (counts.get(f.origin) ?? 0) + 1);
    const label: Record<string, string> = { template: 'SecureVibe template', expanded: 'made from the answers', 'ai-generated': 'written by Claude', 'ai-fixed': 'fixed by Claude', user: 'changed by the owner' };
    lines.push(`Template version ${prov.templateVersion}; ${prov.generatedFiles.length} files: ${[...counts].map(([o, n]) => `${n} ${label[o] ?? o}`).join(', ')}.`);
    if (prov.llm) lines.push(`AI provider ${prov.llm.provider}, model(s) ${prov.llm.servedModels.join(', ') || prov.llm.requestedModel}; every call is listed in \`reports/provenance.json\`.`);
    lines.push(`Code runs under ${prov.sandbox.mode}: ${prov.sandbox.note}`);
  } else {
    lines.push('The provenance record was not available for this build.');
  }
  lines.push('');

  lines.push('## What is in this pack', '');
  for (const c of input.contents) lines.push(`- \`${c.path}\` — ${c.what}`);
  lines.push('');
  return `${lines.join('\n')}\n`;
}
