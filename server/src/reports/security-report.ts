/**
 * security-report.{md,html,json} (CONTRACTS §9.6, DESIGN §13.12 report section list — exact 12 sections).
 */
import type { Finding, Priority, Severity } from '@shared/findings.js';
import { PRIORITY_ORDER, SEVERITY_ORDER, isOpen } from '@shared/findings.js';
import { escapeHtml, anchorId } from './escape.js';
import { htmlList, htmlTable } from './html-table.js';
import { confidenceText, priorityBadge, priorityText, severityText } from './badges.js';
import { mdBullets, mdTable } from './md.js';
import { glossaryHtml, glossaryMarkdown } from './glossary.js';
import { renderPage, type Banner, type TocEntry } from './page.js';
import { coverageRanText, type ReportModel } from './types.js';

function countBy<T extends string>(findings: Finding[], key: (f: Finding) => T, order: Record<T, number>): Record<T, number> {
  const out = {} as Record<T, number>;
  for (const k of Object.keys(order) as T[]) out[k] = 0;
  for (const f of findings) if (isOpen(f)) out[key(f)]++;
  return out;
}

function sourceCounts(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) if (isOpen(f)) out[f.source] = (out[f.source] ?? 0) + 1;
  return out;
}

function severityArrow(f: Finding): string {
  if (!f.severityBase || f.severityBase === f.severity) return severityText(f.severity);
  return `${severityText(f.severityBase)} → ${severityText(f.severity)}${f.adjustmentReason ? ` (${f.adjustmentReason})` : ''}`;
}

function reVerifyCommands(input: Pick<ReportModel, 'sbomPath'>): { label: string; command: string }[] {
  return [
    { label: 'Install the generated app\'s packages', command: 'cd <app folder> && npm install --ignore-scripts --no-audit --no-fund' },
    { label: 'Check the code compiles', command: 'npm run typecheck' },
    { label: 'Run the built-in security tests', command: 'npm test' },
    { label: 'Verify the tamper-evident audit log', command: 'npm run audit:verify' },
    { label: 'Re-run SecureVibe\'s full check suite (static analysis, secrets, dependencies, config, runtime probes)', command: `securevibe verify <app folder>` },
    ...(input.sbomPath ? [{ label: 'Regenerate the software bill of materials', command: 'npx @cyclonedx/cyclonedx-npm --output-file sbom.cdx.json' }] : []),
  ];
}

/** What the security report needs: never the design, and the compliance result only for its human-review banner. */
export type SecurityReportInput = Omit<ReportModel, 'design' | 'compliance'> & { compliance?: ReportModel['compliance'] };

export function renderSecurityReport(input: SecurityReportInput): { md: string; html: string; json: string } {
  const { findings, provenance } = input;
  const open = findings.filter(isOpen);
  const fixed = findings.filter((f) => f.status === 'fixed');
  const accepted = findings.filter((f) => f.status === 'accepted');
  const falsePositive = findings.filter((f) => f.status === 'false-positive');

  const bySeverity = countBy(open, (f) => f.severity, SEVERITY_ORDER as Record<Severity, number>);
  const byPriority = countBy(open, (f) => f.priority, PRIORITY_ORDER as Record<Priority, number>);
  const bySource = sourceCounts(open);

  const prevOpenFp = new Set((input.previousFindings ?? []).filter(isOpen).map((f) => f.fingerprint));
  const currentOpenFp = new Set(open.map((f) => f.fingerprint));
  const newSincePrevious = input.previousFindings ? open.filter((f) => !prevOpenFp.has(f.fingerprint)).length : undefined;
  const resolvedSincePrevious = input.previousFindings ? [...prevOpenFp].filter((fp) => !currentOpenFp.has(fp)).length : undefined;

  const findingsByPriority = [...open].sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const dastFindings = findings.filter((f) => f.source === 'dast');
  const depFindings = findings.filter((f) => f.source === 'deps');
  const secretFindings = findings.filter((f) => f.source === 'secrets');
  const configFindings = findings.filter((f) => f.source === 'config');

  const testCounts = { total: input.testResults.length, passed: input.testResults.filter((t) => t.ok && !t.skipped).length, failed: input.testResults.filter((t) => !t.ok && !t.skipped).length, skipped: input.testResults.filter((t) => t.skipped).length };

  const json = JSON.stringify({ findings, coverage: input.coverage, probeResults: input.probeResults, testResults: input.testResults }, null, 2);

  // ---- Markdown ------------------------------------------------------------------------------
  const md: string[] = [];
  md.push(`# ${input.profile?.app.name ?? 'App'} — security report`);
  md.push('', 'Every finding here shows what it is, why it matters, where it is, and how to fix it. Priority is how urgently it needs attention; severity is how serious it is on its own.');

  md.push('', '## 1. Summary', '');
  md.push(
    mdBullets([
      `Open findings: **${open.length}** (${Object.entries(byPriority).map(([p, n]) => `${p}: ${n}`).join(', ')})`,
      `By severity: ${Object.entries(bySeverity).map(([s, n]) => `${s}: ${n}`).join(', ')}`,
      `By source: ${Object.entries(bySource).map(([s, n]) => `${s}: ${n}`).join(', ') || 'none'}`,
      `Fixed during the build: ${fixed.length}. Accepted risk: ${accepted.length}. False positives: ${falsePositive.length}.`,
      ...(newSincePrevious !== undefined ? [`Since the previous run: ${newSincePrevious} new, ${resolvedSincePrevious} resolved.`] : []),
    ]),
  );

  md.push('', '## 2. How risk is rated', '');
  md.push(
    'Each finding gets a base severity from the tool that found it, then an adjusted severity for how this app is deployed (for example, a finding that only matters if the app is reachable from the internet is downgraded on a computer-only app). Priority combines the adjusted severity, how confident the tool is, and how easily it could be exploited:',
  );
  md.push(
    '',
    mdBullets([
      '**P1 — fix first**: critical/high severity, medium-or-higher confidence, and exploitable without special access.',
      '**P2 — fix soon**: high/critical severity that needs network exposure, or medium severity that is trivially exploitable with high confidence.',
      '**P3 — fix when convenient**: medium severity otherwise, or high-confidence low severity.',
      '**P4 — low priority**: everything else.',
    ]),
  );

  md.push('', '## 3. Tool coverage & limits', '');
  md.push(mdTable(['Tool', 'Ran', 'What it covers'], input.coverage.map((c) => [c.tool, coverageRanText(c), c.covers ?? ''])));

  md.push('', '## 4. Findings by priority', '');
  if (findingsByPriority.length === 0) md.push('No open findings.');
  for (const f of findingsByPriority) {
    md.push(
      '',
      `### ${f.id}: ${f.title}`,
      '',
      mdBullets([
        `**Priority / severity**: ${priorityText(f.priority)} — ${severityArrow(f)} (${confidenceText(f.confidence)})`,
        `**Where**: ${f.location ? `${f.location.file ?? f.location.endpoint ?? ''}${f.location.line ? `:${f.location.line}` : ''}` : 'not tied to a single file'}`,
        `**What it is**: ${f.description}`,
        `**Why it matters**: ${f.impact}`,
        `**What we observed**: ${f.evidence}`,
        `**How to fix it**: ${f.remediation.summary}`,
      ]),
    );
    if (f.remediation.steps.length) md.push('', mdBullets(f.remediation.steps));
    if (f.remediation.example) md.push('', '```', f.remediation.example, '```');
    md.push(
      '',
      mdBullets([
        `**How to confirm it is fixed**: ${f.verification?.howToConfirmFixed ?? 'Re-run the check that found it and confirm it no longer appears.'}${f.verification?.rerunCommand ? ` (\`${f.verification.rerunCommand}\`)` : ''}`,
        `**References**: CWE ${f.cwe.join(', ') || '—'}. ASVS ${f.mappings.asvs.join(', ') || '—'}. AISVS ${f.mappings.aisvs.join(', ') || '—'}. SbD ${f.mappings.sbd.join(', ') || '—'}.${f.remediation.references.length ? ` ${f.remediation.references.join(', ')}` : ''}`,
        `**History**: first seen ${f.firstSeenRun ?? 'this run'}, last seen ${f.lastSeenRun ?? 'this run'}. Who can fix it: ${f.whoCanFix}.${f.triage ? ` Triage: ${f.triage.reason} (by ${f.triage.by} on ${f.triage.at.slice(0, 10)}).` : ''}`,
      ]),
    );
  }

  md.push('', '## 5. Fixed during the build', '');
  md.push(
    fixed.length
      ? mdTable(
          ['Id', 'Title', 'Fixed in round', 'Diff'],
          fixed.map((f) => [f.id, f.title, f.fixedInRound ?? '', f.fixDiffPath ? `\`${f.fixDiffPath}\`` : '']),
        )
      : 'Nothing needed fixing during this build.',
  );

  md.push('', '## 6. Accepted risks & false positives', '');
  md.push(
    [...accepted, ...falsePositive].length
      ? mdTable(
          ['Id', 'Title', 'Decision', 'Reason', 'By', 'Compensating control'],
          [...accepted, ...falsePositive].map((f) => [f.id, f.title, f.status, f.triage?.reason ?? '', f.triage?.by ?? '', f.triage?.compensatingControl ?? '']),
        )
      : 'None recorded.',
  );

  md.push('', '## 7. Runtime (DAST) probe results', '');
  md.push(
    input.probeResults.length
      ? mdTable(
          ['Probe', 'Result', 'Expected', 'Observed'],
          input.probeResults.map((p) => [p.id, p.passed === null ? 'Not attempted' : p.passed ? 'Passed' : 'Failed', p.expected ?? '', p.observed ?? p.reason ?? '']),
        )
      : `No runtime probes ran for this run.${dastFindings.length ? '' : ''}`,
  );

  md.push('', '## 8. Test results', '');
  md.push(mdBullets([`${testCounts.passed} passed, ${testCounts.failed} failed, ${testCounts.skipped} skipped, of ${testCounts.total} total.`]));
  const failedTests = input.testResults.filter((t) => !t.ok && !t.skipped);
  if (failedTests.length) md.push('', mdTable(['Test', 'File'], failedTests.map((t) => [t.name, t.file ?? ''])));

  md.push('', '## 9. Dependencies, SBOM & licenses', '');
  md.push(
    input.sbomPath
      ? `A full software bill of materials (SBOM, CycloneDX format) is included at \`${input.sbomPath}\`.`
      : 'No software bill of materials was generated for this run (the dependency scan may have been skipped, e.g. offline).',
  );
  md.push(
    '',
    depFindings.length
      ? mdTable(
          ['Package', 'Installed', 'Fixed in', 'Advisories', 'Severity'],
          depFindings.map((f) => [f.dependency?.package ?? '', f.dependency?.installedVersion ?? '', f.dependency?.fixedVersion ?? '', f.dependency?.advisoryIds.join(', ') ?? '', severityText(f.severity)]),
        )
      : 'No known-vulnerable dependencies were found.',
  );

  md.push('', '## 10. Secrets & configuration checks', '');
  md.push(
    mdBullets([
      `Secret scanning: ${secretFindings.filter(isOpen).length} open finding(s).`,
      `Configuration checks: ${configFindings.filter(isOpen).length} open finding(s).`,
    ]),
  );
  if (secretFindings.length || configFindings.length) {
    md.push('', mdTable(['Id', 'Source', 'Title', 'Status'], [...secretFindings, ...configFindings].map((f) => [f.id, f.source, f.title, f.status])));
  }

  md.push('', '## 11. How to re-verify', '');
  md.push(mdTable(['Step', 'Command'], reVerifyCommands(input).map((c) => [c.label, `\`${c.command}\``])));

  md.push('', '## 12. Provenance', '');
  md.push(
    mdBullets([
      `Run: ${provenance.runId} on ${provenance.generatedAt.slice(0, 10)} (mode: ${provenance.mode}).`,
      `Code tree hash: \`${provenance.codeTreeHash}\`.`,
      `Sandbox: ${provenance.sandbox.note}`,
    ]),
  );
  md.push('', glossaryMarkdown(input.knowledge.glossary));

  // ---- HTML --------------------------------------------------------------------------------
  const toc: TocEntry[] = [
    { id: 'summary', label: '1. Summary' },
    { id: 'risk-method', label: '2. How risk is rated' },
    { id: 'coverage', label: '3. Tool coverage & limits' },
    { id: 'findings-by-priority', label: '4. Findings by priority' },
    { id: 'fixed', label: '5. Fixed during the build' },
    { id: 'accepted', label: '6. Accepted risks & false positives' },
    { id: 'dast', label: '7. Runtime (DAST) probe results' },
    { id: 'tests', label: '8. Test results' },
    { id: 'deps', label: '9. Dependencies, SBOM & licenses' },
    { id: 'secrets-config', label: '10. Secrets & configuration checks' },
    { id: 'reverify', label: '11. How to re-verify' },
    { id: 'provenance', label: '12. Provenance' },
  ];
  const banners: Banner[] = [];
  if (!input.compliance?.humanReview.performed) banners.push({ kind: 'ai-disclaimer', text: 'This code was generated by an AI and has not been reviewed by a qualified human engineer.' });
  if (input.run.mode === 'demo') banners.push({ kind: 'preview', text: 'PREVIEW — built without AI generation or AI review.' });

  const body: string[] = [];
  body.push(
    `<section id="summary" class="chapter"><h2>1. Summary</h2><div class="scorecard">${(['P1', 'P2', 'P3', 'P4'] as Priority[])
      .map((p) => `<div class="cell"><span class="n">${byPriority[p]}</span>${escapeHtml(p)}</div>`)
      .join('')}</div>${htmlList([
      `By severity: ${Object.entries(bySeverity).map(([s, n]) => `${escapeHtml(s)}: ${n}`).join(', ')}`,
      `By source: ${Object.entries(bySource).map(([s, n]) => `${escapeHtml(s)}: ${n}`).join(', ') || 'none'}`,
      `Fixed during the build: ${fixed.length}. Accepted risk: ${accepted.length}. False positives: ${falsePositive.length}.`,
      ...(newSincePrevious !== undefined ? [`Since the previous run: ${newSincePrevious} new, ${resolvedSincePrevious} resolved.`] : []),
    ])}</section>`,
  );

  body.push(
    `<section id="risk-method" class="chapter"><h2>2. How risk is rated</h2><p>Each finding gets a base severity from the tool that found it, then an adjusted severity for how this app is deployed. Priority combines the adjusted severity, confidence and exploitability:</p>${htmlList([
      '<strong>P1 — fix first</strong>: critical/high severity, medium-or-higher confidence, exploitable without special access.',
      '<strong>P2 — fix soon</strong>: high/critical needing network exposure, or trivially exploitable medium severity with high confidence.',
      '<strong>P3 — fix when convenient</strong>: medium severity otherwise, or high-confidence low severity.',
      '<strong>P4 — low priority</strong>: everything else.',
    ])}</section>`,
  );

  body.push(`<section id="coverage" class="chapter"><h2>3. Tool coverage &amp; limits</h2>${htmlTable(['Tool', 'Ran', 'What it covers'], input.coverage.map((c) => [escapeHtml(c.tool), coverageRanText(c, escapeHtml), escapeHtml(c.covers ?? '')]))}</section>`);

  const findingCards = findingsByPriority
    .map((f) => {
      const id = anchorId('finding', f.id);
      return `<div class="finding-card" id="${id}">
<h4>${escapeHtml(f.id)}: ${escapeHtml(f.title)}</h4>
${priorityBadge(f.priority)}
<dl>
<dt>Severity</dt><dd>${escapeHtml(severityArrow(f))} (${escapeHtml(confidenceText(f.confidence))})</dd>
<dt>Where</dt><dd>${escapeHtml(f.location ? `${f.location.file ?? f.location.endpoint ?? ''}${f.location.line ? `:${f.location.line}` : ''}` : 'not tied to a single file')}</dd>
<dt>What it is</dt><dd>${escapeHtml(f.description)}</dd>
<dt>Why it matters</dt><dd>${escapeHtml(f.impact)}</dd>
<dt>What we observed</dt><dd>${escapeHtml(f.evidence)}</dd>
<dt>How to fix</dt><dd>${escapeHtml(f.remediation.summary)}${htmlList(f.remediation.steps.map(escapeHtml), '')}${f.remediation.example ? `<pre>${escapeHtml(f.remediation.example)}</pre>` : ''}</dd>
<dt>How to confirm fixed</dt><dd>${escapeHtml(f.verification?.howToConfirmFixed ?? 'Re-run the check that found it and confirm it no longer appears.')}${f.verification?.rerunCommand ? ` <code>${escapeHtml(f.verification.rerunCommand)}</code>` : ''}</dd>
<dt>References</dt><dd>CWE ${escapeHtml(f.cwe.join(', ') || '—')}. ASVS ${escapeHtml(f.mappings.asvs.join(', ') || '—')}. AISVS ${escapeHtml(f.mappings.aisvs.join(', ') || '—')}. SbD ${escapeHtml(f.mappings.sbd.join(', ') || '—')}.</dd>
<dt>History / triage</dt><dd>First seen ${escapeHtml(f.firstSeenRun ?? 'this run')}, last seen ${escapeHtml(f.lastSeenRun ?? 'this run')}. Who can fix it: ${escapeHtml(f.whoCanFix)}.${f.triage ? ` Triage: ${escapeHtml(f.triage.reason)} (by ${escapeHtml(f.triage.by)} on ${escapeHtml(f.triage.at.slice(0, 10))}).` : ''}</dd>
</dl>
</div>`;
    })
    .join('\n');
  body.push(`<section id="findings-by-priority" class="chapter"><h2>4. Findings by priority</h2>${findingCards || '<p>No open findings.</p>'}</section>`);

  body.push(
    `<section id="fixed" class="chapter"><h2>5. Fixed during the build</h2>${
      fixed.length ? htmlTable(['Id', 'Title', 'Round', 'Diff'], fixed.map((f) => [escapeHtml(f.id), escapeHtml(f.title), String(f.fixedInRound ?? ''), f.fixDiffPath ? `<a href="${escapeHtml(f.fixDiffPath)}">${escapeHtml(f.fixDiffPath)}</a>` : ''])) : '<p>Nothing needed fixing during this build.</p>'
    }</section>`,
  );

  body.push(
    `<section id="accepted" class="chapter"><h2>6. Accepted risks &amp; false positives</h2>${
      [...accepted, ...falsePositive].length
        ? htmlTable(['Id', 'Title', 'Decision', 'Reason', 'By'], [...accepted, ...falsePositive].map((f) => [escapeHtml(f.id), escapeHtml(f.title), escapeHtml(f.status), escapeHtml(f.triage?.reason ?? ''), escapeHtml(f.triage?.by ?? '')]))
        : '<p>None recorded.</p>'
    }</section>`,
  );

  body.push(
    `<section id="dast" class="chapter"><h2>7. Runtime (DAST) probe results</h2>${
      input.probeResults.length
        ? htmlTable(
            ['Probe', 'Result', 'Expected', 'Observed'],
            input.probeResults.map((p) => [escapeHtml(p.id), p.passed === null ? 'Not attempted' : p.passed ? 'Passed' : 'Failed', escapeHtml(p.expected ?? ''), escapeHtml(p.observed ?? p.reason ?? '')]),
          )
        : '<p>No runtime probes ran for this run.</p>'
    }</section>`,
  );

  body.push(
    `<section id="tests" class="chapter"><h2>8. Test results</h2><p>${testCounts.passed} passed, ${testCounts.failed} failed, ${testCounts.skipped} skipped, of ${testCounts.total} total.</p>${
      failedTests.length ? htmlTable(['Test', 'File'], failedTests.map((t) => [escapeHtml(t.name), escapeHtml(t.file ?? '')])) : ''
    }</section>`,
  );

  body.push(
    `<section id="deps" class="chapter"><h2>9. Dependencies, SBOM &amp; licenses</h2><p>${
      input.sbomPath ? `A full software bill of materials (SBOM, CycloneDX format) is included at <code>${escapeHtml(input.sbomPath)}</code>.` : 'No software bill of materials was generated for this run.'
    }</p>${
      depFindings.length
        ? htmlTable(
            ['Package', 'Installed', 'Fixed in', 'Advisories', 'Severity'],
            depFindings.map((f) => [escapeHtml(f.dependency?.package ?? ''), escapeHtml(f.dependency?.installedVersion ?? ''), escapeHtml(f.dependency?.fixedVersion ?? ''), escapeHtml(f.dependency?.advisoryIds.join(', ') ?? ''), escapeHtml(severityText(f.severity))]),
          )
        : '<p>No known-vulnerable dependencies were found.</p>'
    }</section>`,
  );

  body.push(
    `<section id="secrets-config" class="chapter"><h2>10. Secrets &amp; configuration checks</h2>${htmlList([
      `Secret scanning: ${secretFindings.filter(isOpen).length} open finding(s).`,
      `Configuration checks: ${configFindings.filter(isOpen).length} open finding(s).`,
    ])}${
      secretFindings.length || configFindings.length
        ? htmlTable(['Id', 'Source', 'Title', 'Status'], [...secretFindings, ...configFindings].map((f) => [escapeHtml(f.id), escapeHtml(f.source), escapeHtml(f.title), escapeHtml(f.status)]))
        : ''
    }</section>`,
  );

  body.push(`<section id="reverify" class="chapter"><h2>11. How to re-verify</h2>${htmlTable(['Step', 'Command'], reVerifyCommands(input).map((c) => [escapeHtml(c.label), `<code>${escapeHtml(c.command)}</code>`]))}</section>`);

  body.push(
    `<section id="provenance" class="chapter"><h2>12. Provenance</h2>${htmlList([
      `Run: <code>${escapeHtml(provenance.runId)}</code> on ${escapeHtml(provenance.generatedAt.slice(0, 10))} (mode: ${escapeHtml(provenance.mode)}).`,
      `Code tree hash: <code>${escapeHtml(provenance.codeTreeHash)}</code>.`,
      `Sandbox: ${escapeHtml(provenance.sandbox.note)}`,
    ])}</section>`,
  );

  const html = renderPage({
    title: `${input.profile?.app.name ?? 'App'} — security report`,
    subtitle: `${open.length} open finding(s) — ${byPriority.P1} urgent (P1)`,
    generatedAt: provenance.generatedAt,
    banners,
    toc,
    bodyHtml: body.join('\n'),
    glossaryHtml: glossaryHtml(input.knowledge.glossary),
    filterLabel: 'Show everything, including fixed and accepted findings',
  });

  return { md: md.join('\n'), html, json };
}
