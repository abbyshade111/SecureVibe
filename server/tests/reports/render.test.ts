import { mkdirSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ComplianceResultSchema } from '@shared/compliance.js';
import { adrAnchor } from '../../src/reports/adrs.js';
import { renderComplianceReport } from '../../src/reports/compliance-report.js';
import { renderSecurityReport } from '../../src/reports/security-report.js';
import { renderOverview } from '../../src/reports/overview.js';
import { renderGoingOnline, needsGoingOnline } from '../../src/reports/going-online.js';
import { renderDesignDoc } from '../../src/reports/design-doc.js';
import { buildSarif } from '../../src/reports/sarif.js';
import type { ReportModel } from '../../src/reports/types.js';
import { buildReportModel } from '../fixtures/reports/model.js';

let dir: string;
let model: ReportModel;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securevibe-reports-'));
  model = await buildReportModel(join(dir, 'reports'), join(dir, 'app'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function assertSelfContainedHtml(html: string) {
  expect(html).toMatch(/^<!doctype html>/i);
  expect(html).toContain('<html');
  expect(html).toContain('</html>');
  expect(html).toContain('<style>'); // CSS is inline
  expect(html).not.toMatch(/<link\b/i); // no external stylesheet
  expect(html).not.toMatch(/<script\b/i); // no scripts at all — the filter is CSS-only, so no <script>/<link> can reference an external URL
  expect(Buffer.byteLength(html, 'utf8')).toBeLessThan(5 * 1024 * 1024);
}

describe('renderComplianceReport', () => {
  it('links every design ADR to its full text and includes the app\'s own decision records as text', () => {
    mkdirSync(join(model.appDir, 'docs', 'adr'), { recursive: true });
    writeFileSync(
      join(model.appDir, 'docs', 'adr', '0001-sample.md'),
      '# ADR 1: Sample decision\n\n## Context\n\nUses `node:sqlite`.\n\n<img src=x onerror=alert(1)>\n',
    );
    const { html, md } = renderComplianceReport(model);
    for (const adr of model.design.adrs) {
      const anchor = adrAnchor(adr.id);
      expect(html).toContain(`href="#${anchor}"`);
      expect(html).toContain(`id="${anchor}"`);
      expect(md).toContain(`<a id="${anchor}"></a>`);
    }
    expect(html).toContain('id="adrs"');
    expect(html).toContain('ADR 1: Sample decision');
    expect(html).toContain('<code>node:sqlite</code>');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('produces valid, self-contained HTML with every section anchor present', () => {
    const { html } = renderComplianceReport(model);
    assertSelfContainedHtml(html);
    for (const id of ['scope', 'methodology', 'design-summary', 'traceability', 'sbd-checklist', 'asvs-results', 'aisvs-results', 'appendix-c', 'findings', 'manual-verification', 'recommendations', 'sign-off', 'provenance']) {
      expect(html).toContain(`id="${id}"`);
    }
    // A specific requirement id is anchored and reachable.
    expect(html).toContain('id="req-V6.2.1"');
    expect(html).toContain('id="sbd-AS-01"');
  });

  it('the markdown version contains every required section heading, in order', () => {
    const { md } = renderComplianceReport(model);
    const headings = [
      '## 1. Scope & what was assessed',
      '## 2. Coverage limits & methodology',
      '## 3. Design summary',
      '## 4. Traceability matrix',
      '## 5. Secure by Design checklist',
      '## 6. ASVS results',
      '## 7. AISVS results',
      '## 8. AI-assisted development process',
      '## 9. Findings affecting compliance',
      '## 10. Manual verification',
      '## 11. Prioritised recommendations',
      '## 12. Human sign-off',
      '## 13. Provenance',
    ];
    let cursor = 0;
    for (const h of headings) {
      const idx = md.indexOf(h, cursor);
      expect(idx, `expected to find "${h}" after position ${cursor}`).toBeGreaterThanOrEqual(0);
      cursor = idx + h.length;
    }
  });

  it('never uses the words "compliant" or "certified" in SecureVibe\'s own prose (the requirement text it quotes from OWASP is not SecureVibe\'s voice)', () => {
    // These are the report's own sentences, not the verbatim ASVS/AISVS requirement descriptions it quotes
    // (one AISVS Appendix C requirement legitimately contains the word "non-compliant" in its official text).
    const ownVoice = [model.compliance.overall.headline, model.compliance.overall.canIUseIt, model.compliance.methodology, ...model.compliance.limitations, ...model.compliance.asvs.results.map((r) => r.rationale)].join(' ');
    expect(ownVoice).not.toMatch(/\bcompliant\b/i);
    expect(ownVoice).not.toMatch(/\bcertified\b/i);
    const { html } = renderComplianceReport(model);
    expect(html).toContain(model.compliance.overall.headline.replace(/&/g, '&amp;'));
  });

  it('states the non-dismissable AI disclaimer when no human review was performed', () => {
    const { html, md } = renderComplianceReport(model);
    expect(model.compliance.humanReview.performed).toBe(false);
    expect(html).toContain('This code was generated by an AI and has not been reviewed by a qualified human engineer.');
    expect(md).toContain('This code was generated by an AI and has not been reviewed by a qualified human engineer.');
  });

  it('produces a JSON payload that round-trips through the shared schema', () => {
    const { json } = renderComplianceReport(model);
    const parsed = JSON.parse(json);
    expect(() => ComplianceResultSchema.parse(parsed)).not.toThrow();
  });
});

describe('renderSecurityReport', () => {
  it('produces valid, self-contained HTML with a finding card anchored by id', () => {
    const { html } = renderSecurityReport(model);
    assertSelfContainedHtml(html);
    expect(html).toContain('id="finding-f-0001"');
    for (const id of ['summary', 'risk-method', 'coverage', 'findings-by-priority', 'fixed', 'accepted', 'dast', 'tests', 'deps', 'secrets-config', 'reverify', 'provenance']) {
      expect(html).toContain(`id="${id}"`);
    }
  });

  it('the finding template covers every required field', () => {
    const { md } = renderSecurityReport(model);
    expect(md).toContain('F-0001: Passwords are not checked');
    expect(md).toMatch(/\*\*Priority \/ severity\*\*/);
    expect(md).toMatch(/\*\*Where\*\*/);
    expect(md).toMatch(/\*\*What it is\*\*/);
    expect(md).toMatch(/\*\*Why it matters\*\*/);
    expect(md).toMatch(/\*\*What we observed\*\*/);
    expect(md).toMatch(/\*\*How to fix it\*\*/);
    expect(md).toMatch(/\*\*How to confirm it is fixed\*\*/);
    expect(md).toMatch(/\*\*References\*\*/);
    expect(md).toMatch(/\*\*History\*\*/);
  });

  it('the markdown version contains every required section heading', () => {
    const { md } = renderSecurityReport(model);
    for (const h of ['## 1. Summary', '## 2. How risk is rated', '## 3. Tool coverage & limits', '## 4. Findings by priority', '## 5. Fixed during the build', '## 6. Accepted risks & false positives', '## 7. Runtime (DAST) probe results', '## 8. Test results', '## 9. Dependencies, SBOM & licenses', '## 10. Secrets & configuration checks', '## 11. How to re-verify', '## 12. Provenance']) {
      expect(md).toContain(h);
    }
  });

  it('produces a valid JSON payload', () => {
    const { json } = renderSecurityReport(model);
    const parsed = JSON.parse(json) as { findings: unknown[] };
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(parsed.findings).toHaveLength(1);
  });
});

describe('renderOverview', () => {
  it('produces valid, self-contained HTML with the required sections', () => {
    const html = renderOverview(model);
    assertSelfContainedHtml(html);
    for (const id of ['what-you-built', 'can-i-use-it', 'top-actions', 'scorecards', 'not-checked', 'recheck']) {
      expect(html).toContain(`id="${id}"`);
    }
  });
});

describe('renderGoingOnline', () => {
  it('is produced for an internet-later, customer-facing app', () => {
    expect(needsGoingOnline(model)).toBe(true);
    const { md, html } = renderGoingOnline(model);
    expect(md).toContain('# Going online safely');
    assertSelfContainedHtml(html);
  });
});

describe('renderDesignDoc', () => {
  it('renders a non-empty design.md from the profile when no pre-rendered markdown is supplied', () => {
    const md = renderDesignDoc(model);
    expect(md).toContain('design document');
    expect(md.length).toBeGreaterThan(200);
  });

  it('uses the supplied designMarkdown verbatim when present', () => {
    const md = renderDesignDoc({ ...model, designMarkdown: '# Pre-rendered\n\nAlready done.' });
    expect(md).toBe('# Pre-rendered\n\nAlready done.');
  });
});

describe('buildSarif', () => {
  it('produces a structurally valid SARIF 2.1.0 document', () => {
    const sarif = buildSarif(model.findings, '0.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.tool.driver.name).toBe('SecureVibe');
    expect(sarif.runs[0]!.tool.driver.rules.map((r) => r.id)).toContain('sast.example');
    expect(sarif.runs[0]!.results).toHaveLength(1);
    const result = sarif.runs[0]!.results[0]!;
    expect(result.ruleId).toBe('sast.example');
    expect(result.level).toBe('error'); // high severity
    expect(result.locations[0]!.physicalLocation.artifactLocation.uri).toBe('src/security/password.ts');
    expect(result.partialFingerprints.securevibeFingerprint).toBe('fp-0001');
  });
});
