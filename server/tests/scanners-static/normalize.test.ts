/**
 * normalize.ts / finalizeFindings (CONTRACTS §9.2): dedupe by fingerprint, SAST-over-lint preference,
 * remediation enrichment, deployment-adjusted severity, priority, whoCanFix, persisted decisions,
 * firstSeenRun/lastSeenRun continuity, and final id assignment + sort order.
 */
import { describe, expect, it } from 'vitest';
import type { Finding } from '@shared/findings.js';
import type { FindingDecision } from '@shared/project.js';
import { finalizeFindings } from '../../src/scanners/normalize.js';
import { fixtureDir, makeScanContext } from './helpers.js';

function makeFinding(overrides: Partial<Finding> & Pick<Finding, 'fingerprint' | 'ruleId' | 'source'>): Finding {
  return {
    id: 'tmp-0000',
    title: 'A finding',
    severity: 'medium',
    priority: 'P3',
    exploitability: 'requires-network-exposure',
    confidence: 'high',
    cwe: [],
    description: 'What it is.',
    impact: 'Why it matters.',
    evidence: 'What was observed.',
    remediation: { summary: 'Fix it.', steps: [], references: [] },
    mappings: { asvs: [], aisvs: [], sbd: [] },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'unknown',
    sourcesReporting: [overrides.source],
    ...overrides,
  };
}

const ctx = makeScanContext(fixtureDir('clean-app'));

describe('finalizeFindings: de-duplication', () => {
  it('merges two findings that share a fingerprint, unioning sourcesReporting, cwe and mappings', () => {
    const a = makeFinding({
      fingerprint: 'fp-1',
      ruleId: 'sast.example',
      source: 'sast',
      cwe: ['CWE-79'],
      mappings: { asvs: ['V1.1.2'], aisvs: [], sbd: [] },
    });
    const b = makeFinding({
      fingerprint: 'fp-1',
      ruleId: 'sast.example',
      source: 'external',
      cwe: ['CWE-80'],
      mappings: { asvs: [], aisvs: [], sbd: ['AS-01'] },
    });
    const out = finalizeFindings([a, b], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out).toHaveLength(1);
    expect(out[0]!.sourcesReporting.sort()).toEqual(['external', 'sast']);
    expect(out[0]!.cwe.sort()).toEqual(['CWE-79', 'CWE-80']);
    expect(out[0]!.mappings.asvs).toEqual(['V1.1.2']);
    expect(out[0]!.mappings.sbd).toEqual(['AS-01']);
  });

  it('a lint finding at the same file:line as a sast finding is absorbed into the sast finding (SAST wins)', () => {
    const sast = makeFinding({
      fingerprint: 'fp-sast',
      ruleId: 'sast.eval-usage',
      source: 'sast',
      severity: 'high',
      location: { file: 'src/a.ts', line: 10 },
    });
    const lint = makeFinding({
      fingerprint: 'fp-lint',
      ruleId: 'lint.security/detect-eval-with-expression',
      source: 'lint',
      severity: 'high',
      location: { file: 'src/a.ts', line: 10 },
    });
    const out = finalizeFindings([sast, lint], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out).toHaveLength(1);
    expect(out[0]!.ruleId).toBe('sast.eval-usage');
    expect(out[0]!.sourcesReporting.sort()).toEqual(['lint', 'sast']);
  });

  it('a lint finding at a different location from any sast finding survives on its own', () => {
    const sast = makeFinding({ fingerprint: 'fp-a', ruleId: 'sast.eval-usage', source: 'sast', location: { file: 'src/a.ts', line: 10 } });
    const lint = makeFinding({ fingerprint: 'fp-b', ruleId: 'lint.security/detect-unsafe-regex', source: 'lint', location: { file: 'src/b.ts', line: 3 } });
    const out = finalizeFindings([sast, lint], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out).toHaveLength(2);
    expect(out.map((f) => f.ruleId).sort()).toEqual(['lint.security/detect-unsafe-regex', 'sast.eval-usage']);
  });
});

describe('finalizeFindings: remediation enrichment', () => {
  it('fills description/impact/cwe/mappings from data/knowledge/remediation.json when the finding left them blank', () => {
    const bare = makeFinding({
      fingerprint: 'fp-enrich',
      ruleId: 'secrets.high-entropy-assignment',
      source: 'secrets',
      description: '',
      impact: '',
      remediation: { summary: '', steps: [], references: [] },
      cwe: [],
      mappings: { asvs: [], aisvs: [], sbd: [] },
    });
    const [out] = finalizeFindings([bare], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out!.description.length).toBeGreaterThan(0);
    expect(out!.impact.length).toBeGreaterThan(0);
    expect(out!.remediation.summary.length).toBeGreaterThan(0);
    expect(out!.cwe).toContain('CWE-798');
  });
});

describe('finalizeFindings: deployment-adjusted severity', () => {
  it('downgrades a requires-network-exposure finding one step for local-only, with a reason', () => {
    const f = makeFinding({ fingerprint: 'fp-net', ruleId: 'sast.cors-any-origin', source: 'sast', severity: 'medium', exploitability: 'requires-network-exposure' });
    const [out] = finalizeFindings([f], ctx, { deploymentTarget: 'local-only', decisions: [], runId: 'r1' });
    expect(out!.severity).toBe('low');
    expect(out!.severityBase).toBe('medium');
    expect(out!.adjustmentReason).toBeDefined();
  });

  it('does not downgrade for local-network or internet-later', () => {
    const f1 = makeFinding({ fingerprint: 'fp-lan', ruleId: 'sast.cors-any-origin', source: 'sast', severity: 'medium', exploitability: 'requires-network-exposure' });
    const [outLan] = finalizeFindings([f1], ctx, { deploymentTarget: 'local-network', decisions: [], runId: 'r1' });
    expect(outLan!.severity).toBe('medium');
    expect(outLan!.adjustmentReason).toBeUndefined();

    const f2 = makeFinding({ fingerprint: 'fp-net2', ruleId: 'sast.cors-any-origin', source: 'sast', severity: 'medium', exploitability: 'requires-network-exposure' });
    const [outNet] = finalizeFindings([f2], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(outNet!.severity).toBe('medium');
  });

  it('does not downgrade a local-only finding whose exploitability is not requires-network-exposure', () => {
    const f = makeFinding({ fingerprint: 'fp-trivial', ruleId: 'sast.hardcoded-secret', source: 'sast', severity: 'critical', exploitability: 'trivial' });
    const [out] = finalizeFindings([f], ctx, { deploymentTarget: 'local-only', decisions: [], runId: 'r1' });
    expect(out!.severity).toBe('critical');
  });
});

describe('finalizeFindings: priority', () => {
  it('computes priority from the (possibly adjusted) severity, confidence and exploitability', () => {
    const p1 = makeFinding({ fingerprint: 'fp-p1', ruleId: 'x', source: 'sast', severity: 'critical', confidence: 'high', exploitability: 'trivial' });
    const p4 = makeFinding({ fingerprint: 'fp-p4', ruleId: 'y', source: 'sast', severity: 'info', confidence: 'low', exploitability: 'theoretical' });
    const out = finalizeFindings([p1, p4], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out.find((f) => f.fingerprint === 'fp-p1')!.priority).toBe('P1');
    expect(out.find((f) => f.fingerprint === 'fp-p4')!.priority).toBe('P4');
  });
});

describe('finalizeFindings: whoCanFix', () => {
  it('routes deployment-only findings to the hosting provider and documentation findings to the owner', () => {
    const tls = makeFinding({ fingerprint: 'fp-tls', ruleId: 'config.tls-mode-consistent', source: 'config', whoCanFix: 'developer' });
    const readme = makeFinding({ fingerprint: 'fp-readme', ruleId: 'config.readme-run-instructions', source: 'config', whoCanFix: 'developer' });
    const ordinary = makeFinding({ fingerprint: 'fp-ord', ruleId: 'sast.eval-usage', source: 'sast', whoCanFix: 'developer' });
    const out = finalizeFindings([tls, readme, ordinary], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out.find((f) => f.fingerprint === 'fp-tls')!.whoCanFix).toBe('hosting-provider');
    expect(out.find((f) => f.fingerprint === 'fp-readme')!.whoCanFix).toBe('owner');
    expect(out.find((f) => f.fingerprint === 'fp-ord')!.whoCanFix).toBe('developer');
  });
});

describe('finalizeFindings: persisted decisions', () => {
  it('applies an accepted decision by fingerprint', () => {
    const f = makeFinding({ fingerprint: 'fp-decided', ruleId: 'sast.console-log', source: 'sast' });
    const decisions: FindingDecision[] = [
      { fingerprint: 'fp-decided', status: 'accepted', triage: { reason: 'Known, low risk here.', by: 'owner:jane', at: new Date().toISOString() } },
    ];
    const [out] = finalizeFindings([f], ctx, { deploymentTarget: 'internet-later', decisions, runId: 'r1' });
    expect(out!.status).toBe('accepted');
    expect(out!.triage?.reason).toBe('Known, low risk here.');
  });

  it('leaves undecided findings open', () => {
    const f = makeFinding({ fingerprint: 'fp-undecided', ruleId: 'sast.console-log', source: 'sast' });
    const [out] = finalizeFindings([f], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out!.status).toBe('open');
  });
});

describe('finalizeFindings: run continuity', () => {
  it('a brand-new finding gets firstSeenRun === lastSeenRun === the current run', () => {
    const f = makeFinding({ fingerprint: 'fp-new', ruleId: 'sast.console-log', source: 'sast' });
    const [out] = finalizeFindings([f], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r2' });
    expect(out!.firstSeenRun).toBe('r2');
    expect(out!.lastSeenRun).toBe('r2');
  });

  it('a recurring finding keeps its original firstSeenRun and advances lastSeenRun', () => {
    const previous = makeFinding({ fingerprint: 'fp-recur', ruleId: 'sast.console-log', source: 'sast', firstSeenRun: 'r1', lastSeenRun: 'r1' });
    const current = makeFinding({ fingerprint: 'fp-recur', ruleId: 'sast.console-log', source: 'sast' });
    const [out] = finalizeFindings([current], ctx, { deploymentTarget: 'internet-later', decisions: [], previousFindings: [previous], runId: 'r2' });
    expect(out!.firstSeenRun).toBe('r1');
    expect(out!.lastSeenRun).toBe('r2');
  });

  it('notes in the evidence when a finding marked fixed in a previous run has reappeared', () => {
    const previous = makeFinding({ fingerprint: 'fp-reap', ruleId: 'sast.console-log', source: 'sast', status: 'fixed', lastSeenRun: 'r1' });
    const current = makeFinding({ fingerprint: 'fp-reap', ruleId: 'sast.console-log', source: 'sast', evidence: 'console.log(x) at line 3' });
    const [out] = finalizeFindings([current], ctx, { deploymentTarget: 'internet-later', decisions: [], previousFindings: [previous], runId: 'r2' });
    expect(out!.status).toBe('open');
    expect(out!.evidence).toContain('reappeared');
  });
});

describe('finalizeFindings: ids and sort order', () => {
  it('assigns sequential F-0001-style ids in priority/severity order', () => {
    const low = makeFinding({ fingerprint: 'fp-low', ruleId: 'a', source: 'sast', severity: 'low', confidence: 'low', exploitability: 'theoretical' });
    const critical = makeFinding({ fingerprint: 'fp-crit', ruleId: 'b', source: 'sast', severity: 'critical', confidence: 'high', exploitability: 'trivial' });
    const out = finalizeFindings([low, critical], ctx, { deploymentTarget: 'internet-later', decisions: [], runId: 'r1' });
    expect(out[0]!.id).toBe('F-0001');
    expect(out[0]!.fingerprint).toBe('fp-crit'); // P1 sorts before P4
    expect(out[1]!.id).toBe('F-0002');
  });
});
