/**
 * Probe results → evidence and findings. The honesty rules live here: "not attempted" is never evidence and
 * never a finding, remediation text comes from the knowledge base by probe id, and every probe id in the
 * knowledge base has a probe behind it.
 */
import { describe, expect, it } from 'vitest';
import type { RemediationEntry } from '@shared/knowledge.js';
import { loadKnowledge } from '../../src/frameworks/index.js';
import { evidenceForResult, evidenceRef, findingsForResult } from '../../src/scanners/dast/findings.js';
import { ALL_PROBES, probeById } from '../../src/scanners/dast/probes/index.js';
import { PROBE_GROUPS, type ProbeResult } from '../../src/scanners/dast/types.js';

const knowledge = loadKnowledge({ warn: () => {} });

function result(overrides: Partial<ProbeResult> & Pick<ProbeResult, 'id' | 'passed'>): ProbeResult {
  return {
    group: 'headers',
    phase: 'test',
    requirementIds: ['V3.4.3', 'V3.4.6'],
    expected: 'a content security policy is sent',
    observed: 'no Content-Security-Policy header',
    durationMs: 3,
    ...overrides,
  };
}

describe('probe catalog', () => {
  it('every probe id is unique and namespaced dast.*', () => {
    const ids = ALL_PROBES.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^dast\.[a-z0-9-]+\.[a-z0-9-]+$/);
  });

  it('every probe declares a group, requirement ids and built-in remediation wording', () => {
    for (const probe of ALL_PROBES) {
      expect(PROBE_GROUPS, probe.id).toContain(probe.group);
      expect(probe.requirementIds.length, probe.id).toBeGreaterThan(0);
      expect(probe.fallback.title.length, probe.id).toBeGreaterThan(10);
      expect(probe.fallback.fix.length, probe.id).toBeGreaterThan(10);
    }
  });

  it('every dast.* rule in the knowledge base has a probe', () => {
    const missing = Object.keys(knowledge.remediation)
      .filter((id) => id.startsWith('dast.'))
      .filter((id) => !probeById(id));
    expect(missing).toEqual([]);
  });

  it('covers every probe id CONTRACTS lists for the rate-limit group', () => {
    for (const id of [
      'dast.auth.login-rate-limited',
      'dast.auth.mfa-rate-limited',
      'dast.rate.registration-limited',
      'dast.rate.reset-limited',
      'dast.rate.xff-spoof-ignored',
    ]) {
      expect(probeById(id)?.group, id).toBe('rate');
    }
  });
});

describe('evidence', () => {
  it('records a passing probe as strong evidence with a plain-language summary', () => {
    const [evidence] = evidenceForResult(result({ id: 'dast.headers.csp', passed: true, observed: 'policy present' }), probeById('dast.headers.csp'), {
      runId: 'run-1',
    });
    expect(evidence?.type).toBe('dast');
    expect(evidence?.tier).toBe('strong');
    expect(evidence?.passed).toBe(true);
    expect(evidence?.ref).toBe('dast:headers.csp');
    expect(evidence?.summary).toContain('Checked on the running app');
    expect(evidence?.runId).toBe('run-1');
  });

  it('records a failing probe as failing evidence, not as missing evidence', () => {
    const [evidence] = evidenceForResult(result({ id: 'dast.headers.csp', passed: false }), probeById('dast.headers.csp'));
    expect(evidence?.passed).toBe(false);
    expect(evidence?.summary).toContain('It did not');
  });

  it('produces nothing at all for a probe that could not run', () => {
    const notAttempted = result({ id: 'dast.headers.csp', passed: null, observed: 'not attempted', reason: 'the app has no sign-in page' });
    expect(evidenceForResult(notAttempted, probeById('dast.headers.csp'))).toEqual([]);
    expect(findingsForResult(notAttempted, probeById('dast.headers.csp'))).toEqual([]);
  });

  it('keeps the request and response excerpts as raw evidence', () => {
    const [evidence] = evidenceForResult(
      result({ id: 'dast.headers.csp', passed: false, requestExcerpt: 'GET /login', responseExcerpt: 'HTTP 200' }),
      probeById('dast.headers.csp'),
      { artifactPath: 'pipeline/run-1/dast/probes.json' },
    );
    expect(evidence?.raw?.excerpt).toContain('GET /login');
    expect(evidence?.raw?.excerpt).toContain('HTTP 200');
    expect(evidence?.raw?.artifactPath).toBe('pipeline/run-1/dast/probes.json');
  });
});

describe('findings', () => {
  it('takes title, severity and remediation from the knowledge base when it has an entry', () => {
    const entry = knowledge.remediation['dast.headers.csp'] as RemediationEntry;
    const [finding] = findingsForResult(result({ id: 'dast.headers.csp', passed: false }), probeById('dast.headers.csp'), { knowledge });
    expect(finding?.source).toBe('dast');
    expect(finding?.ruleId).toBe('dast.headers.csp');
    expect(finding?.title).toBe(entry.title);
    expect(finding?.severity).toBe(entry.severity);
    expect(finding?.remediation.summary).toBe(entry.remediation.summary);
    expect(finding?.mappings.asvs).toEqual(expect.arrayContaining(['V3.4.3']));
    expect(finding?.verification?.howToConfirmFixed).toBe(entry.howToConfirmFixed);
  });

  it('falls back to the probe\'s own wording when the knowledge base has no entry', () => {
    const [finding] = findingsForResult(result({ id: 'dast.made.up', passed: false, requirementIds: ['V3.4.3'] }), probeById('dast.headers.csp'), {});
    expect(finding?.title).toBe(probeById('dast.headers.csp')?.fallback.title);
    expect(finding?.remediation.summary).toBe(probeById('dast.headers.csp')?.fallback.fix);
  });

  it('produces one finding per endpoint when a probe checked many', () => {
    const findings = findingsForResult(
      result({
        id: 'dast.authz.anonymous-denied',
        group: 'authz',
        passed: false,
        requirementIds: ['V8.2.1'],
        failures: [
          { endpoint: 'GET /admin', observed: 'status 200 without a session' },
          { endpoint: 'GET /api/notes', observed: 'status 200 without a session' },
        ],
      }),
      probeById('dast.authz.anonymous-denied'),
      { knowledge },
    );
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.location?.endpoint)).toEqual(['GET /admin', 'GET /api/notes']);
    expect(new Set(findings.map((f) => f.fingerprint)).size).toBe(2);
  });

  it('gives the same fingerprint for the same problem on two runs', () => {
    const make = () => findingsForResult(result({ id: 'dast.headers.csp', passed: false, endpoint: 'GET /login' }), probeById('dast.headers.csp'), { knowledge })[0];
    expect(make()?.fingerprint).toBe(make()?.fingerprint);
  });

  it('lets a probe raise the severity of its own finding', () => {
    const [finding] = findingsForResult(
      result({ id: 'dast.headers.csp', passed: false, findingOnFail: { severity: 'critical', confidence: 'medium' } }),
      probeById('dast.headers.csp'),
      { knowledge },
    );
    expect(finding?.severity).toBe('critical');
    expect(finding?.confidence).toBe('medium');
  });

  it('builds the evidence reference the compliance engine expects', () => {
    expect(evidenceRef('dast.session.rotated-on-login')).toBe('dast:session.rotated-on-login');
  });
});
