import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { STATUS_DEFINITIONS } from '@shared/compliance.js';
import { plainLanguageProblems, readKnowledge } from './helpers.js';

/**
 * Glossary entries carry both `definition` (this module's contract) and `plain` (what
 * server/src/frameworks/knowledge.ts reads). They must be identical.
 */
const GlossaryEntrySchema = z
  .object({
    term: z.string().min(1),
    definition: z.string().min(20),
    plain: z.string().min(20),
    seeAlso: z.array(z.string()).optional(),
  })
  .strict();

/** Terms the UI and reports use; each must be findable by this keyword (case-insensitive substring of the term). */
const REQUIRED_KEYWORDS = [
  'ASVS',
  'AISVS',
  'Appendix C',
  'SbD',
  'OWASP',
  'CSRF',
  'CSP',
  'TLS',
  'HSTS',
  'MFA',
  'TOTP',
  'IDOR',
  'SAST',
  'DAST',
  'SBOM',
  'CWE',
  'CVSS',
  'XSS',
  'SQL injection',
  'Prompt injection',
  'Rate limiting',
  'Session',
  'Cookie',
  'Hash',
  'Encryption at rest',
  'Encryption in transit',
  'Least privilege',
  'Threat model',
  'STRIDE',
  'Provenance',
  'Attestation',
  'Evidence tiers',
  'Priority',
  'Severity',
  'Confidence',
  'Exploitability',
  'Finding',
  'Evidence',
  'Manual verification',
  'Human review',
  'Audit log',
  'Incident response',
  'Data retention',
  'Secrets',
  'API key',
  'Trust zones',
  'Extra care',
  'Level 1',
];

/** Every requirement status from shared/src/compliance.ts must have a glossary term. */
const STATUS_TERMS: Record<keyof typeof STATUS_DEFINITIONS, string> = {
  pass: 'Pass',
  'ai-assessed': 'AI-assessed',
  documented: 'Documented',
  attested: 'Attested',
  partial: 'Partial',
  fail: 'Fail',
  'not-applicable': 'Not applicable',
  'not-verified': 'Not verified',
  'out-of-level': 'Out of level',
};

const raw = readKnowledge<unknown>('glossary.json');

describe('data/knowledge/glossary.json', () => {
  const entries = z.array(GlossaryEntrySchema).parse(raw);
  const terms = entries.map((e) => e.term);
  const lowerTerms = terms.map((t) => t.toLowerCase());

  it('has unique terms and identical definition/plain text', () => {
    expect(new Set(lowerTerms).size).toBe(terms.length);
    for (const e of entries) expect(e.plain, e.term).toBe(e.definition);
  });

  it('defines every acronym and concept the UI and reports use', () => {
    const missing = REQUIRED_KEYWORDS.filter((kw) => !lowerTerms.some((t) => t.includes(kw.toLowerCase())));
    expect(missing).toEqual([]);
  });

  it('defines every requirement status from STATUS_DEFINITIONS and P1-P4 priorities', () => {
    for (const [status, term] of Object.entries(STATUS_TERMS)) {
      const entry = entries.find((e) => e.term.toLowerCase() === term.toLowerCase());
      expect(entry, `status ${status} → term "${term}"`).toBeDefined();
    }
    const priority = entries.find((e) => /priority/i.test(e.term));
    expect(priority).toBeDefined();
    for (const p of ['P1', 'P2', 'P3', 'P4']) expect(priority!.definition, `priority entry should explain ${p}`).toContain(p);
  });

  it('definitions are plain language: short sentences, acronyms explained', () => {
    for (const e of entries) {
      const problems = plainLanguageProblems(`${e.term}. ${e.definition}`, { checkAcronyms: true });
      expect(problems, e.term).toEqual([]);
      expect(e.definition.trim().endsWith('.'), `${e.term} should end with a full stop`).toBe(true);
    }
  });

  it('seeAlso references point at existing terms', () => {
    const bad: string[] = [];
    for (const e of entries) for (const ref of e.seeAlso ?? []) if (!lowerTerms.includes(ref.toLowerCase())) bad.push(`${e.term} → ${ref}`);
    expect(bad).toEqual([]);
  });
});
