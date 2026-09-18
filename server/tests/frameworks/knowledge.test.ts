import { copyFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { KNOWLEDGE_DIR, KNOWLEDGE_FILES, loadKnowledge } from '../../src/frameworks/index.js';

function tempKnowledgeDir(): string {
  const dir = mkdtempSync(join(process.env['TMPDIR'] ?? tmpdir(), 'securevibe-knowledge-'));
  for (const file of [KNOWLEDGE_FILES.applicability, KNOWLEDGE_FILES.sbdRules, KNOWLEDGE_FILES.patterns]) {
    copyFileSync(join(KNOWLEDGE_DIR, file), join(dir, file));
  }
  return dir;
}

describe('loadKnowledge', () => {
  it('loads the real knowledge directory and validates the files this module owns', () => {
    const k = loadKnowledge({ warn: () => {} });
    expect(k.applicability.defaultVerificationClass).toBe('ai-assistable');
    expect(k.applicability.rules.length).toBeGreaterThan(100);
    expect(k.sbdRules).toHaveLength(36);
    expect(k.patterns).toHaveLength(27);
    expect(loadKnowledge()).toBe(k);
  });

  it('returns empty structures and warns when files owned by other modules are missing', () => {
    const dir = tempKnowledgeDir();
    const warnings: string[] = [];
    const k = loadKnowledge({ dir, warn: (m) => warnings.push(m) });
    expect(k.missingFiles.sort()).toEqual(
      [
        KNOWLEDGE_FILES.remediation,
        KNOWLEDGE_FILES.requirementsPlain,
        KNOWLEDGE_FILES.glossary,
        KNOWLEDGE_FILES.wizardCopy,
        KNOWLEDGE_FILES.examples,
        KNOWLEDGE_FILES.injectionPatterns,
      ].sort(),
    );
    expect(warnings).toHaveLength(6);
    expect(k.remediation).toEqual({});
    expect(k.requirementsPlain).toEqual({});
    expect(k.glossary).toEqual([]);
    expect(k.wizardCopy).toEqual({});
    expect(k.examples).toEqual([]);
    expect(k.injectionPatterns).toEqual({ high: [], medium: [] });
  });

  it('validates optional files when they are present and accepts array or keyed shapes', () => {
    const dir = tempKnowledgeDir();
    writeFileSync(
      join(dir, KNOWLEDGE_FILES.remediation),
      JSON.stringify([
        {
          ruleId: 'sast.eval-usage',
          title: 'Dynamic code execution',
          severity: 'high',
          description: 'd',
          impact: 'i',
          remediation: { summary: 's', steps: ['a'] },
        },
      ]),
    );
    writeFileSync(
      join(dir, KNOWLEDGE_FILES.requirementsPlain),
      JSON.stringify({ 'V6.2.1': { plain: 'Passwords must be at least 12 characters.' } }),
    );
    writeFileSync(join(dir, KNOWLEDGE_FILES.glossary), JSON.stringify({ CSRF: 'A forged request from another site.' }));
    writeFileSync(
      join(dir, KNOWLEDGE_FILES.injectionPatterns),
      JSON.stringify({ high: [{ id: 'ignore-previous', pattern: 'ignore (all )?previous instructions', flags: 'i' }], medium: [] }),
    );
    const k = loadKnowledge({ dir, warn: () => {} });
    expect(k.remediation['sast.eval-usage']?.severity).toBe('high');
    expect(k.requirementsPlain['V6.2.1']?.plain).toContain('12 characters');
    expect(k.glossary).toEqual([{ term: 'CSRF', plain: 'A forged request from another site.' }]);
    expect(k.injectionPatterns.high).toHaveLength(1);
    expect(k.missingFiles).toEqual([KNOWLEDGE_FILES.wizardCopy, KNOWLEDGE_FILES.examples]);
  });

  it('accepts glossary entries named "definition" and injection lists named "highPrecision"', () => {
    const dir = tempKnowledgeDir();
    writeFileSync(
      join(dir, KNOWLEDGE_FILES.glossary),
      JSON.stringify([{ term: 'ASVS', definition: 'A public checklist of what a secure web application should do.' }]),
    );
    writeFileSync(
      join(dir, KNOWLEDGE_FILES.injectionPatterns),
      JSON.stringify({
        description: 'ruleset',
        highPrecision: [{ id: 'inj.ignore', pattern: 'ignore previous', flags: 'i' }],
        medium: [{ id: 'inj.m.system-prompt', pattern: 'system prompt', flags: 'i' }],
      }),
    );
    const k = loadKnowledge({ dir, warn: () => {} });
    expect(k.glossary[0]).toMatchObject({ term: 'ASVS', plain: 'A public checklist of what a secure web application should do.' });
    expect(k.injectionPatterns.high.map((p) => p.id)).toEqual(['inj.ignore']);
    expect(k.injectionPatterns.medium.map((p) => p.id)).toEqual(['inj.m.system-prompt']);
  });

  it('loads the optional files other modules have written so far, when present', () => {
    const k = loadKnowledge({ warn: () => {} });
    for (const file of k.missingFiles) process.stdout.write(`[knowledge] ${file} not written yet\n`);
    if (!k.missingFiles.includes(KNOWLEDGE_FILES.glossary)) expect(k.glossary.length).toBeGreaterThan(0);
    if (!k.missingFiles.includes(KNOWLEDGE_FILES.injectionPatterns)) expect(k.injectionPatterns.high.length).toBeGreaterThan(0);
    if (!k.missingFiles.includes(KNOWLEDGE_FILES.remediation)) expect(Object.keys(k.remediation).length).toBeGreaterThan(0);
    if (!k.missingFiles.includes(KNOWLEDGE_FILES.requirementsPlain)) expect(k.requirementsPlain['V6.2.1']?.plain).toBeTruthy();
  });

  it('accepts a flat injection-pattern list with a precision field', () => {
    const dir = tempKnowledgeDir();
    writeFileSync(
      join(dir, KNOWLEDGE_FILES.injectionPatterns),
      JSON.stringify([
        { id: 'a', pattern: 'x', precision: 'high' },
        { id: 'b', pattern: 'y' },
      ]),
    );
    const k = loadKnowledge({ dir, warn: () => {} });
    expect(k.injectionPatterns.high.map((p) => p.id)).toEqual(['a']);
    expect(k.injectionPatterns.medium.map((p) => p.id)).toEqual(['b']);
  });

  it('fails loudly on an invalid optional file instead of silently ignoring it', () => {
    const dir = tempKnowledgeDir();
    writeFileSync(join(dir, KNOWLEDGE_FILES.remediation), JSON.stringify([{ ruleId: 'x' }]));
    expect(() => loadKnowledge({ dir, warn: () => {} })).toThrow(/remediation\.json is invalid/);
  });
});
