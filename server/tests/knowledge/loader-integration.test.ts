/**
 * Loads the real data/knowledge files through the server's loader (server/src/frameworks/knowledge.ts) to prove
 * the shapes this module writes are the shapes the rest of SecureVibe reads: glossary entries carry `plain`,
 * injection patterns expose `high`/`medium`, examples validate as ExampleProject, and nothing is reported missing.
 */
import { describe, expect, it } from 'vitest';
import { loadKnowledge, resetKnowledgeCache } from '../../src/frameworks/knowledge.js';
import { KNOWLEDGE_DIR } from './helpers.js';

describe('data/knowledge through the server loader', () => {
  resetKnowledgeCache();
  const warnings: string[] = [];
  const knowledge = loadKnowledge({ dir: KNOWLEDGE_DIR, warn: (m) => warnings.push(m) });

  it('finds every file this module owns', () => {
    expect(knowledge.missingFiles).toEqual([]);
    expect(warnings).toEqual([]);
  });

  it('exposes the glossary, injection patterns, examples, remediation and plain-language entries', () => {
    expect(knowledge.glossary.length).toBeGreaterThan(80);
    expect(knowledge.glossary.every((g) => typeof g.plain === 'string' && g.plain.length > 0)).toBe(true);
    expect(knowledge.injectionPatterns.high.length).toBeGreaterThanOrEqual(10);
    expect(knowledge.injectionPatterns.medium.length).toBeGreaterThanOrEqual(5);
    expect(knowledge.examples.map((e) => e.id).sort()).toEqual(['customer-portal', 'habit-log', 'salon-booking', 'shop-inventory', 'team-tasks-ai']);
    expect(Object.keys(knowledge.remediation).length).toBeGreaterThan(160);
    expect(Object.keys(knowledge.requirementsPlain).length).toBeGreaterThan(400);
    expect(knowledge.wizardCopy).toHaveProperty('questions');
    expect(knowledge.wizardCopy).toHaveProperty('whatThisChanges');
  });
});
