import { describe, expect, it } from 'vitest';
import { chapterIdOf, loadFrameworks, sectionIdOf, standardForId } from '../../src/frameworks/index.js';

describe('loadFrameworks', () => {
  const fw = loadFrameworks();

  it('is cached in module scope', () => {
    expect(loadFrameworks()).toBe(fw);
  });

  it('loads all four frameworks with the expected shape', () => {
    expect(fw.asvs.version).toBe('5.0.0');
    expect(fw.asvs.chapters).toHaveLength(17);
    expect(fw.aisvs.chapters).toHaveLength(12);
    expect(fw.appendixC.chapters).toHaveLength(14);
    expect(fw.sbd.controls).toHaveLength(36);
    expect(fw.sbd.domains.map((d) => d.id)).toEqual(['A', 'B', 'C', 'D', 'E']);
    expect(fw.sbd.scoring.threshold).toBe(6);
    expect(fw.sbd.processSteps).toHaveLength(10);
  });

  it('looks up ASVS, AISVS and Appendix C requirements', () => {
    expect(fw.getRequirement('V6.2.1')).toMatchObject({
      id: 'V6.2.1',
      standard: 'asvs',
      chapterId: 'V6',
      chapterName: 'Authentication',
      sectionId: 'V6.2',
      sectionName: 'Password Security',
      level: 1,
    });
    expect(fw.getRequirement('C2.1.3')).toMatchObject({
      standard: 'aisvs',
      chapterId: 'C2',
      sectionId: 'C2.1',
      level: 1,
    });
    expect(fw.getRequirement('AC.4.1')).toMatchObject({
      standard: 'aisvs-appendix-c',
      chapterId: 'AC.4',
      sectionId: 'AC.4',
      chapterName: 'Validation of AI-Generated Code',
      level: 1,
    });
    expect(fw.getRequirement('V99.1.1')).toBeUndefined();
    expect(fw.getRequirement('C2.1.3')?.description.length).toBeGreaterThan(20);
  });

  it('lists requirements and chapters per standard', () => {
    const asvs = fw.listRequirements('asvs');
    expect(asvs.length).toBeGreaterThan(300);
    expect(asvs.every((r) => r.standard === 'asvs')).toBe(true);
    expect(fw.chapters('aisvs').map((c) => c.id)).toContain('C9');
    const v6 = fw.chapters('asvs').find((c) => c.id === 'V6');
    expect(v6?.shortName).toBe('Authentication');
    expect(v6?.sections.find((s) => s.id === 'V6.2')?.requirementIds).toContain('V6.2.12');
  });

  it('looks up SbD controls with their domain and severity', () => {
    expect(fw.getSbdControl('AC-02')).toMatchObject({
      domain: 'D',
      critical: true,
      severityIfNo: 'high',
    });
    expect(fw.getSbdControl('MT-02')?.severityIfNo).toBe('low');
    expect(fw.getSbdControl('XX-99')).toBeUndefined();
  });

  it('resolves scopes to requirement ids', () => {
    expect(fw.hasScope('V10')).toBe(true);
    expect(fw.hasScope('V10.4')).toBe(true);
    expect(fw.hasScope('V10.4.1')).toBe(true);
    expect(fw.hasScope('V10.9')).toBe(false);
    expect(fw.requirementIdsInScope('V4.3')).toEqual(['V4.3.1', 'V4.3.2']);
    expect(fw.requirementIdsInScope('AC.6')).toHaveLength(4);
    expect(fw.requirementIdsInScope('V6.2.1')).toEqual(['V6.2.1']);
    expect(fw.requirementIdsInScope('nope')).toEqual([]);
  });

  it('classifies ids by shape', () => {
    expect(standardForId('V6.2.1')).toBe('asvs');
    expect(standardForId('C9')).toBe('aisvs');
    expect(standardForId('AC.4.1')).toBe('aisvs-appendix-c');
    expect(standardForId('AC-01')).toBe('sbd');
    expect(standardForId('TPL-AUTH-01')).toBeUndefined();
    expect(sectionIdOf('V6.2.1')).toBe('V6.2');
    expect(sectionIdOf('AC.4.1')).toBe('AC.4');
    expect(chapterIdOf('V6.2.1')).toBe('V6');
    expect(chapterIdOf('AC.4.1')).toBe('AC.4');
    expect(chapterIdOf('C12.1')).toBe('C12');
  });
});
