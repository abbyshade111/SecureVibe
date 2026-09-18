/**
 * SbD step 3: select patterns from data/knowledge/patterns.json whose `when` condition matches the profile.
 * The catalog order is preserved so the output is deterministic.
 */
import type { Pattern } from '@shared/design.js';
import type { PatternCatalogEntry } from '@shared/knowledge.js';
import type { DesignProfile } from '@shared/profile.js';
import { COMPONENT_IDS, FLOW_IDS, externalApiComponentId, externalApiFlowId } from './architecture.js';
import { matchesPatternWhen, type PatternWhen, type ProfileFacts } from './conditions.js';

export function selectPatterns(profile: DesignProfile, f: ProfileFacts, catalog: PatternCatalogEntry[]): Pattern[] {
  const patterns: Pattern[] = [];
  for (const entry of catalog) {
    if (!matchesPatternWhen(entry.when, f)) continue;
    patterns.push({
      id: entry.id,
      name: entry.name,
      principle: entry.principle,
      sbdDomain: entry.sbdDomain,
      why: fillTemplate(entry.whyTemplate, profile),
      appliesTo: appliesTo(entry.when, profile, f),
      implementedBy: [...entry.implementedBy],
      sbdChecklist: [...entry.sbdChecklist],
    });
  }
  return patterns;
}

export function fillTemplate(template: string, profile: DesignProfile): string {
  return template
    .replaceAll('{appName}', profile.app.name)
    .replaceAll('{ownerName}', profile.deployment.owner.name)
    .replaceAll('{ownerEmail}', profile.deployment.owner.contactEmail);
}

function appliesTo(when: PatternWhen, profile: DesignProfile, f: ProfileFacts): string[] {
  switch (when) {
    case 'always':
    case 'level2':
      return [COMPONENT_IDS.app];
    case 'auth':
    case 'internet':
    case 'lan':
      return [COMPONENT_IDS.app, FLOW_IDS.browserToApp];
    case 'sensitive-data':
    case 'personal-data':
      return [COMPONENT_IDS.db, FLOW_IDS.appToDb];
    case 'uploads':
      return [COMPONENT_IDS.files, FLOW_IDS.appToFiles];
    case 'ai':
    case 'ai-actions':
      return [COMPONENT_IDS.ai, FLOW_IDS.appToAi];
    case 'email':
      return [COMPONENT_IDS.email, FLOW_IDS.appToEmail];
    case 'external-apis':
      return [
        ...profile.capabilities.externalApis.flatMap((_, i) => [externalApiComponentId(i), externalApiFlowId(i)]),
        ...(f.ai ? [COMPONENT_IDS.ai, FLOW_IDS.appToAi] : []),
        ...(f.email ? [COMPONENT_IDS.email, FLOW_IDS.appToEmail] : []),
      ];
    case 'public-api':
      return [COMPONENT_IDS.apiClient, FLOW_IDS.apiClientToApp];
    case 'payments':
      return [COMPONENT_IDS.payments, FLOW_IDS.appToPayments];
    case 'scheduler':
      return [COMPONENT_IDS.scheduler, FLOW_IDS.schedulerToDb];
  }
}
