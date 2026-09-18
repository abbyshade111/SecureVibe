/**
 * Writes one accepted follow-up answer or suggested feature into the owner's answers.
 *
 * Only the fields on the refine allow-list can be reached (see llm/flows/refine.ts), and the two "add" fields only
 * ever append: a suggestion can add a feature or a record type, never rewrite or remove what the owner wrote.
 */
import type { PartialDesignProfile } from '@shared/profile.js';

const MAX_FEATURES = 30;
const MAX_ENTITIES = 12;

/** "Visit note" → "visit-note", the name shape the design uses for a record type. */
export function entityName(label: string): string {
  const name = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return name === '' ? 'record' : name;
}

function boolOf(value: string): boolean | undefined {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

export function applyRefinement(profile: PartialDesignProfile, field: string, value: string): PartialDesignProfile {
  const next: PartialDesignProfile = structuredClone(profile);
  const app = (next.app ??= {});
  const users = (next.users ??= {});
  const data = (next.data ??= {});
  const caps = (next.capabilities ??= {});
  const trimmed = value.trim();

  switch (field) {
    case 'app.description':
      app.description = trimmed.slice(0, 2000);
      break;
    case 'app.keyFeatures.add': {
      const features = (app.keyFeatures ??= []);
      const exists = features.some((f) => f.trim().toLowerCase() === trimmed.toLowerCase());
      if (!exists && features.length < MAX_FEATURES && trimmed !== '') features.push(trimmed.slice(0, 200));
      break;
    }
    case 'app.entities.add': {
      const entities = (app.entities ??= []);
      const name = entityName(trimmed);
      const exists = entities.some((e) => e?.name === name || e?.label?.trim().toLowerCase() === trimmed.toLowerCase());
      if (!exists && entities.length < MAX_ENTITIES && trimmed !== '') {
        // Fields are left for the owner (or the generator) to fill in; the record itself is what was accepted.
        entities.push({ name, label: trimmed.slice(0, 60), description: '', access: 'all-signed-in', fields: [] });
      }
      break;
    }
    case 'users.audience':
      users.audience = trimmed as NonNullable<PartialDesignProfile['users']>['audience'];
      break;
    case 'users.requiresSignIn':
      users.requiresSignIn = boolOf(trimmed) ?? users.requiresSignIn;
      break;
    case 'data.aboutOtherPeople':
      data.aboutOtherPeople = boolOf(trimmed) ?? data.aboutOtherPeople;
      break;
    case 'data.retention':
      data.retention = trimmed as NonNullable<PartialDesignProfile['data']>['retention'];
      break;
    case 'capabilities.fileUploads':
      caps.fileUploads = boolOf(trimmed) ?? caps.fileUploads;
      break;
    case 'capabilities.email':
      caps.email = boolOf(trimmed) ?? caps.email;
      break;
    case 'capabilities.scheduledJobs':
      caps.scheduledJobs = boolOf(trimmed) ?? caps.scheduledJobs;
      break;
    case 'capabilities.publicApi':
      caps.publicApi = boolOf(trimmed) ?? caps.publicApi;
      break;
    case 'capabilities.payments':
      caps.payments = boolOf(trimmed) ?? caps.payments;
      break;
    case 'capabilities.aiAssistant.enabled':
    case 'capabilities.aiAssistant.canSearchWeb':
    case 'capabilities.aiAssistant.storesHistory': {
      const on = boolOf(trimmed);
      if (on === undefined) break;
      const ai = { ...(caps.aiAssistant ?? {}) } as NonNullable<NonNullable<PartialDesignProfile['capabilities']>['aiAssistant']>;
      if (field.endsWith('enabled')) ai.enabled = on;
      else if (field.endsWith('canSearchWeb')) ai.canSearchWeb = on;
      else ai.storesHistory = on;
      caps.aiAssistant = ai;
      break;
    }
    default:
      // Not on the allow-list: the answers are left exactly as they were.
      break;
  }
  return next;
}
