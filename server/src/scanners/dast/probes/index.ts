/**
 * Every runtime probe, in the execution order CONTRACTS §2 fixes:
 * headers → leak → errors → input → csrf → session → auth → authz → uploads → ai → redirect → xss → log → rate.
 */
import { PROBE_GROUPS, type ProbeGroup, type ProbeModule } from '../types.js';
import { aiProbes } from './ai.js';
import { authProbes } from './auth.js';
import { authzProbes } from './authz.js';
import { csrfProbes } from './csrf.js';
import { errorProbes } from './errors.js';
import { headerProbes } from './headers.js';
import { inputProbes } from './input.js';
import { leakProbes } from './leak.js';
import { logProbes } from './log.js';
import { rateProbes } from './rate.js';
import { redirectProbes } from './redirect.js';
import { sessionProbes } from './session.js';
import { uploadProbes } from './uploads.js';
import { xssProbes } from './xss.js';

const FAMILIES: ProbeModule[][] = [
  headerProbes,
  leakProbes,
  errorProbes,
  inputProbes,
  csrfProbes,
  sessionProbes,
  authProbes,
  authzProbes,
  uploadProbes,
  aiProbes,
  redirectProbes,
  xssProbes,
  logProbes,
  rateProbes,
];

const groupRank = new Map<ProbeGroup, number>(PROBE_GROUPS.map((g, i) => [g, i]));

/** All probes sorted by group order; probes keep their order inside a family. */
export const ALL_PROBES: ProbeModule[] = FAMILIES.flat().sort(
  (a, b) => (groupRank.get(a.group) ?? 99) - (groupRank.get(b.group) ?? 99),
);

export function probesForPhase(phase: ProbeModule['phase']): ProbeModule[] {
  return ALL_PROBES.filter((p) => (p.phase ?? 'test') === phase);
}

export function probeById(id: string): ProbeModule | undefined {
  return ALL_PROBES.find((p) => p.id === id);
}

export {
  aiProbes,
  authProbes,
  authzProbes,
  csrfProbes,
  errorProbes,
  headerProbes,
  inputProbes,
  leakProbes,
  logProbes,
  rateProbes,
  redirectProbes,
  sessionProbes,
  uploadProbes,
  xssProbes,
};
