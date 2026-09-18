/** provenance.json: the run's provenance metadata, verbatim (AISVS Appendix C AC.7.1 / AC.10.1). */
import type { Provenance } from '@shared/pipeline.js';

export function renderProvenanceJson(provenance: Provenance): string {
  return JSON.stringify(provenance, null, 2);
}
