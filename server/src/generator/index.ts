export {
  scaffoldApp,
  manifestFeatureFlags,
  computeProtectedFileHashes,
  tryNodeModulesFastPath,
  exportRouteManifest,
  refreshDerivedFiles,
  type ScaffoldInput,
  type ScaffoldResult,
  type FirstLoginInfo,
  type AppDesignSubset,
} from './scaffold.js';
export { expandEntities, type ExpandResult } from './expand.js';
export { buildGenerationBrief, buildFixBrief } from './brief.js';
export { initialProvenance, markGeneratedFiles, finalizeProvenance, type InitialProvenanceInput, type FinalizeProvenanceInput } from './provenance.js';
export { listFiles, sha256, sha256File, matchesAnyGlob, globToRegex, type AppFile } from './files.js';
