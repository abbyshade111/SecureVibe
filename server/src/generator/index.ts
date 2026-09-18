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
export { applyRecipes, type ApplyRecipesInput, type ApplyRecipesResult } from './recipes/apply.js';
export { RECIPES, recipeById } from './recipes/registry.js';
export type { AnyRecipe, Recipe, RecipeContext, RecipeEmission, RecipeRequirement, RecipeRoute } from './recipes/types.js';
export { buildGenerationBrief, buildFixBrief } from './brief.js';
export { initialProvenance, markGeneratedFiles, recordRecipes, finalizeProvenance, type InitialProvenanceInput, type FinalizeProvenanceInput } from './provenance.js';
export { listFiles, sha256, sha256File, contentSha256File, matchesAnyGlob, globToRegex, type AppFile } from './files.js';
