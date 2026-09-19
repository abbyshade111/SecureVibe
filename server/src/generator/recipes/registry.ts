/**
 * The recipe library. Recipes run in this order, and the order matters: later recipes may build on what earlier
 * ones produced (a summary page needs its record types to exist first), and migration numbers are handed out in
 * the same sequence.
 *
 * Adding a recipe means adding it here. `recipes.contract.test.ts` then holds it to the library's rules — unique
 * and stable ids, paths inside the template's writable allow-list, and a requirement mapping that every claimed
 * requirement has an emitted test for.
 */
import { recordAttachmentRecipe } from './record-attachment/index.js';
import { recordTypeRecipe } from './record-type/index.js';
import type { AnyRecipe } from './types.js';

export const RECIPES: AnyRecipe[] = [recordTypeRecipe as AnyRecipe, recordAttachmentRecipe as AnyRecipe];

export function recipeById(id: string): AnyRecipe | undefined {
  return RECIPES.find((r) => r.id === id);
}
