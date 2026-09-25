/**
 * Every SAST rule from CONTRACTS §3, in one ordered list.
 */
import type { SastRule } from '../engine.js';
import { aiRules } from './ai.js';
import { codeExecutionRules } from './code-execution.js';
import { cryptoRules } from './crypto.js';
import { databaseRules } from './database.js';
import { domRules } from './dom.js';
import { expressRules } from './express.js';
import { inputRules } from './input.js';
import { loggingRules } from './logging.js';
import { networkRules } from './network.js';
import { projectRules } from './project.js';
import { viewRules } from './views.js';
import { workingStateRules } from './working-state.js';

export const ALL_RULES: SastRule[] = [
  ...codeExecutionRules,
  ...databaseRules,
  ...viewRules,
  ...domRules,
  ...cryptoRules,
  ...networkRules,
  ...expressRules,
  ...inputRules,
  ...loggingRules,
  ...aiRules,
  ...projectRules,
  ...workingStateRules,
];

export const RULE_IDS: string[] = ALL_RULES.map((r) => r.id);

export function ruleById(id: string): SastRule | undefined {
  return ALL_RULES.find((r) => r.id === id);
}

export { directRouteCalls } from './express.js';
export { isDbHelperCall, sqlStringConcat, dbRawOutsideWrapper } from './database.js';
export { weakHashSecurityContext, cryptoCreateCipher } from './crypto.js';
export { isImportAllowed, packageNameOf } from './project.js';
