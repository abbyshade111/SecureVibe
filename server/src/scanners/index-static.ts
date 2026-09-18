/**
 * Entry point for the static half of the scanner suite (CONTRACTS §9.2): the four Scanners that only
 * read the generated app's source tree (no running process), plus the named AST checks the template
 * manifest references. The dynamic half (`dast`) and `deps`/`tests`/`external` live in their own modules.
 */
export { runConfig, CONFIG_TOOL } from './config/index.js';
export { runLint, LINT_TOOL } from './lint/index.js';
export { runSecrets, SECRETS_TOOL } from './secrets/index.js';
export { ALL_RULES, buildScanTree, runRulesOnTree, runSast, RULE_IDS, ruleById } from './sast/index.js';
export { AST_CHECK_NAMES, isAstCheckName, runAstCheck, type AstCheckName } from './ast-checks.js';
export { finalizeFindings, type FinalizeOptions } from './normalize.js';
export type { AstCheckResult, Knowledge, ScanContext, ScanResult, Scanner, ScanStatus } from './types.js';
