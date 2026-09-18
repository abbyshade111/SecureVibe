/**
 * Scanner interfaces (CONTRACTS §9.2). Every scanner — static or dynamic — takes a ScanContext and
 * returns a ScanResult; the pipeline runs them as stages and hands their findings to normalize.ts.
 */
import type { Evidence } from '@shared/compliance.js';
import type { BuildSpec } from '@shared/design.js';
import type { Finding } from '@shared/findings.js';
import type { TemplateManifest } from '@shared/knowledge.js';
import type { Provenance, ToolCoverage } from '@shared/pipeline.js';
import type { Knowledge } from '../frameworks/knowledge.js';

export type { Knowledge };

export interface ScanContext {
  /** Absolute path of the generated application (the folder that holds package.json). */
  appDir: string;
  /** Absolute path of the SecureVibe project folder (workspace/projects/<id>). */
  projectDir: string;
  runId: string;
  buildSpec: BuildSpec;
  manifest: TemplateManifest;
  /** securevibe.provenance.json of the app, when it exists (path → origin, protected file hashes). */
  provenance?: Provenance;
  /** Extra ignore patterns (gitignore-style globs, relative to appDir) on top of the built-in ones. */
  ignore: string[];
  knowledge: Knowledge;
  log(msg: string): void;
  abort: AbortSignal;
}

export type ScanStatus = 'passed' | 'failed' | 'warning' | 'skipped';

export interface ScanResult {
  findings: Finding[];
  evidence: Evidence[];
  coverage: ToolCoverage;
  details?: unknown;
  status: ScanStatus;
  /** One plain-language sentence for the progress log and the report's tool coverage table. */
  summary: string;
}

export type Scanner = (ctx: ScanContext) => Promise<ScanResult>;

/** Result of a named semantic check referenced by the template manifest (`{ type: 'ast', check, file? }`). */
export interface AstCheckResult {
  passed: boolean;
  detail: string;
  /** Set when the check did not run (the build was cancelled); it is then neither a pass nor a failure. */
  skippedReason?: string;
}
