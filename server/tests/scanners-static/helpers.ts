/**
 * Shared test scaffolding for the static scanner suite: builds a minimal but type-correct ScanContext
 * against a fixture directory on disk, using the real knowledge base so remediation/ASVS lookups behave
 * exactly as they do in production.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BuildSpec } from '@shared/design.js';
import type { TemplateManifest } from '@shared/knowledge.js';
import type { Provenance } from '@shared/pipeline.js';
import { loadKnowledge } from '../../src/frameworks/knowledge.js';
import type { ScanContext } from '../../src/scanners/types.js';

export const FIXTURES_ROOT = fileURLToPath(new URL('../fixtures/scanners-static', import.meta.url));

export function fixtureDir(name: string): string {
  return join(FIXTURES_ROOT, name);
}

export function defaultBuildSpec(overrides: Partial<BuildSpec> = {}): BuildSpec {
  return {
    features: {
      auth: true,
      adminMfa: true,
      userMfa: true,
      uploads: false,
      ai: false,
      aiActions: false, aiWebSearch: false,
      aiModeration: false,
      email: false,
      scheduler: false,
      publicApi: false,
      payments: false,
      fieldEncryption: false,
      retentionJobs: false,
      lanBinding: false,
      tlsMode: 'off',
    },
    packageName: 'fixture-app',
    sessionPolicy: { idleMinutes: 30, absoluteHours: 12, maxConcurrent: 5 },
    brief: 'Fixture app for the static scanner test suite.',
    ...overrides,
  };
}

export function readManifest(appDir: string): TemplateManifest {
  return JSON.parse(readFileSync(join(appDir, 'securevibe.manifest.json'), 'utf8')) as TemplateManifest;
}

export interface MakeContextOptions {
  manifest?: TemplateManifest;
  buildSpec?: BuildSpec;
  provenance?: Provenance;
  ignore?: string[];
  runId?: string;
  projectDir?: string;
}

export function makeScanContext(appDir: string, opts: MakeContextOptions = {}): ScanContext {
  return {
    appDir,
    projectDir: opts.projectDir ?? appDir,
    runId: opts.runId ?? 'test-run-1',
    buildSpec: opts.buildSpec ?? defaultBuildSpec(),
    manifest: opts.manifest ?? readManifest(appDir),
    provenance: opts.provenance,
    ignore: opts.ignore ?? [],
    knowledge: loadKnowledge({ warn: () => {} }),
    log: () => {},
    abort: new AbortController().signal,
  };
}
