/**
 * Small builders for compliance-engine tests: a BuildSpec, a ManifestCheckContext and an EvaluateInput with
 * sensible empty defaults that a test overrides piece by piece.
 */
import { fileURLToPath } from 'node:url';
import type { BuildSpec } from '@shared/design.js';
import type { AstCheckResult } from '../../../src/scanners/types.js';
import type { ConfigCheckResult, DocsRegenerateResult, ManifestCheckContext, TestResult } from '../../../src/compliance/types.js';

export const FIXTURE_APP_DIR = fileURLToPath(new URL('./app', import.meta.url));

export function buildSpecFixture(overrides: Partial<BuildSpec['features']> = {}): BuildSpec {
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
      ...overrides,
    },
    packageName: 'fixture-app',
    sessionPolicy: { idleMinutes: 30, absoluteHours: 12, maxConcurrent: 5 },
    brief: 'Fixture generation brief.',
  };
}

export interface ManifestContextOptions {
  appDir?: string;
  buildSpec?: BuildSpec;
  testResults?: TestResult[];
  probeResults?: ManifestCheckContext['probeResults'];
  configResults?: ConfigCheckResult[];
  sastFindings?: ManifestCheckContext['sastFindings'];
  astResults?: Record<string, AstCheckResult>;
  docsMatch?: Record<string, boolean>;
}

/** A ManifestCheckContext whose file-backed checks (file-exists/file-contains) read the fixture app under ./app by default. */
export function makeManifestCheckContext(opts: ManifestContextOptions = {}): ManifestCheckContext {
  return {
    appDir: opts.appDir ?? FIXTURE_APP_DIR,
    buildSpec: opts.buildSpec ?? buildSpecFixture(),
    testResults: opts.testResults ?? [],
    probeResults: opts.probeResults ?? [],
    configResults: opts.configResults ?? [],
    sastFindings: opts.sastFindings ?? [],
    astCheck: (name: string): AstCheckResult => opts.astResults?.[name] ?? { passed: false, detail: `no fixture result for ast check "${name}"` },
    docsRegenerate: (file: string): DocsRegenerateResult => ({ matches: opts.docsMatch?.[file] ?? false, detail: opts.docsMatch?.[file] ? `${file} matches` : `${file} does not match` }),
    runId: 'run_fixture',
    capturedAt: '2026-09-16T10:00:00.000Z',
  };
}
