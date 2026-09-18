/**
 * Config scanner (CONTRACTS §4): every `config.*` check, exercised once in a fixture app where it should
 * pass and once where it should fail. `config.trust-proxy-hops` and `config.bind-loopback-default` need a
 * TLS_MODE/BIND_LAN combination the other two fixtures don't use, so they get their own small fixture.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Provenance } from '@shared/pipeline.js';
import { CONFIG_CHECKS } from '../../src/scanners/config/checks.js';
import { ALL_CONFIG_CHECKS, CONFIG_TOOL, runConfig } from '../../src/scanners/config/index.js';
import { fixtureDir, makeScanContext } from './helpers.js';

function fileHash(appDir: string, relPath: string): string {
  return createHash('sha256').update(readFileSync(join(appDir, relPath))).digest('hex');
}

function fakeProvenance(overrides: Partial<Provenance> = {}): Provenance {
  return {
    reportSchemaVersion: '1',
    tool: 'SecureVibe test',
    securevibeVersion: '0.0.0',
    templateVersion: '0.0.0',
    frameworkVersions: { asvs: '5.0.0', aisvs: '1.0.0', sbd: '0.5.0' },
    toolVersions: {},
    runId: 'test-run-1',
    projectId: 'p_test',
    generatedAt: new Date().toISOString(),
    mode: 'full',
    humanInvolvement: { summary: 'test', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
    designProfileHash: 'x',
    designHash: 'x',
    codeTreeHash: 'x',
    generatedFiles: [],
    protectedFileHashes: {},
    sandbox: { mode: 'node-permission-model', note: 'file system restricted to the project folder' },
    ...overrides,
  };
}

describe('every config.* check from CONTRACTS §4 is implemented', () => {
  it('covers exactly the 19 listed ids', () => {
    const EXPECTED = [
      'config.env-example-present',
      'config.gitignore-covers-env',
      'config.secrets-strength',
      'config.no-default-admin',
      'config.node-engine-pinned',
      'config.lockfile-present',
      'config.ignore-scripts',
      'config.no-debug-flags',
      'config.example-feature-disabled',
      'config.test-mode-not-in-env',
      'config.tls-mode-consistent',
      'config.trust-proxy-hops',
      'config.session-policy',
      'config.protected-files-unchanged',
      'config.provenance-present',
      'config.bind-loopback-default',
      'config.security-md-present',
      'config.readme-run-instructions',
      'config.package-json-unmodified',
    ];
    expect(CONFIG_CHECKS.map((c) => c.meta.id).sort()).toEqual([...EXPECTED].sort());
  });
});

describe('config-app-good: every check passes', () => {
  it('runConfig finds no failing checks', async () => {
    const appDir = fixtureDir('config-app-good');
    const ctx = makeScanContext(appDir, {
      provenance: fakeProvenance({
        protectedFileHashes: {
          'package.json': fileHash(appDir, 'package.json'),
          'src/security/headers.ts': fileHash(appDir, 'src/security/headers.ts'),
        },
      }),
    });
    const result = await runConfig(ctx);
    expect(result.findings.map((f) => f.ruleId)).toEqual([]);
    expect(result.status).toBe('passed');
    expect(result.evidence).toHaveLength(ALL_CONFIG_CHECKS.length);
    expect(result.evidence.every((e) => e.passed)).toBe(true);
    expect(result.evidence.every((e) => e.tool === CONFIG_TOOL.name && e.tier === 'medium' && e.type === 'config')).toBe(true);
  });
});

describe('config-app (bad): most checks fail with a plain-language reason', () => {
  it('runConfig reports the expected failures', async () => {
    const ctx = makeScanContext(fixtureDir('config-app')); // no provenance supplied
    const result = await runConfig(ctx);
    const failed = new Set(result.findings.map((f) => f.ruleId));

    const expectedToFail = [
      'config.env-example-present',
      'config.gitignore-covers-env',
      'config.secrets-strength',
      'config.no-default-admin',
      'config.node-engine-pinned',
      'config.lockfile-present',
      'config.ignore-scripts',
      'config.no-debug-flags',
      'config.example-feature-disabled',
      'config.test-mode-not-in-env',
      'config.tls-mode-consistent',
      'config.session-policy',
      'config.protected-files-unchanged',
      'config.provenance-present',
      'config.security-md-present',
      'config.readme-run-instructions',
      'config.package-json-unmodified',
    ];
    for (const id of expectedToFail) expect(failed.has(id), id).toBe(true);
    expect(result.status).toBe('failed');
  });
});

describe('config-app-net: trust-proxy-hops and bind-loopback-default', () => {
  it('both fail when TRUST_PROXY_HOPS is set without a proxy and BIND_LAN is on without TLS', async () => {
    const ctx = makeScanContext(fixtureDir('config-app-net'));
    const result = await runConfig(ctx);
    const failed = new Set(result.findings.map((f) => f.ruleId));
    expect(failed.has('config.trust-proxy-hops')).toBe(true);
    expect(failed.has('config.bind-loopback-default')).toBe(true);
  });

  it('both pass on the good fixture (TRUST_PROXY_HOPS=0, BIND_LAN=0)', async () => {
    const appDir = fixtureDir('config-app-good');
    const ctx = makeScanContext(appDir, {
      provenance: fakeProvenance({
        protectedFileHashes: {
          'package.json': fileHash(appDir, 'package.json'),
          'src/security/headers.ts': fileHash(appDir, 'src/security/headers.ts'),
        },
      }),
    });
    const result = await runConfig(ctx);
    const failed = new Set(result.findings.map((f) => f.ruleId));
    expect(failed.has('config.trust-proxy-hops')).toBe(false);
    expect(failed.has('config.bind-loopback-default')).toBe(false);
  });
});
