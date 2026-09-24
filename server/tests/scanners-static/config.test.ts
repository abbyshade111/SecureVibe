/**
 * Config scanner (CONTRACTS §4): every `config.*` check, exercised once in a fixture app where it should
 * pass and once where it should fail. `config.trust-proxy-hops` and `config.bind-loopback-default` need a
 * TLS_MODE/BIND_LAN combination the other two fixtures don't use, so they get their own small fixture.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { uploadedManifest } from '../../src/api/uploads.js';
import { describe, expect, it } from 'vitest';
import type { Provenance } from '@shared/pipeline.js';
import { CONFIG_CHECKS } from '../../src/scanners/config/checks.js';
import { ALL_CONFIG_CHECKS, CONFIG_TOOL, runConfig } from '../../src/scanners/config/index.js';
import { fixtureDir, makeScanContext } from './helpers.js';

/** The manifest of an app SecureVibe built: the fixture's own, which is the template's shape. */
function readManifestForBuiltApp() {
  return makeScanContext(fixtureDir('config-app-good')).manifest;
}

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

describe('the provenance file is never checked against a hash stored inside itself', () => {
  it('reports nothing when the only "mismatch" is the record of the hashes', async () => {
    // An owner saw two high findings — "protected files differ from the template" and "protected security file
    // was changed" — on an app whose other 105 protected files all matched. The odd one out was
    // securevibe.provenance.json, which cannot match: writing its own hash into it changes it, so the recorded
    // value is wrong the moment it is written. Any value here is wrong, which is the point of the test.
    const appDir = fixtureDir('config-app-good');
    const ctx = makeScanContext(appDir, {
      provenance: fakeProvenance({
        protectedFileHashes: {
          'package.json': fileHash(appDir, 'package.json'),
          'securevibe.provenance.json': 'f'.repeat(64),
        },
      }),
    });
    const result = await runConfig(ctx);
    expect(result.findings.map((f) => f.ruleId)).not.toContain('config.protected-files-unchanged');
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

describe('an app SecureVibe did not build is not measured against its own conventions (ADR-012)', () => {
  function pythonApp(readme: string | undefined): string {
    const dir = mkdtempSync(join(tmpdir(), 'sv-flask-'));
    writeFileSync(join(dir, 'app.py'), 'from flask import Flask\napp = Flask(__name__)\n');
    writeFileSync(join(dir, 'requirements.txt'), 'flask==3.0.0\n');
    if (readme !== undefined) writeFileSync(join(dir, 'README.md'), readme);
    return dir;
  }
  const uploaded = (appDir: string) => makeScanContext(appDir, { manifest: uploadedManifest() });

  it('does not ask npm questions of a Python app, and does not fail it for lacking our documents', async () => {
    const result = await runConfig(uploaded(pythonApp('# Notes\n\n## Running\n\n    pip install -r requirements.txt\n    flask run\n')));
    const failed = result.findings.map((f) => f.ruleId);
    // The three classes the Flask re-run on 20 September 2026 still showed firing.
    expect(failed).not.toContain('config.node-engine-pinned');
    expect(failed).not.toContain('config.readme-run-instructions');
    expect(failed.filter((id) => id.startsWith('docs.'))).toEqual([]);
    expect(failed).not.toContain('config.lockfile-present');
    expect(failed).not.toContain('config.ignore-scripts');
    const notApplicable = (result.details as { notApplicable: string[] }).notApplicable;
    expect(notApplicable).toEqual(expect.arrayContaining(['config.node-engine-pinned', 'config.lockfile-present', 'config.ignore-scripts']));
    expect(notApplicable.filter((id) => id.startsWith('docs.'))).toHaveLength(7);
    // No evidence either: a document that could not be looked for verifies nothing.
    expect(result.evidence.some((e) => e.ref.startsWith('docs.'))).toBe(false);
    // The summary says why, in two groups, rather than calling everything "about npm".
    expect(result.summary).toMatch(/3 because they are about npm/);
    expect(result.summary).toMatch(/7 because they look for the documents SecureVibe writes/);
  });

  it('still asks whether the README says how to run the app, in that app\'s own terms', async () => {
    const ok = await runConfig(uploaded(pythonApp('Start it with `gunicorn app:app`.')));
    expect(ok.findings.map((f) => f.ruleId)).not.toContain('config.readme-run-instructions');
    expect(ok.evidence.find((e) => e.ref === 'config.readme-run-instructions')?.summary).toMatch(/says how to set up and run/);

    const silent = await runConfig(uploaded(pythonApp('A small app. Enjoy.')));
    const finding = silent.findings.find((f) => f.ruleId === 'config.readme-run-instructions');
    expect(finding).toBeDefined();
    // What it says about this app names no npm command; the remediation steps say which apps npm applies to.
    expect(finding!.evidence).not.toContain('npm');
    expect(finding!.description).not.toContain('npm');

    const missing = await runConfig(uploaded(pythonApp(undefined)));
    expect(missing.findings.find((f) => f.ruleId === 'config.readme-run-instructions')?.evidence).toMatch(/missing or empty/);
  });

  it('keeps the strict template question for an app SecureVibe built', async () => {
    const dir = pythonApp('## Getting started\n\nnpm install\nnpm start\n');
    writeFileSync(join(dir, 'package.json'), '{}');
    // Built apps are read with the template manifest; the README must name the setup step that makes the secrets.
    const result = await runConfig(makeScanContext(dir, { manifest: readManifestForBuiltApp() }));
    expect(result.findings.find((f) => f.ruleId === 'config.readme-run-instructions')?.evidence).toMatch(/npm run setup/);
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
