/**
 * The dependency scanner: lockfile reading, `npm audit` parsing and caching, the deps.* checks from CONTRACTS §4,
 * the licence inventory and the CycloneDX bill of materials (including the fallback built from the lockfile).
 *
 * The offline path is exercised for real by pointing npm at a port nothing is listening on.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadKnowledge } from '../../src/frameworks/index.js';
import {
  buildFallbackSbom,
  collectLicenses,
  generateSbom,
  isCopyleft,
  parseAuditJson,
  parseLockfile,
  purlFor,
  readAuditCache,
  runDeps,
  summarizeLicenses,
  writeAuditCache,
  type DepsDetails,
} from '../../src/scanners/deps/index.js';
import type { ScanContext } from '../../src/scanners/types.js';
import { buildSpecFor } from './helpers/mini-app.js';

const DEPS_APP_DIR = fileURLToPath(new URL('../fixtures/scanners-runtime/deps-app/', import.meta.url));
/** A port nothing listens on: npm cannot reach a registry, which is exactly the offline case. */
const DEAD_REGISTRY = 'http://127.0.0.1:9/';

const knowledge = loadKnowledge({ warn: () => {} });

let projectDir: string;

function contextFor(appDir: string): ScanContext {
  return {
    appDir,
    projectDir,
    runId: 'run-deps-1',
    buildSpec: buildSpecFor(),
    manifest: undefined as never,
    ignore: [],
    knowledge,
    log: () => {},
    abort: new AbortController().signal,
  };
}

beforeEach(() => {
  projectDir = mkdtempSync(join(tmpdir(), 'securevibe-deps-'));
});

afterEach(() => rmSync(projectDir, { recursive: true, force: true }));

describe('package-lock.json', () => {
  const lock = parseLockfile(DEPS_APP_DIR)!;

  it('reads the packages with their versions, licences and flags', () => {
    expect(lock.rootName).toBe('securevibe-deps-fixture');
    expect(lock.lockfileVersion).toBe(3);
    expect(lock.packages.map((p) => p.name).sort()).toEqual(['copyleft-lib', 'left-pad', 'nested-helper', 'sharp-like', 'tiny-test-helper']);
    expect(lock.packages.find((p) => p.name === 'sharp-like')?.hasInstallScript).toBe(true);
    expect(lock.packages.find((p) => p.name === 'left-pad')?.deprecated).toMatch(/padStart/);
    expect(lock.packages.find((p) => p.name === 'tiny-test-helper')?.path).toBe('dev');
    expect(lock.packages.find((p) => p.name === 'nested-helper')?.chain).toEqual(['sharp-like', 'nested-helper']);
  });

  it('hashes the file so a cached audit can be matched to it', () => {
    expect(lock.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(parseLockfile(DEPS_APP_DIR)?.hash).toBe(lock.hash);
  });

  it('returns nothing when there is no lockfile', () => {
    expect(parseLockfile(projectDir)).toBeUndefined();
  });

  it('encodes scoped names in package URLs', () => {
    expect(purlFor('express', '5.2.1')).toBe('pkg:npm/express@5.2.1');
    expect(purlFor('@types/node', '22.0.0')).toBe('pkg:npm/%40types/node@22.0.0');
  });
});

describe('npm audit output', () => {
  const text = readFileSync(join(DEPS_APP_DIR, 'audit.json'), 'utf8');

  it('flattens the vulnerabilities map into one advisory per problem', () => {
    const report = parseAuditJson(text)!;
    expect(report.advisories).toHaveLength(2);
    const direct = report.advisories.find((a) => a.ids.includes('GHSA-abcd-1234-efgh'))!;
    expect(direct.package).toBe('left-pad');
    expect(direct.severity).toBe('high');
    expect(direct.cvss).toBe(7.5);
    expect(direct.fixedVersion).toBe('1.3.1');
    expect(direct.cwe).toEqual(['CWE-1333']);
    const indirect = report.advisories.find((a) => a.package === 'sharp-like')!;
    expect(indirect.title).toContain('depends on a vulnerable package');
  });

  it('maps npm severities onto the shared scale', () => {
    const moderate = parseAuditJson(JSON.stringify({ vulnerabilities: { x: { name: 'x', severity: 'moderate', via: [{ title: 'y', severity: 'moderate' }] } } }))!;
    expect(moderate.advisories[0]?.severity).toBe('medium');
  });

  it('refuses anything that is not an audit report', () => {
    expect(parseAuditJson('not json')).toBeUndefined();
    expect(parseAuditJson('{"error":{"code":"ENETUNREACH"}}')).toBeUndefined();
    expect(parseAuditJson('')).toBeUndefined();
  });

  it('keeps a result per lockfile so an offline run can reuse it with its date', () => {
    const report = parseAuditJson(text)!;
    writeAuditCache(projectDir, 'hash-1', report);
    const cached = readAuditCache(projectDir, 'hash-1');
    expect(cached?.advisories).toHaveLength(2);
    expect(cached?.fromCache).toBe(true);
    expect(cached?.vulnDbAsOf).toBe(report.vulnDbAsOf);
    expect(readAuditCache(projectDir, 'a-different-hash')).toBeUndefined();
  });
});

describe('licences', () => {
  it('recognises the licences that come with sharing obligations', () => {
    expect(isCopyleft('GPL-3.0-or-later')).toBe(true);
    expect(isCopyleft('AGPL-3.0')).toBe(true);
    expect(isCopyleft('MIT')).toBe(false);
    expect(isCopyleft('Apache-2.0')).toBe(false);
  });

  it('builds an inventory from the lockfile when nothing is installed', () => {
    const lock = parseLockfile(DEPS_APP_DIR)!;
    const entries = collectLicenses(DEPS_APP_DIR, lock.packages);
    expect(entries.map((e) => e.name)).toContain('copyleft-lib');
    expect(entries.find((e) => e.name === 'copyleft-lib')?.license).toBe('GPL-3.0-or-later');
    expect(summarizeLicenses(entries).map((s) => s.license)).toContain('MIT');
  });
});

describe('the bill of materials', () => {
  it('builds a valid CycloneDX 1.5 document from the lockfile', () => {
    const lock = parseLockfile(DEPS_APP_DIR)!;
    const sbom = buildFallbackSbom(lock, collectLicenses(DEPS_APP_DIR, lock.packages));
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
    expect(sbom.metadata.component.name).toBe('securevibe-deps-fixture');
    expect(sbom.components).toHaveLength(5);
    const left = sbom.components.find((c) => c.name === 'left-pad')!;
    expect(left.purl).toBe('pkg:npm/left-pad@1.3.0');
    expect(left['bom-ref']).toBe(left.purl);
    expect(sbom.components.find((c) => c.name === 'copyleft-lib')?.licenses?.[0]?.license.id).toBe('GPL-3.0-or-later');
    expect(sbom.dependencies?.[0]?.dependsOn).toEqual(expect.arrayContaining(['pkg:npm/left-pad@1.3.0']));
  });

  it('writes the fallback document to the run report folder', async () => {
    const result = await generateSbom({ appDir: DEPS_APP_DIR, projectDir, runId: 'run-deps-1', preferCli: false });
    expect(result.written).toBe(true);
    expect(result.generator).toBe('lockfile-fallback');
    expect(result.path).toBe(join(projectDir, 'reports', 'run-deps-1', 'sbom.cdx.json'));
    const written = JSON.parse(readFileSync(result.path!, 'utf8')) as { components: unknown[] };
    expect(written.components).toHaveLength(5);
    expect(result.note).toMatch(/package-lock\.json/);
  });

  it('uses the CycloneDX tool when the packages are installed', async () => {
    // SecureVibe's own folder is the only tree on this machine that is guaranteed to have node_modules.
    const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
    if (!existsSync(join(repoRoot, 'node_modules'))) return;
    const result = await generateSbom({ appDir: repoRoot, projectDir, runId: 'run-cdx' });
    expect(result.written).toBe(true);
    expect(result.generator).toBe('cyclonedx-npm');
    expect(result.componentCount).toBeGreaterThan(10);
    const written = JSON.parse(readFileSync(result.path!, 'utf8')) as { bomFormat: string; specVersion: string };
    expect(written.bomFormat).toBe('CycloneDX');
    expect(written.specVersion).toBe('1.5');
  }, 300_000);

  it('says so plainly when there is nothing to build a document from', async () => {
    const result = await generateSbom({ appDir: projectDir, projectDir, runId: 'run-deps-1', preferCli: false });
    expect(result.written).toBe(false);
    expect(result.note).toMatch(/no package-lock\.json/i);
  });
});

describe('runDeps against the fixture app with no reachable registry', () => {
  it('skips the vulnerability check honestly and still does everything else', async () => {
    const result = await runDeps(contextFor(DEPS_APP_DIR), { env: { npm_config_registry: DEAD_REGISTRY }, preferCli: false });
    const details = result.details as DepsDetails;

    expect(details.audit.ran).toBe(false);
    expect(result.coverage.ran).toBe(false);
    expect(result.coverage.reason).toMatch(/skipped \(offline\)/);
    expect(result.summary).toMatch(/Could not check packages/);
    // Nothing may claim "no vulnerabilities" when the check never ran.
    expect(result.findings.some((f) => f.ruleId === 'deps.vulnerability')).toBe(false);
    expect(result.evidence.some((e) => e.ref === 'deps.vulnerability')).toBe(false);
    expect(details.checks.find((c) => c.id === 'deps.vulnerability')?.passed).toBeNull();

    expect(details.lockfile.present).toBe(true);
    expect(details.lockfile.packageCount).toBe(5);
    expect(result.evidence.find((e) => e.ref === 'deps.lockfile-missing')?.passed).toBe(true);

    const installScripts = result.findings.filter((f) => f.ruleId === 'deps.install-scripts-present');
    expect(installScripts).toHaveLength(1);
    expect(installScripts[0]?.dependency?.package).toBe('sharp-like');

    const deprecated = result.findings.filter((f) => f.ruleId === 'deps.deprecated-package');
    expect(deprecated).toHaveLength(1);
    expect(deprecated[0]?.evidence).toMatch(/padStart/);

    const copyleft = result.findings.filter((f) => f.ruleId === 'deps.license-copyleft');
    expect(copyleft.map((f) => f.dependency?.package)).toEqual(['copyleft-lib']);
    expect(copyleft[0]?.severity).toBe('info');

    expect(details.sbom.written).toBe(true);
    expect(existsSync(join(projectDir, 'reports', 'run-deps-1', 'sbom.cdx.json'))).toBe(true);
    expect(result.evidence.find((e) => e.ref === 'deps.sbom-generated')?.passed).toBe(true);

    for (const finding of result.findings) {
      expect(finding.source).toBe('deps');
      expect(finding.remediation.summary.length).toBeGreaterThan(5);
    }
  }, 180_000);

  it('reuses a cached result for the same lockfile when the registry cannot be reached', async () => {
    const lock = parseLockfile(DEPS_APP_DIR)!;
    const report = parseAuditJson(readFileSync(join(DEPS_APP_DIR, 'audit.json'), 'utf8'))!;
    writeAuditCache(projectDir, lock.hash, report);

    const result = await runDeps(contextFor(DEPS_APP_DIR), { env: { npm_config_registry: DEAD_REGISTRY }, preferCli: false });
    const details = result.details as DepsDetails;
    expect(details.audit.ran).toBe(true);
    expect(details.audit.fromCache).toBe(true);
    expect(details.audit.vulnDbAsOf).toBe(report.vulnDbAsOf);
    expect(result.coverage.reason).toMatch(/advisory data reused from/);
    const vulns = result.findings.filter((f) => f.ruleId === 'deps.vulnerability');
    expect(vulns).toHaveLength(2);
    expect(vulns[0]?.dependency?.installedVersion).toBe('1.3.0');
    expect(vulns[0]?.dependency?.advisoryIds).toContain('GHSA-abcd-1234-efgh');
    expect(vulns[0]?.mappings.asvs.length).toBeGreaterThan(0);
    expect(result.status).toBe('failed');
  }, 180_000);

  it('reports a missing lockfile', async () => {
    const result = await runDeps(contextFor(projectDir), { env: { npm_config_registry: DEAD_REGISTRY }, preferCli: false });
    expect(result.findings.some((f) => f.ruleId === 'deps.lockfile-missing')).toBe(true);
    expect(result.evidence.find((e) => e.ref === 'deps.lockfile-missing')?.passed).toBe(false);
  }, 180_000);
});
