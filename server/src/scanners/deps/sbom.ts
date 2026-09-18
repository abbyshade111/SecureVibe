/**
 * The software bill of materials (CycloneDX 1.5 JSON): the list of every package the app ships, written to
 * `reports/<runId>/sbom.cdx.json`.
 *
 * First choice is `@cyclonedx/cyclonedx-npm` from SecureVibe's own node_modules (run as a child `node` process,
 * never through a shell and never via npx, so nothing is fetched). When it is missing or fails, a valid minimal
 * bill of materials is built directly from `package-lock.json` — a smaller document, clearly marked as such.
 */
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runNode } from '../../pipeline/process.js';
import { parseLockfile, purlFor, type Lockfile } from './lockfile.js';
import { collectLicenses, type LicenseEntry } from './licenses.js';

export const SBOM_TIMEOUT_MS = 120_000;
export const CYCLONEDX_SPEC_VERSION = '1.5';

/** SecureVibe's repository root, from this file's location (server/src/scanners/deps/sbom.ts). */
export const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

export function cyclonedxCli(repoRoot = REPO_ROOT): string | undefined {
  const candidates = [
    join(repoRoot, 'node_modules', '@cyclonedx', 'cyclonedx-npm', 'bin', 'cyclonedx-npm-cli.js'),
    join(repoRoot, 'server', 'node_modules', '@cyclonedx', 'cyclonedx-npm', 'bin', 'cyclonedx-npm-cli.js'),
  ];
  return candidates.find((c) => existsSync(c));
}

export interface SbomComponent {
  type: 'library';
  'bom-ref': string;
  name: string;
  version: string;
  purl: string;
  scope: 'required' | 'optional';
  licenses?: { license: { id?: string; name?: string } }[];
}

export interface Sbom {
  bomFormat: 'CycloneDX';
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { components: { type: 'application'; name: string; version: string; publisher?: string }[] };
    component: { type: 'application'; 'bom-ref': string; name: string; version: string; purl: string };
  };
  components: SbomComponent[];
  dependencies?: { ref: string; dependsOn: string[] }[];
}

function licenseBlock(license: string | undefined): SbomComponent['licenses'] {
  if (!license || license === 'UNKNOWN') return undefined;
  // SPDX expressions (with OR/AND/WITH) are not plain ids, so they go in `name`.
  return /[\s()]/.test(license) ? [{ license: { name: license } }] : [{ license: { id: license } }];
}

/** Builds a valid, minimal CycloneDX 1.5 document straight from the lockfile. */
export function buildFallbackSbom(lock: Lockfile, licenses: LicenseEntry[], toolVersion = '0.1.0'): Sbom {
  const licenseByKey = new Map(licenses.map((l) => [`${l.name}@${l.version}`, l.license]));
  const seen = new Set<string>();
  const components: SbomComponent[] = [];
  for (const pkg of lock.packages) {
    const purl = purlFor(pkg.name, pkg.version);
    if (seen.has(purl)) continue;
    seen.add(purl);
    components.push({
      type: 'library',
      'bom-ref': purl,
      name: pkg.name,
      version: pkg.version,
      purl,
      scope: pkg.optional ? 'optional' : 'required',
      licenses: licenseBlock(licenseByKey.get(`${pkg.name}@${pkg.version}`) ?? pkg.license),
    });
  }
  const rootRef = purlFor(lock.rootName, lock.rootVersion);
  return {
    bomFormat: 'CycloneDX',
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'securevibe', version: toolVersion, publisher: 'SecureVibe' }] },
      component: { type: 'application', 'bom-ref': rootRef, name: lock.rootName, version: lock.rootVersion, purl: rootRef },
    },
    components,
    dependencies: [
      { ref: rootRef, dependsOn: components.filter((c) => lock.directDependencies.includes(c.name)).map((c) => c['bom-ref']) },
      ...components.map((c) => ({ ref: c['bom-ref'], dependsOn: [] })),
    ],
  };
}

export interface SbomResult {
  written: boolean;
  path?: string;
  /** How the document was produced. */
  generator: 'cyclonedx-npm' | 'lockfile-fallback' | 'none';
  componentCount: number;
  /** Plain-language explanation when the preferred generator was not used. */
  note?: string;
}

export interface GenerateSbomOptions {
  appDir: string;
  projectDir: string;
  runId: string;
  /** Where the file goes; default `<projectDir>/reports/<runId>/sbom.cdx.json`. */
  outFile?: string;
  repoRoot?: string;
  timeoutMs?: number;
  abort?: AbortSignal;
  /** Skip the external generator (used by the fallback test). */
  preferCli?: boolean;
  log?(msg: string): void;
}

function countComponents(text: string): number {
  try {
    const parsed = JSON.parse(text) as { components?: unknown[] };
    return Array.isArray(parsed.components) ? parsed.components.length : 0;
  } catch {
    return 0;
  }
}

export async function generateSbom(opts: GenerateSbomOptions): Promise<SbomResult> {
  const log = opts.log ?? (() => {});
  const outFile = opts.outFile ?? join(opts.projectDir, 'reports', opts.runId, 'sbom.cdx.json');
  mkdirSync(dirname(outFile), { recursive: true });

  const cli = opts.preferCli === false ? undefined : cyclonedxCli(opts.repoRoot ?? REPO_ROOT);
  if (cli && existsSync(join(opts.appDir, 'node_modules'))) {
    // The positional argument is the package manifest, not a folder, and --omit is variadic so it needs "=".
    const result = await runNode(
      [cli, '--output-format', 'JSON', '--output-file', outFile, '--spec-version', CYCLONEDX_SPEC_VERSION, '--omit=dev', 'package.json'],
      {
        cwd: opts.appDir,
        projectDir: opts.projectDir,
        runId: opts.runId,
        timeoutMs: opts.timeoutMs ?? SBOM_TIMEOUT_MS,
        abort: opts.abort,
      },
    );
    if (result.code === 0 && existsSync(outFile)) {
      const count = countComponents(readFileSync(outFile, 'utf8'));
      log(`[deps] bill of materials written with cyclonedx-npm (${count} packages)`);
      return { written: true, path: outFile, generator: 'cyclonedx-npm', componentCount: count };
    }
    log(`[deps] cyclonedx-npm did not produce a document (exit ${result.code ?? 'unknown'}); using the lockfile instead`);
  }

  const lock = parseLockfile(opts.appDir);
  if (!lock) {
    return {
      written: false,
      generator: 'none',
      componentCount: 0,
      note: 'No bill of materials could be produced because the app has no package-lock.json.',
    };
  }
  const sbom = buildFallbackSbom(lock, collectLicenses(opts.appDir, lock.packages));
  writeFileSync(outFile, `${JSON.stringify(sbom, null, 2)}\n`);
  return {
    written: true,
    path: outFile,
    generator: 'lockfile-fallback',
    componentCount: sbom.components.length,
    note: cli
      ? 'The bill of materials was built from package-lock.json because the CycloneDX tool could not run (for example, packages are not installed).'
      : 'The bill of materials was built from package-lock.json because the CycloneDX tool is not installed.',
  };
}
