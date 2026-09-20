/**
 * The `deps` stage (CONTRACTS §4): what third-party code the app ships, whether any of it has a known
 * vulnerability, whether the set is pinned, and a bill of materials.
 *
 * Everything here degrades honestly. `npm audit` needs the network; when it cannot reach the advisory service the
 * result for the same lockfile is reused from the cache (with the date it was fetched) and, failing that, the
 * coverage row says "skipped: offline" instead of implying that nothing was found.
 */
import { createHash } from 'node:crypto';
import { detectEcosystems, usesNpm } from '../ecosystems.js';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import type { Finding, Severity } from '@shared/findings.js';
import type { RemediationEntry } from '@shared/knowledge.js';
import type { ToolCoverage } from '@shared/pipeline.js';
import { runNpm } from '../../pipeline/process.js';
import type { ScanContext, ScanResult, ScanStatus } from '../types.js';
import { runAudit, type Advisory, type AuditReport } from './audit.js';
import { collectLicenses, isCopyleft, summarizeLicenses, type LicenseEntry } from './licenses.js';
import { parseLockfile, type Lockfile, type LockedPackage } from './lockfile.js';
import { generateSbom, type SbomResult } from './sbom.js';

export * from './audit.js';
export * from './lockfile.js';
export * from './licenses.js';
export * from './sbom.js';

export const DEPS_COVERS =
  'Checks every third-party package your app uses for publicly known security problems, and lists them all in a bill of materials.';
export const RERUN_COMMAND = 'npm audit';

/** Built-in wording used when data/knowledge/remediation.json has no entry for the check. */
interface DepsRuleFallback {
  title: string;
  severity: Severity;
  cwe: string[];
  description: string;
  impact: string;
  fix: string;
  steps: string[];
}

const FALLBACKS: Record<string, DepsRuleFallback> = {
  'deps.vulnerability': {
    title: 'A package your app uses has a known security problem',
    severity: 'high',
    cwe: ['CWE-1395'],
    description: 'One of the third-party packages your app installs has a publicly published security problem.',
    impact: 'Published problems are the easiest kind to exploit, because the attack is already written down.',
    fix: 'Update the package to a fixed version.',
    steps: ['Open a terminal in your app folder.', 'Run `npm audit fix`.', 'Run `npm test` to check nothing broke.'],
  },
  'deps.lockfile-missing': {
    title: 'No package-lock.json: the exact package versions are not pinned',
    severity: 'medium',
    cwe: ['CWE-1104'],
    description: 'Your app has no package-lock.json, so a future install can pull different versions of its packages than the ones that were checked.',
    impact: 'Your app could silently start using code that was never reviewed or tested here.',
    fix: 'Run `npm install` once and keep the package-lock.json file it creates.',
    steps: ['Open a terminal in your app folder.', 'Run `npm install`.', 'Keep package-lock.json alongside package.json.'],
  },
  'deps.unpinned-versions': {
    title: 'The exact versions of your packages are not written down',
    severity: 'medium',
    cwe: ['CWE-1104'],
    description:
      'This app lists the packages it needs but not the exact versions, so what actually gets installed can differ from what was checked here.',
    impact:
      'Nobody can say which code your app is running, so a known problem in a package cannot be looked up, and an install tomorrow can bring in code nobody has seen.',
    fix: 'Write the exact versions down in the file your package manager uses for it, and keep that file with the app.',
    steps: [
      'Ask your package manager to record exact versions (for example a lock file).',
      'Keep that file alongside the app, and update it deliberately rather than by accident.',
    ],
  },
  'deps.install-scripts-present': {
    title: 'A package runs its own script at install time',
    severity: 'low',
    cwe: ['CWE-829'],
    description: 'One of the installed packages asks npm to run a script of its own during installation.',
    impact: 'Install scripts are a common way for a tampered package to run code on your computer.',
    fix: 'Keep `ignore-scripts=true` in .npmrc so install scripts never run.',
    steps: ['Check that .npmrc in your app folder contains `ignore-scripts=true`.', 'Install with `npm ci --ignore-scripts`.'],
  },
  'deps.deprecated-package': {
    title: 'A package your app uses is no longer maintained',
    severity: 'low',
    cwe: ['CWE-1104'],
    description: 'The package author has marked this package as deprecated, which usually means it will not get security fixes.',
    impact: 'Problems found in an abandoned package may never be fixed.',
    fix: 'Replace the package with the maintained alternative the deprecation note names.',
    steps: ['Read the deprecation message shown with this finding.', 'Move to the suggested replacement.'],
  },
  'deps.license-copyleft': {
    title: 'A package comes with sharing obligations',
    severity: 'info',
    cwe: [],
    description: 'This package is published under a licence that asks you to share your own source code if you distribute the app.',
    impact: 'This is a legal consideration, not a security problem. It matters only if you give the app to other people.',
    fix: 'If you plan to distribute the app, check the licence with whoever advises you on contracts.',
    steps: ['Note the package and licence.', 'If the app stays on your own machines, no action is needed.'],
  },
  'deps.sbom-generated': {
    title: 'No bill of materials could be produced',
    severity: 'low',
    cwe: ['CWE-1059'],
    description: 'SecureVibe could not write the list of every package your app ships (the bill of materials).',
    impact: 'Without that list it is harder to answer "does my app include the package that was just found vulnerable?".',
    fix: 'Install the app\'s packages (`npm install`) and run verification again.',
    steps: ['Open a terminal in your app folder.', 'Run `npm install`.', 'Run verification again.'],
  },
};

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

let findingCounter = 0;
let evidenceCounter = 0;

function known(ctx: ScanContext, ruleId: string): RemediationEntry | undefined {
  return ctx.knowledge?.remediation?.[ruleId];
}

interface DepsFindingInput {
  ruleId: string;
  key: string;
  evidence: string;
  severity?: Severity;
  title?: string;
  description?: string;
  file?: string;
  dependency?: Finding['dependency'];
  cwe?: string[];
  cvss?: number;
}

function buildDepsFinding(ctx: ScanContext, input: DepsFindingInput): Finding {
  const fallback = FALLBACKS[input.ruleId];
  const entry = known(ctx, input.ruleId);
  const severity = input.severity ?? entry?.severity ?? fallback?.severity ?? 'medium';
  findingCounter += 1;
  return {
    id: `deps-${String(findingCounter).padStart(4, '0')}`,
    fingerprint: sha256(`deps|${input.ruleId}|${input.file ?? ''}|${input.key}`),
    source: 'deps',
    sourcesReporting: ['deps'],
    ruleId: input.ruleId,
    title: input.title ?? entry?.title ?? fallback?.title ?? input.ruleId,
    severity,
    severityBase: severity,
    priority: 'P3',
    exploitability: entry?.exploitability ?? 'requires-network-exposure',
    confidence: 'high',
    cwe: [...new Set([...(input.cwe ?? []), ...(entry?.cwe ?? fallback?.cwe ?? [])])],
    location: input.file ? { file: input.file } : undefined,
    description: input.description ?? entry?.description ?? fallback?.description ?? '',
    impact: entry?.impact ?? fallback?.impact ?? '',
    evidence: input.evidence,
    remediation: entry
      ? { summary: entry.remediation.summary, steps: entry.remediation.steps, example: entry.remediation.example, references: entry.remediation.references }
      : { summary: fallback?.fix ?? '', steps: fallback?.steps ?? [], references: [] },
    verification: {
      howToConfirmFixed: entry?.howToConfirmFixed ?? 'Run verification again; this package no longer appears in the list.',
      rerunCommand: RERUN_COMMAND,
    },
    mappings: { asvs: entry?.asvs ?? [], aisvs: entry?.aisvs ?? [], sbd: entry?.sbd ?? [] },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'dependency',
    dependency: input.dependency,
    tool: { name: 'npm' },
  };
}

function buildEvidence(input: { ref: string; summary: string; passed: boolean; runId?: string }): Evidence {
  evidenceCounter += 1;
  return {
    id: `E-deps-${String(evidenceCounter).padStart(4, '0')}`,
    type: 'scanner',
    tier: 'medium',
    ref: input.ref,
    summary: input.summary,
    passed: input.passed,
    tool: 'npm',
    runId: input.runId,
    capturedAt: new Date().toISOString(),
    producedBy: 'securevibe-deps',
  };
}

function versionOf(locked: LockedPackage[], name: string): string {
  return locked.find((p) => p.name === name)?.version ?? 'unknown';
}

function pathOf(locked: LockedPackage[], name: string): 'direct' | 'transitive' | 'dev' {
  return locked.find((p) => p.name === name)?.path ?? 'transitive';
}

function advisoryFinding(ctx: ScanContext, advisory: Advisory, lock: Lockfile | undefined): Finding {
  const locked = lock?.packages ?? [];
  const installed = versionOf(locked, advisory.package);
  const chain = locked.find((p) => p.name === advisory.package)?.chain ?? [];
  const fixText = advisory.fixedVersion
    ? `A fixed version is available: ${advisory.fixedVersion}${advisory.fixIsMajor ? ' (a major update — test your app after)' : ''}.`
    : 'npm does not know of a fixed version yet.';
  return buildDepsFinding(ctx, {
    ruleId: 'deps.vulnerability',
    key: `${advisory.package}|${advisory.ids.join(',') || advisory.title}`,
    severity: advisory.severity,
    title: `${advisory.package}: ${advisory.title}`,
    description: `The package "${advisory.package}" (version ${installed}) has a published security problem: ${advisory.title}. ${fixText}`,
    evidence: `npm audit reported ${advisory.ids.join(', ') || advisory.title} for ${advisory.package}${advisory.vulnerableRange ? ` (affected versions ${advisory.vulnerableRange})` : ''}.`,
    file: 'package-lock.json',
    cwe: advisory.cwe,
    dependency: {
      package: advisory.package,
      installedVersion: installed,
      fixedVersion: advisory.fixedVersion,
      advisoryIds: advisory.ids,
      path: advisory.isDirect ? pathOf(locked, advisory.package) : pathOf(locked, advisory.package),
      chain,
      cvss: advisory.cvss,
    },
  });
}

export interface DepsDetails {
  lockfile: { present: boolean; lockfileVersion?: number; packageCount: number; hash?: string };
  audit: { ran: boolean; reason?: string; vulnDbAsOf?: string; fromCache: boolean; counts: Record<string, number> };
  advisories: Advisory[];
  installScripts: { name: string; version: string }[];
  deprecated: { name: string; version: string; message: string }[];
  licenses: { entries: LicenseEntry[]; summary: { license: string; count: number }[]; copyleft: LicenseEntry[] };
  sbom: SbomResult;
  npmVersion?: string;
  checks: { id: string; passed: boolean | null; detail: string }[];
}

export interface RunDepsOptions {
  /** Extra environment for npm (the offline test points npm_config_registry at a dead port). */
  env?: Record<string, string>;
  /** Skip the CycloneDX CLI and build the bill of materials from the lockfile. */
  preferCli?: boolean;
  auditTimeoutMs?: number;
  sbomOutFile?: string;
}

async function npmVersion(ctx: ScanContext): Promise<string | undefined> {
  try {
    const result = await runNpm(['--version'], { cwd: ctx.appDir, projectDir: ctx.projectDir, runId: ctx.runId, timeoutMs: 20_000 });
    const version = result.stdout.trim().split('\n').pop();
    return version && /^\d/.test(version) ? version : undefined;
  } catch {
    return undefined;
  }
}

/** True when .npmrc switches install scripts off, which is what makes an install script harmless. */
function ignoreScriptsConfigured(appDir: string): boolean {
  const file = join(appDir, '.npmrc');
  if (!existsSync(file)) return false;
  try {
    return /^\s*ignore-scripts\s*=\s*true\s*$/m.test(readFileSync(file, 'utf8'));
  } catch {
    return false;
  }
}

function statusFor(findings: Finding[], auditRan: boolean): ScanStatus {
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 'failed';
  if (!auditRan) return 'warning';
  if (findings.length > 0) return 'warning';
  return 'passed';
}

export async function runDeps(ctx: ScanContext, opts: RunDepsOptions = {}): Promise<ScanResult> {
  const findings: Finding[] = [];
  const evidence: Evidence[] = [];
  const checks: DepsDetails['checks'] = [];
  const lock = parseLockfile(ctx.appDir);

  /**
   * Everything below this point is about npm. An app that does not use npm is not missing a
   * package-lock.json; it is a different kind of app, and saying otherwise puts a false sentence in a report
   * (ADR-012). What such an app does get is the question underneath, asked in its own terms: are the versions
   * of its packages written down anywhere?
   */
  if (!usesNpm(ctx.appDir)) {
    const ecosystems = detectEcosystems(ctx.appDir);
    const unpinned = ecosystems.filter((e) => e.lockfile === undefined);
    for (const eco of unpinned) {
      findings.push(
        buildDepsFinding(ctx, {
          ruleId: 'deps.unpinned-versions',
          key: eco.manifest,
          file: eco.manifest,
          evidence: `${eco.manifest} lists this app's ${eco.name} packages, and no file next to it records the exact versions that were installed.`,
        }),
      );
    }
    const named = ecosystems.map((e) => e.name).join(', ');
    return {
      findings,
      evidence,
      coverage: {
        tool: 'deps',
        ran: false,
        reason:
          ecosystems.length === 0
            ? 'skipped: this app does not list its packages in a file SecureVibe recognises, so they could not be checked'
            : `skipped: SecureVibe's own package check only reads npm, and this app uses ${named}. Its packages were checked by the optional scanners instead, when they are installed.`,
        covers: 'Known problems in the packages an app installs, and whether their versions are pinned.',
      },
      status: findings.length > 0 ? 'warning' : 'skipped',
      summary:
        ecosystems.length === 0
          ? 'No package list was found that SecureVibe knows how to read, so its packages were not checked here.'
          : `This app uses ${named} rather than npm, so SecureVibe's own package check did not run.${unpinned.length > 0 ? ` ${unpinned.length} of its package lists do not record exact versions.` : ''}`,
      details: { checks, notApplicable: ['npm'] },
    };
  }

  // deps.lockfile-missing ------------------------------------------------------------------------
  if (!lock) {
    findings.push(
      buildDepsFinding(ctx, {
        ruleId: 'deps.lockfile-missing',
        key: 'package-lock.json',
        file: 'package.json',
        evidence: 'No package-lock.json was found next to package.json.',
      }),
    );
    checks.push({ id: 'deps.lockfile-missing', passed: false, detail: 'package-lock.json is missing' });
    evidence.push(buildEvidence({ ref: 'deps.lockfile-missing', summary: 'Your app does not pin its package versions (no package-lock.json).', passed: false, runId: ctx.runId }));
  } else {
    checks.push({ id: 'deps.lockfile-missing', passed: true, detail: `package-lock.json v${lock.lockfileVersion} with ${lock.packages.length} packages` });
    evidence.push(
      buildEvidence({
        ref: 'deps.lockfile-missing',
        summary: `Your app pins the exact version of all ${lock.packages.length} packages it uses (package-lock.json).`,
        passed: true,
        runId: ctx.runId,
      }),
    );
  }

  // deps.vulnerability ---------------------------------------------------------------------------
  const audit = await runAudit({
    appDir: ctx.appDir,
    projectDir: ctx.projectDir,
    runId: ctx.runId,
    lockfileHash: lock?.hash,
    abort: ctx.abort,
    env: opts.env,
    timeoutMs: opts.auditTimeoutMs,
    log: ctx.log,
  });

  let report: AuditReport | undefined;
  let auditReason: string | undefined;
  if (audit.ok) {
    report = audit.report;
    for (const advisory of report.advisories) findings.push(advisoryFinding(ctx, advisory, lock));
    checks.push({
      id: 'deps.vulnerability',
      passed: report.advisories.length === 0,
      detail: `${report.advisories.length} advisories (data as of ${report.vulnDbAsOf}${report.fromCache ? ', from cache' : ''})`,
    });
    evidence.push(
      buildEvidence({
        ref: 'deps.vulnerability',
        summary:
          report.advisories.length === 0
            ? `No package your app uses has a known security problem (checked against advisory data from ${report.vulnDbAsOf.slice(0, 10)}).`
            : `${report.advisories.length} packages your app uses have known security problems (advisory data from ${report.vulnDbAsOf.slice(0, 10)}).`,
        passed: report.advisories.length === 0,
        runId: ctx.runId,
      }),
    );
  } else {
    auditReason = audit.reason;
    checks.push({ id: 'deps.vulnerability', passed: null, detail: audit.reason });
    ctx.log(`[deps] ${audit.reason}`);
  }

  // deps.install-scripts-present -----------------------------------------------------------------
  const installScripts = (lock?.packages ?? []).filter((p) => p.hasInstallScript).map((p) => ({ name: p.name, version: p.version }));
  const ignoreScripts = ignoreScriptsConfigured(ctx.appDir);
  if (lock) {
    if (installScripts.length > 0) {
      for (const pkg of installScripts) {
        findings.push(
          buildDepsFinding(ctx, {
            ruleId: 'deps.install-scripts-present',
            key: `${pkg.name}@${pkg.version}`,
            file: 'package-lock.json',
            evidence: `package-lock.json marks ${pkg.name}@${pkg.version} with "hasInstallScript": true.${ignoreScripts ? ' Your app installs with install scripts switched off (.npmrc has ignore-scripts=true), which keeps this safe.' : ''}`,
            severity: ignoreScripts ? 'info' : undefined,
            dependency: { package: pkg.name, installedVersion: pkg.version, advisoryIds: [], path: pathOf(lock.packages, pkg.name), chain: [] },
          }),
        );
      }
    }
    checks.push({
      id: 'deps.install-scripts-present',
      passed: installScripts.length === 0 || ignoreScripts,
      detail: `${installScripts.length} packages with install scripts; ignore-scripts=${ignoreScripts}`,
    });
    evidence.push(
      buildEvidence({
        ref: 'deps.install-scripts-present',
        summary:
          installScripts.length === 0
            ? 'None of your packages runs a script of its own while installing.'
            : ignoreScripts
              ? `${installScripts.length} packages want to run a script while installing, but your app installs with those scripts switched off.`
              : `${installScripts.length} packages run a script of their own while installing, and install scripts are not switched off.`,
        passed: installScripts.length === 0 || ignoreScripts,
        runId: ctx.runId,
      }),
    );
  }

  // deps.deprecated-package ----------------------------------------------------------------------
  const deprecated = (lock?.packages ?? [])
    .filter((p) => typeof p.deprecated === 'string' && p.deprecated.length > 0)
    .map((p) => ({ name: p.name, version: p.version, message: p.deprecated ?? '' }));
  if (deprecated.length > 0) {
    for (const pkg of deprecated) {
      findings.push(
        buildDepsFinding(ctx, {
          ruleId: 'deps.deprecated-package',
          key: `${pkg.name}@${pkg.version}`,
          file: 'package-lock.json',
          evidence: `The package author's note: ${pkg.message.slice(0, 300)}`,
          dependency: { package: pkg.name, installedVersion: pkg.version, advisoryIds: [], path: pathOf(lock?.packages ?? [], pkg.name), chain: [] },
        }),
      );
    }
    checks.push({ id: 'deps.deprecated-package', passed: false, detail: `${deprecated.length} deprecated packages` });
  } else if (lock && lock.lockfileVersion >= 3) {
    checks.push({ id: 'deps.deprecated-package', passed: true, detail: 'no package in the lockfile is marked deprecated' });
  } else {
    // Older lockfiles do not record deprecation, and SecureVibe does not query the registry for it.
    checks.push({ id: 'deps.deprecated-package', passed: null, detail: 'the lockfile does not record deprecation notices' });
  }

  // deps.license-copyleft ------------------------------------------------------------------------
  const licenseEntries = collectLicenses(ctx.appDir, lock?.packages ?? []);
  const copyleft = licenseEntries.filter((l) => l.path !== 'dev' && isCopyleft(l.license));
  for (const entry of copyleft) {
    findings.push(
      buildDepsFinding(ctx, {
        ruleId: 'deps.license-copyleft',
        key: `${entry.name}@${entry.version}|${entry.license}`,
        file: 'package-lock.json',
        severity: 'info',
        evidence: `${entry.name}@${entry.version} is published under ${entry.license}.`,
        dependency: { package: entry.name, installedVersion: entry.version, advisoryIds: [], path: entry.path, chain: [] },
      }),
    );
  }
  checks.push({ id: 'deps.license-copyleft', passed: copyleft.length === 0, detail: `${copyleft.length} packages with sharing obligations of ${licenseEntries.length}` });

  // deps.sbom-generated --------------------------------------------------------------------------
  const sbom = await generateSbom({
    appDir: ctx.appDir,
    projectDir: ctx.projectDir,
    runId: ctx.runId,
    outFile: opts.sbomOutFile,
    preferCli: opts.preferCli,
    abort: ctx.abort,
    log: ctx.log,
  });
  checks.push({ id: 'deps.sbom-generated', passed: sbom.written, detail: `${sbom.generator}, ${sbom.componentCount} components` });
  evidence.push(
    buildEvidence({
      ref: 'deps.sbom-generated',
      summary: sbom.written
        ? `A bill of materials listing ${sbom.componentCount} packages was written to reports/${ctx.runId}/sbom.cdx.json.`
        : 'No bill of materials could be produced.',
      passed: sbom.written,
      runId: ctx.runId,
    }),
  );
  if (!sbom.written) {
    findings.push(buildDepsFinding(ctx, { ruleId: 'deps.sbom-generated', key: 'sbom', evidence: sbom.note ?? 'The bill of materials could not be written.' }));
  }

  const details: DepsDetails = {
    lockfile: { present: Boolean(lock), lockfileVersion: lock?.lockfileVersion, packageCount: lock?.packages.length ?? 0, hash: lock?.hash },
    audit: {
      ran: Boolean(report),
      reason: auditReason,
      vulnDbAsOf: report?.vulnDbAsOf,
      fromCache: report?.fromCache ?? false,
      counts: report?.metadata ?? {},
    },
    advisories: report?.advisories ?? [],
    installScripts,
    deprecated,
    licenses: { entries: licenseEntries, summary: summarizeLicenses(licenseEntries), copyleft },
    sbom,
    npmVersion: await npmVersion(ctx),
    checks,
  };

  const coverage: ToolCoverage = {
    tool: 'deps',
    ran: Boolean(report),
    version: details.npmVersion ? `npm ${details.npmVersion}` : 'npm',
    reason: report
      ? report.fromCache
        ? `advisory data reused from ${report.vulnDbAsOf.slice(0, 10)} because this computer could not reach the service`
        : undefined
      : `skipped (offline): ${auditReason ?? 'npm audit could not run'}`,
    covers: DEPS_COVERS,
  };

  const vulnCount = report?.advisories.length ?? 0;
  const summary = report
    ? `Checked ${details.lockfile.packageCount} packages: ${vulnCount === 0 ? 'none has a known security problem' : `${vulnCount} have known security problems`}. Bill of materials: ${sbom.written ? `${sbom.componentCount} packages listed` : 'not produced'}.`
    : `Could not check packages for known security problems (${auditReason ?? 'npm audit did not run'}). Bill of materials: ${sbom.written ? `${sbom.componentCount} packages listed` : 'not produced'}.`;

  return { findings, evidence, coverage, details, status: statusFor(findings, Boolean(report)), summary };
}
