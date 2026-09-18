/**
 * `scaffold` stage (CONTRACTS §9.5, DESIGN §6/§7): copies the hardened template, switches features on/off,
 * writes the generated app's own configuration and design summary, creates its database, and bootstraps the
 * first administrator — all before a single line of AI-generated code exists.
 *
 * The copy happens into `app.tmp` first and is only renamed into place at the very end, so a crash mid-scaffold
 * never leaves a half-built `app/` behind (the caller is expected to have already archived any previous `app/`
 * with `ProjectStore.archiveApp`).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';
import { z } from 'zod';
import type { BuildSpec, DesignArtifacts } from '@shared/design.js';
import { TemplateManifestSchema, type TemplateManifest } from '@shared/knowledge.js';
import type { Provenance } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';
import type { Settings } from '../config.js';
import { describeSandbox, runNode } from '../pipeline/process.js';
import { listFiles, matchesAnyGlob, sha256File } from './files.js';
import { initialProvenance } from './provenance.js';
import { templateHash } from './template-hash.js';

// ---------------------------------------------------------------------------------------------------------------
// Feature flags (manifest feature ids -> on/off). BuildSpec.features covers most of them directly; the three the
// wizard tracks but the design engine does not fold into BuildSpec (ai-history, external-apis, example) are
// derived here from the profile, matching compliance/types.ts's `ManifestCheckContext.extraFeatures`.
// ---------------------------------------------------------------------------------------------------------------

export function manifestFeatureFlags(buildSpec: BuildSpec, profile: DesignProfile): Record<string, boolean> {
  return {
    auth: buildSpec.features.auth,
    'admin-mfa': buildSpec.features.adminMfa,
    'user-mfa': buildSpec.features.userMfa,
    uploads: buildSpec.features.uploads,
    ai: buildSpec.features.ai,
    'ai-actions': buildSpec.features.aiActions,
    'ai-moderation': buildSpec.features.aiModeration,
    'ai-history': buildSpec.features.ai && profile.capabilities.aiAssistant.storesHistory,
    email: buildSpec.features.email,
    scheduler: buildSpec.features.scheduler,
    'public-api': buildSpec.features.publicApi,
    payments: buildSpec.features.payments,
    'field-encryption': buildSpec.features.fieldEncryption,
    retention: buildSpec.features.retentionJobs,
    'external-apis': profile.capabilities.externalApis.length > 0,
    example: false, // TPL-EXAMPLE-01: never on in a generated app
  };
}

function outboundHostsFor(buildSpec: BuildSpec): string[] {
  const hosts = new Set<string>();
  if (buildSpec.features.ai) hosts.add('api.anthropic.com');
  return [...hosts];
}

// ---------------------------------------------------------------------------------------------------------------
// .env
// ---------------------------------------------------------------------------------------------------------------

function upsertEnvLines(lines: string[], overrides: Record<string, string>): string[] {
  const remaining = new Map(Object.entries(overrides));
  const out = lines.map((line) => {
    const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (!m) return line;
    const key = m[1]!;
    if (!remaining.has(key)) return line;
    const value = remaining.get(key)!;
    remaining.delete(key);
    return `${key}=${value}`;
  });
  if (remaining.size > 0) {
    out.push('');
    for (const [key, value] of remaining) out.push(`${key}=${value}`);
  }
  return out;
}

/**
 * An app that serves https itself (TLS_MODE=selfsigned) cannot start without a certificate, so one is made here,
 * the same way the app's own `npm run gen-cert` does. Without openssl the app is left as it is and the owner is told.
 */
function ensureSelfSignedCert(appDir: string): string | undefined {
  const certsDir = join(appDir, 'certs');
  const keyFile = join(certsDir, 'key.pem');
  const certFile = join(certsDir, 'cert.pem');
  if (existsSync(keyFile) && existsSync(certFile)) return undefined;
  const missing = 'Your app is set to serve https with its own certificate, but none could be created here because the "openssl" command is not installed. Run "npm run gen-cert" in the app folder once openssl is available; until then the app will not start.';
  const version = spawnSync('openssl', ['version'], { encoding: 'utf8', timeout: 10_000 });
  if (version.error || version.status !== 0) return missing;
  mkdirSync(certsDir, { recursive: true, mode: 0o700 });
  const result = spawnSync(
    'openssl',
    ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '825', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
    { encoding: 'utf8', timeout: 30_000 },
  );
  if (result.status !== 0) return `The self-signed certificate could not be created (openssl said: ${(result.stderr ?? '').trim().slice(0, 200)}). Run "npm run gen-cert" in the app folder.`;
  chmodSync(keyFile, 0o600);
  chmodSync(certFile, 0o644);
  return undefined;
}

async function writeEnvFile(appDir: string, profile: DesignProfile, buildSpec: BuildSpec, settings: Settings): Promise<string[]> {
  const exampleFile = join(appDir, '.env.example');
  const envFile = join(appDir, '.env');
  const base = existsSync(exampleFile) ? await readFile(exampleFile, 'utf8') : '';
  const overrides: Record<string, string> = {
    APP_NAME: profile.app.name,
    TLS_MODE: buildSpec.features.tlsMode,
    BIND_LAN: buildSpec.features.lanBinding ? '1' : '0',
    TRUST_PROXY_HOPS: buildSpec.features.tlsMode === 'proxy' ? '1' : '0',
    SESSION_IDLE_MINUTES: String(buildSpec.sessionPolicy.idleMinutes),
    SESSION_ABSOLUTE_HOURS: String(buildSpec.sessionPolicy.absoluteHours),
    SESSION_MAX_CONCURRENT: String(buildSpec.sessionPolicy.maxConcurrent),
    ADMIN_MFA_REQUIRED: buildSpec.features.adminMfa ? '1' : '0',
    USER_MFA_AVAILABLE: buildSpec.features.userMfa ? '1' : '0',
    REGISTRATION_MODE: profile.users.registration,
    ADMIN_EMAIL: profile.deployment.owner.contactEmail,
    AI_ENABLED: buildSpec.features.ai ? '1' : '0',
    AI_MODEL: settings.model,
    // Looking things up on the web happens at the AI provider, so no extra outbound host is needed.
    AI_WEB_SEARCH: buildSpec.features.aiWebSearch ? '1' : '0',
    AI_WEB_SEARCH_DOMAINS: buildSpec.features.aiWebSearch ? profile.capabilities.aiAssistant.webSearchSites.join(',') : '',
    AI_MODERATION: buildSpec.features.aiModeration ? '1' : '0',
    OUTBOUND_ALLOWED_HOSTS: outboundHostsFor(buildSpec).join(','),
    RETENTION_MONTHS: profile.data.retention === 'auto-delete-after-period' && profile.data.retentionMonths ? String(profile.data.retentionMonths) : '',
    EXAMPLE_FEATURE: '0',
  };
  const lines = upsertEnvLines(base.split(/\r?\n/), overrides);
  await writeFile(envFile, `${lines.join('\n').replace(/\n*$/, '\n')}`, { mode: 0o600 });

  const warnings: string[] = [];
  if (profile.capabilities.externalApis.length > 0) {
    warnings.push(
      `${profile.capabilities.externalApis.length} external connection(s) you described (${profile.capabilities.externalApis
        .map((a) => a.name)
        .join(', ')}) need their address added to OUTBOUND_ALLOWED_HOSTS in .env before the app can reach them.`,
    );
  }
  return warnings;
}

// ---------------------------------------------------------------------------------------------------------------
// Feature toggle removal
// ---------------------------------------------------------------------------------------------------------------

async function removeDisabledFeatures(appDir: string, manifest: TemplateManifest, flags: Record<string, boolean>): Promise<string[]> {
  const removed: string[] = [];
  for (const feature of manifest.features) {
    if (flags[feature.id] !== false) continue;
    for (const relPath of feature.paths) {
      const abs = join(appDir, relPath);
      if (existsSync(abs)) {
        await rm(abs, { recursive: true, force: true });
        removed.push(relPath);
      }
    }
  }
  return removed;
}

// ---------------------------------------------------------------------------------------------------------------
// securevibe.design.json (subset used by docs:build)
// ---------------------------------------------------------------------------------------------------------------

const AppDesignSubsetSchema = z.object({
  appName: z.string(),
  dataCategories: z.array(z.string()),
  owner: z.object({ name: z.string(), contactEmail: z.string() }),
  retention: z.object({ policy: z.enum(['keep-until-deleted', 'auto-delete-after-period']), months: z.number().optional() }),
  region: z.string(),
  sessionPolicy: z.object({ idleMinutes: z.number(), absoluteHours: z.number(), maxConcurrent: z.number() }),
  outboundHosts: z.array(z.string()),
  businessImpact: z.string(),
});
export type AppDesignSubset = z.infer<typeof AppDesignSubsetSchema>;

function designSubsetFor(profile: DesignProfile, buildSpec: BuildSpec): AppDesignSubset {
  return AppDesignSubsetSchema.parse({
    appName: profile.app.name,
    dataCategories: profile.data.categories,
    owner: profile.deployment.owner,
    retention: { policy: profile.data.retention, ...(profile.data.retentionMonths ? { months: profile.data.retentionMonths } : {}) },
    region: profile.data.region,
    sessionPolicy: buildSpec.sessionPolicy,
    outboundHosts: outboundHostsFor(buildSpec),
    businessImpact: profile.deployment.businessImpact,
  });
}

// ---------------------------------------------------------------------------------------------------------------
// node_modules fast path
// ---------------------------------------------------------------------------------------------------------------

async function lockfileHash(file: string): Promise<string | undefined> {
  if (!existsSync(file)) return undefined;
  return createHash('sha256').update(await readFile(file)).digest('hex');
}

/** Copies the template's own node_modules instead of running `npm ci`, when its lockfile matches the scaffolded one. */
export async function tryNodeModulesFastPath(templateDir: string, appDir: string): Promise<boolean> {
  const templateNodeModules = join(templateDir, 'node_modules');
  if (!existsSync(templateNodeModules)) return false;
  const [templateHash, appHash] = await Promise.all([lockfileHash(join(templateDir, 'package-lock.json')), lockfileHash(join(appDir, 'package-lock.json'))]);
  if (!templateHash || !appHash || templateHash !== appHash) return false;
  // node_modules/.bin holds relative symlinks (../typescript/bin/tsc); copying their targets instead would
  // leave scripts that cannot find their own package, so the links are kept exactly as they are.
  await cp(templateNodeModules, join(appDir, 'node_modules'), { recursive: true, dereference: false, verbatimSymlinks: true });
  return true;
}

// ---------------------------------------------------------------------------------------------------------------
// Protected file hashes
// ---------------------------------------------------------------------------------------------------------------

export function computeProtectedFileHashes(appDir: string, manifest: TemplateManifest): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const file of listFiles(appDir)) {
    if (!matchesAnyGlob(file.relPath, manifest.protectedPaths)) continue;
    const hash = sha256File(file.absPath);
    if (hash) hashes[file.relPath] = hash;
  }
  return hashes;
}

// ---------------------------------------------------------------------------------------------------------------
// setup: secrets, migrations, first admin
// ---------------------------------------------------------------------------------------------------------------

export interface FirstLoginInfo {
  email: string;
  password: string;
  expiresAt: string;
  file: string;
}

function extractFirstLogin(stdout: string): { email?: string; password?: string; expiresAt?: string } {
  const email = /Administrator account created:\s*(\S+)/.exec(stdout)?.[1];
  const password = /One-time password:\s*(\S+)/.exec(stdout)?.[1];
  const expiresAt = /It expires at ([\d-]+ [\d:]+) UTC/.exec(stdout)?.[1];
  return { email, password, expiresAt };
}

/**
 * Regenerates routes.manifest.json from the app's live route registry. Runs after entity expansion so the
 * manifest lists the template's own routes and the generated ones; the runtime scan treats any live route
 * missing from this file as having an unknown authorization policy.
 */
export async function exportRouteManifest(appDir: string, projectDir: string, runId: string): Promise<string[]> {
  const result = await runNode(['--experimental-strip-types', 'scripts/routes-export.ts'], {
    cwd: appDir,
    projectDir,
    runId,
    permission: { read: [appDir], write: [appDir] },
    timeoutMs: 60_000,
  });
  const warnings = [...result.warnings];
  if (result.code !== 0) warnings.push(`Could not list the app's routes: ${result.stderr.slice(0, 500) || result.stdout.slice(0, 500)}`);
  return warnings;
}

/**
 * Regenerates the files SecureVibe derives from the code: routes.manifest.json and docs/ (docs:build). Called after
 * the expander, after generation and after every fix round, so the docs and route list always describe the code
 * being assessed. docs/ is protected from the agent, so SecureVibe records the fresh docs hashes itself; any other
 * change to a protected file is still reported by the integrity check.
 */
export async function refreshDerivedFiles(opts: {
  appDir: string;
  projectDir: string;
  runId: string;
  manifest?: TemplateManifest;
  provenance?: Provenance;
}): Promise<{ warnings: string[]; provenance?: Provenance }> {
  const { appDir, projectDir, runId } = opts;
  const warnings = await exportRouteManifest(appDir, projectDir, runId);
  if (existsSync(join(appDir, 'scripts', 'docs-build.ts'))) {
    const docs = await runNode(['--experimental-strip-types', 'scripts/docs-build.ts'], {
      cwd: appDir,
      projectDir,
      runId,
      permission: { read: [appDir], write: [appDir] },
      timeoutMs: 60_000,
    });
    warnings.push(...docs.warnings);
    if (docs.code !== 0) warnings.push(`Could not refresh the app's documentation: ${docs.stderr.slice(0, 500) || docs.stdout.slice(0, 500)}`);
  }
  if (!opts.provenance || !opts.manifest) return { warnings };
  const fresh = computeProtectedFileHashes(appDir, opts.manifest);
  const hashes = Object.fromEntries(Object.entries(opts.provenance.protectedFileHashes).filter(([file]) => !file.startsWith('docs/')));
  for (const [file, hash] of Object.entries(fresh)) if (file.startsWith('docs/')) hashes[file] = hash;
  const provenance: Provenance = { ...opts.provenance, protectedFileHashes: hashes };
  await writeFile(join(appDir, 'securevibe.provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
  return { warnings, provenance };
}

/**
 * Files that may exist in a template checkout (editor state, or leftovers from running the template's own tests)
 * but must never reach a generated app: each app gets its own secrets, database and feature file.
 */
const TEMPLATE_COPY_SKIP = new Set(['.claude', '.env', 'securevibe.features.json', 'securevibe.design.json', 'data/app.sqlite', 'data/app.sqlite-wal', 'data/app.sqlite-shm', 'data/app.log', 'data/outbox']);

async function runSetupScripts(appDir: string, projectDir: string, runId: string, ownerEmail: string, log: (m: string) => void): Promise<{ firstLogin?: FirstLoginInfo; warnings: string[] }> {
  const warnings: string[] = [];
  const permission = { read: [appDir], write: [appDir] };
  const common = { cwd: appDir, projectDir, runId, permission, timeoutMs: 60_000 };

  log('Generating strong secrets for this application…');
  const secrets = await runNode(['--experimental-strip-types', 'scripts/gen-secrets.ts'], common);
  if (secrets.code !== 0) warnings.push(`Could not generate secrets: ${secrets.stderr.slice(0, 500) || secrets.stdout.slice(0, 500)}`);
  warnings.push(...secrets.warnings);

  log('Creating the database…');
  const migrate = await runNode(['--experimental-strip-types', 'scripts/migrate.ts'], common);
  if (migrate.code !== 0) warnings.push(`Could not create the database: ${migrate.stderr.slice(0, 500) || migrate.stdout.slice(0, 500)}`);
  warnings.push(...migrate.warnings);

  log('Creating the first administrator account…');
  const bootstrap = await runNode(['--experimental-strip-types', 'scripts/bootstrap-admin.ts', '--email', ownerEmail], common);
  warnings.push(...bootstrap.warnings);
  if (bootstrap.code !== 0) {
    warnings.push(`Could not create the first administrator account: ${bootstrap.stderr.slice(0, 500) || bootstrap.stdout.slice(0, 500)}`);
    return { warnings };
  }
  const parsed = extractFirstLogin(bootstrap.stdout);
  if (!parsed.email || !parsed.password) {
    warnings.push('The administrator account was created, but the one-time password could not be read from the setup output. See app/FIRST-LOGIN.txt.');
    return { warnings };
  }
  return {
    firstLogin: { email: parsed.email, password: parsed.password, expiresAt: parsed.expiresAt ?? '', file: join(appDir, 'FIRST-LOGIN.txt') },
    warnings,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------------------------------------------

export interface ScaffoldInput {
  templateDir: string;
  projectDir: string;
  /** Final location (`<project>/app`); the caller is responsible for archiving any existing app/ first. */
  appDir: string;
  design: DesignArtifacts;
  profile: DesignProfile;
  buildSpec: BuildSpec;
  settings: Settings;
  runId: string;
  projectId: string;
  securevibeVersion: string;
  /** Repository `data/knowledge` folder (source of truth for common-passwords.txt). */
  knowledgeDir: string;
  previousRunId?: string;
  log(msg: string): void;
}

export interface ScaffoldResult {
  manifest: TemplateManifest;
  featureFlags: Record<string, boolean>;
  removedFeaturePaths: string[];
  protectedFileHashes: Record<string, string>;
  provenance: Provenance;
  firstLogin?: FirstLoginInfo;
  warnings: string[];
  nodeModulesFastPath: boolean;
}

export interface StageTemplateInput {
  templateDir: string;
  /** An empty (or absent) folder the configured template is written into. */
  targetDir: string;
  profile: DesignProfile;
  buildSpec: BuildSpec;
  settings: Settings;
  knowledgeDir: string;
  log(msg: string): void;
}

export interface StagedTemplate {
  manifest: TemplateManifest;
  featureFlags: Record<string, boolean>;
  removedFeaturePaths: string[];
  warnings: string[];
}

/**
 * Copies the template and configures it for a design: features switched on or off, the features/design files,
 * the .env, a certificate when the app serves https itself, and the common-password list. No packages, no
 * database, no provenance: that is what a build adds on top, and what a template update leaves alone.
 */
export async function stageTemplate(input: StageTemplateInput): Promise<StagedTemplate> {
  const { templateDir, targetDir, profile, buildSpec, settings, log } = input;
  log('Copying the hardened starter application…');
  await mkdir(targetDir, { recursive: true });
  await cp(templateDir, targetDir, {
    recursive: true,
    dereference: true,
    filter: (src) => basename(src) !== 'node_modules' && !TEMPLATE_COPY_SKIP.has(relative(templateDir, src).split(sep).join('/')),
  });

  const manifest = TemplateManifestSchema.parse(JSON.parse(await readFile(join(targetDir, 'securevibe.manifest.json'), 'utf8')));
  const featureFlags = manifestFeatureFlags(buildSpec, profile);

  log('Switching on the features you chose…');
  const removedFeaturePaths = await removeDisabledFeatures(targetDir, manifest, featureFlags);

  await writeFile(join(targetDir, 'securevibe.features.json'), `${JSON.stringify(featureFlags, null, 2)}\n`);
  await writeFile(join(targetDir, 'securevibe.design.json'), `${JSON.stringify(designSubsetFor(profile, buildSpec), null, 2)}\n`);

  const warnings = await writeEnvFile(targetDir, profile, buildSpec, settings);
  if (buildSpec.features.tlsMode === 'selfsigned') {
    log('Creating the self-signed certificate the app serves https with…');
    const certWarning = ensureSelfSignedCert(targetDir);
    if (certWarning) warnings.push(certWarning);
  }

  const commonPasswordsSource = join(input.knowledgeDir, 'common-passwords.txt');
  if (existsSync(commonPasswordsSource)) {
    // The large public list and the template's own curated list overlap but neither contains the other, so the
    // app gets both.
    const target = join(targetDir, 'data', 'common-passwords.txt');
    await mkdir(join(targetDir, 'data'), { recursive: true });
    const lists = [await readFile(commonPasswordsSource, 'utf8'), existsSync(target) ? await readFile(target, 'utf8') : ''];
    const merged = new Set<string>();
    for (const list of lists) for (const line of list.split(/\r?\n/)) if (line.trim()) merged.add(line.trim().toLowerCase());
    await writeFile(target, `${[...merged].join('\n')}\n`);
  }
  return { manifest, featureFlags, removedFeaturePaths, warnings };
}

export async function scaffoldApp(input: ScaffoldInput): Promise<ScaffoldResult> {
  const { templateDir, projectDir, appDir, design, profile, buildSpec, settings, log } = input;
  const tmpDir = join(projectDir, 'app.tmp');
  await rm(tmpDir, { recursive: true, force: true });

  const staged = await stageTemplate({ templateDir, targetDir: tmpDir, profile, buildSpec, settings, knowledgeDir: input.knowledgeDir, log });
  const { manifest, featureFlags, removedFeaturePaths } = staged;
  const envWarnings = staged.warnings;

  log('Checking whether the installed packages can be reused…');
  const nodeModulesFastPath = await tryNodeModulesFastPath(templateDir, tmpDir);

  const setupWarnings: string[] = [];
  let firstLogin: FirstLoginInfo | undefined;
  if (nodeModulesFastPath) {
    const result = await runSetupScripts(tmpDir, projectDir, input.runId, profile.deployment.owner.contactEmail, log);
    firstLogin = result.firstLogin;
    setupWarnings.push(...result.warnings);
  } else {
    setupWarnings.push('The application\'s packages are not installed yet, so the database and the first administrator account will be created after the "install" step.');
  }

  const protectedFileHashes = computeProtectedFileHashes(tmpDir, manifest);
  const provenance = initialProvenance({
    runId: input.runId,
    projectId: input.projectId,
    mode: 'full',
    appDir: tmpDir,
    templateVersion: manifest.version,
    securevibeVersion: input.securevibeVersion,
    designProfileHash: design.profileHash,
    designHash: sha256Hex(JSON.stringify(design)),
    protectedFileHashes,
    templateHash: templateHash(templateDir),
    sandbox: describeSandbox(),
    ...(input.previousRunId ? { previousRunId: input.previousRunId } : {}),
    ...(design.contractHash ? { contractHash: design.contractHash } : {}),
  });
  await writeFile(join(tmpDir, 'securevibe.provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);

  log('Finishing the application folder…');
  await rm(appDir, { recursive: true, force: true });
  await rename(tmpDir, appDir);

  return {
    manifest,
    featureFlags,
    removedFeaturePaths,
    protectedFileHashes,
    provenance,
    ...(firstLogin ? { firstLogin } : {}),
    warnings: [...envWarnings, ...setupWarnings],
    nodeModulesFastPath,
  };
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}
