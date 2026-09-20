/**
 * Config checks (CONTRACTS §4): every `config.*` id, each answering a plain pass/fail question about the
 * generated app's configuration files. `index.ts` turns each outcome into Evidence, plus a Finding when it
 * fails.
 */
import { existsSync } from 'node:fs';
import { usesNpm } from '../ecosystems.js';
import { join } from 'node:path';
import type { RuleMeta } from '../sast/findings.js';
import { globToRegex, listAppFiles, readTextFile, sha256File } from '../sast/files.js';
import { NOT_SELF_HASHABLE } from '../../generator/files.js';
import type { ScanContext } from '../types.js';
import { base64ByteLength, parseEnv } from './env.js';

export interface ConfigCheckOutcome {
  passed: boolean;
  /** Plain-language sentence: what was checked and what was found. */
  summary: string;
  file?: string;
  line?: number;
  /** Overrides the rule's severity for this result (a reminder is less serious than a hard-coded password). */
  severity?: RuleMeta['severity'];
}

export interface ConfigCheckDef {
  meta: RuleMeta;
  run(ctx: ScanContext): ConfigCheckOutcome;
  /**
   * Whether this check has anything to say about this application. Absent means always.
   *
   * A check that does not apply is not a check that failed. Without this, a Python app was told its
   * `package-lock.json` was missing and marked down for not setting `ignore-scripts=true` in an `.npmrc` it has
   * no reason to own — not a coverage gap, which is honest, but a report saying something untrue out loud
   * (ADR-012).
   */
  applies?(ctx: ScanContext): boolean;
}

function meta(input: Omit<RuleMeta, 'remediation' | 'whoCanFix'> & { fix: string; steps?: string[]; references?: string[] }): RuleMeta {
  const { fix, steps, references, ...rest } = input;
  return { ...rest, remediation: { summary: fix, steps: steps ?? [], references: references ?? [] } };
}

function read(ctx: Pick<ScanContext, 'appDir'>, relPath: string): string | undefined {
  return readTextFile(join(ctx.appDir, relPath));
}

function readJson<T>(ctx: Pick<ScanContext, 'appDir'>, relPath: string): T | undefined {
  const text = read(ctx, relPath);
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

function readEnv(ctx: Pick<ScanContext, 'appDir'>): Record<string, string> | undefined {
  const text = read(ctx, '.env');
  return text === undefined ? undefined : parseEnv(text);
}

// ---------------------------------------------------------------------------------------------

export const envExamplePresent: ConfigCheckDef = {
  meta: meta({
    id: 'config.env-example-present',
    title: '.env.example is missing',
    severity: 'low',
    confidence: 'high',
    cwe: ['CWE-1188'],
    asvs: ['V13.2.3'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'theoretical',
    description: 'The app folder has no .env.example file listing the settings it needs.',
    impact: 'Whoever sets the app up next will not know which settings exist and may leave one at an unsafe value.',
    fix: 'Restore .env.example from the template (placeholder values only, no real secrets).',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const exists = existsSync(join(ctx.appDir, '.env.example'));
    return { passed: exists, summary: exists ? '.env.example is present.' : '.env.example was not found.', file: '.env.example' };
  },
};

export const gitignoreCoversEnv: ConfigCheckDef = {
  meta: meta({
    id: 'config.gitignore-covers-env',
    title: '.gitignore does not exclude .env',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-540'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'theoretical',
    description: 'The .gitignore file does not list .env (and .env.*), so secrets could be committed to version control.',
    impact: 'Once a secret is in a repository it is effectively public to everyone with access, including any backup or hosting service.',
    fix: 'Add .env and .env.* (with an exception for .env.example) to .gitignore.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const text = read(ctx, '.gitignore');
    if (text === undefined) return { passed: false, summary: '.gitignore was not found.', file: '.gitignore' };
    const lines = text
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    const covered = lines.some((l) => /^\.env(\*|\.\*)?$/.test(l));
    return {
      passed: covered,
      summary: covered ? '.gitignore excludes .env.' : '.gitignore does not have a line for .env or .env.*.',
      file: '.gitignore',
    };
  },
};

const SECRET_ENV_KEYS = ['SESSION_SECRET', 'TOKEN_HMAC_KEY'] as const;

export const secretsStrength: ConfigCheckDef = {
  meta: meta({
    id: 'config.secrets-strength',
    title: 'A secret in .env is weak or a placeholder',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-521', 'CWE-1392'],
    asvs: ['V13.2.3', 'V11.2.3'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'requires-network-exposure',
    description: 'SESSION_SECRET, FIELD_KEYS or TOKEN_HMAC_KEY is shorter than 32 bytes or equals the .env.example placeholder.',
    impact: 'Sessions, reset tokens and encrypted fields all rely on these values. A weak or known value lets an attacker forge sessions or decrypt data.',
    fix: 'Run npm run setup (or node scripts/gen-secrets.ts) in the app folder, then restart.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx);
    if (!env) return { passed: false, summary: '.env was not found, so secret strength could not be checked.', file: '.env' };
    const example = read(ctx, '.env.example');
    const exampleEnv = example ? parseEnv(example) : {};
    const problems: string[] = [];
    for (const key of SECRET_ENV_KEYS) {
      const value = env[key];
      if (!value) {
        problems.push(`${key} is missing`);
        continue;
      }
      if (exampleEnv[key] !== undefined && value === exampleEnv[key]) {
        problems.push(`${key} still has the .env.example placeholder`);
        continue;
      }
      const bytes = base64ByteLength(value);
      if (Number.isNaN(bytes) || bytes < 32) problems.push(`${key} decodes to fewer than 32 bytes`);
    }
    const fieldKeys = env['FIELD_KEYS'];
    if (fieldKeys !== undefined) {
      const entries = fieldKeys.split(',').map((e) => e.trim());
      for (const entry of entries) {
        const [id, value] = entry.split(':');
        if (!id || !value) {
          problems.push(`FIELD_KEYS entry "${entry}" is not in the id:key form`);
          continue;
        }
        const bytes = base64ByteLength(value);
        if (Number.isNaN(bytes) || bytes < 32) problems.push(`FIELD_KEYS key ${id} decodes to fewer than 32 bytes`);
      }
    } else {
      problems.push('FIELD_KEYS is missing');
    }
    return {
      passed: problems.length === 0,
      summary: problems.length === 0 ? 'SESSION_SECRET, FIELD_KEYS and TOKEN_HMAC_KEY are all at least 32 bytes and not placeholders.' : problems.join('; '),
      file: '.env',
    };
  },
};

export const noDefaultAdmin: ConfigCheckDef = {
  meta: meta({
    id: 'config.no-default-admin',
    title: 'Default administrator credential present',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-1392'],
    asvs: ['V6.3.2', 'V6.4.1'],
    aisvs: [],
    sbd: [],
    exploitability: 'requires-network-exposure',
    description: 'An ADMIN_PASSWORD-style variable exists in .env, or FIRST-LOGIN.txt still holds an unused one-time password.',
    impact: 'A known or written-down administrator password is the first thing an attacker tries.',
    fix: 'Remove any fixed admin password variables; sign in once with the one-time password and delete FIRST-LOGIN.txt.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const fixedPasswordKey = Object.keys(env).find((k) => /^ADMIN_?PASSWORD/i.test(k) || /^DEFAULT_?ADMIN/i.test(k));
    const firstLoginExists = existsSync(join(ctx.appDir, 'FIRST-LOGIN.txt'));
    const problems: string[] = [];
    if (fixedPasswordKey) problems.push(`.env sets ${fixedPasswordKey}`);
    if (firstLoginExists) problems.push('FIRST-LOGIN.txt is still on disk');
    // A one-time password waiting to be used is expected right after a build; it expires after 24 hours and must
    // be changed at first sign-in, so on its own it is a reminder to the owner rather than a vulnerability.
    return {
      passed: problems.length === 0,
      summary:
        problems.length === 0
          ? 'No fixed admin password and FIRST-LOGIN.txt has been removed.'
          : fixedPasswordKey
            ? problems.join('; ')
            : 'FIRST-LOGIN.txt still holds the one-time administrator password. Sign in once, then delete the file.',
      file: fixedPasswordKey ? '.env' : 'FIRST-LOGIN.txt',
      ...(fixedPasswordKey ? {} : { severity: 'low' as const }),
    };
  },
};

export const nodeEnginePinned: ConfigCheckDef = {
  meta: meta({
    id: 'config.node-engine-pinned',
    title: 'Node.js version not pinned',
    severity: 'low',
    confidence: 'high',
    cwe: ['CWE-1104'],
    asvs: ['V15.2.1'],
    aisvs: [],
    sbd: ['RR-01'],
    exploitability: 'theoretical',
    description: 'package.json has no engines.node requirement.',
    impact: 'Running on an old Node.js version silently loses security fixes and built-in features the app relies on.',
    fix: 'Set "engines": { "node": ">=22.13.0" } in package.json.',
    references: ['https://nodejs.org/en/about/previous-releases'],
  }),
  run: (ctx) => {
    const pkg = readJson<{ engines?: { node?: string } }>(ctx, 'package.json');
    const node = pkg?.engines?.node;
    return { passed: !!node, summary: node ? `package.json requires Node ${node}.` : 'package.json has no engines.node field.', file: 'package.json' };
  },
};

export const lockfilePresent: ConfigCheckDef = {
  meta: meta({
    id: 'config.lockfile-present',
    title: 'package-lock.json is missing',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-1104'],
    asvs: ['V15.1.2'],
    aisvs: [],
    sbd: ['RR-01'],
    exploitability: 'theoretical',
    description: 'There is no lockfile, so npm may install different package versions than the ones that were tested.',
    impact: 'Untested or compromised package versions can be installed without anyone noticing.',
    fix: 'Restore the tested package-lock.json from the template and install with npm ci --ignore-scripts.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html'],
  }),
  applies: (ctx) => usesNpm(ctx.appDir),
  run: (ctx) => {
    const exists = existsSync(join(ctx.appDir, 'package-lock.json'));
    return { passed: exists, summary: exists ? 'package-lock.json is present.' : 'package-lock.json was not found.', file: 'package-lock.json' };
  },
};

export const ignoreScripts: ConfigCheckDef = {
  meta: meta({
    id: 'config.ignore-scripts',
    title: 'npm install scripts are allowed',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-829'],
    asvs: ['V15.1.2'],
    aisvs: [],
    sbd: ['RR-01'],
    exploitability: 'theoretical',
    description: '.npmrc does not set ignore-scripts=true.',
    impact: 'Packages can run arbitrary code on your computer during install — a common supply-chain attack path.',
    fix: 'Add ignore-scripts=true to .npmrc.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html'],
  }),
  applies: (ctx) => usesNpm(ctx.appDir),
  run: (ctx) => {
    const text = read(ctx, '.npmrc');
    const ok = !!text && /^\s*ignore-scripts\s*=\s*true\s*$/m.test(text);
    return { passed: ok, summary: ok ? '.npmrc sets ignore-scripts=true.' : '.npmrc is missing or does not set ignore-scripts=true.', file: '.npmrc' };
  },
};

export const noDebugFlags: ConfigCheckDef = {
  meta: meta({
    id: 'config.no-debug-flags',
    title: 'Debug settings enabled',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-489'],
    asvs: ['V13.4.2'],
    aisvs: [],
    sbd: [],
    exploitability: 'requires-network-exposure',
    description: 'NODE_ENV is development, or a start script uses --inspect.',
    impact: 'Debug modes show detailed errors and can expose a debugging port that gives full control of the process.',
    fix: 'Set NODE_ENV=production (or remove it) and remove --inspect from any start command.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const pkg = readJson<{ scripts?: Record<string, string> }>(ctx, 'package.json');
    const problems: string[] = [];
    if (env['NODE_ENV'] === 'development') problems.push('NODE_ENV=development in .env');
    for (const [name, cmd] of Object.entries(pkg?.scripts ?? {})) {
      if (/--inspect/.test(cmd)) problems.push(`the "${name}" script uses --inspect`);
    }
    return { passed: problems.length === 0, summary: problems.length === 0 ? 'No debug flags found.' : problems.join('; '), file: problems.some((p) => p.includes('NODE_ENV')) ? '.env' : 'package.json' };
  },
};

export const exampleFeatureDisabled: ConfigCheckDef = {
  meta: meta({
    id: 'config.example-feature-disabled',
    title: 'Example feature enabled in production',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-1188'],
    asvs: ['V15.2.3'],
    aisvs: [],
    sbd: [],
    exploitability: 'requires-network-exposure',
    description: 'EXAMPLE_FEATURE=1 mounts the reference "notes" feature.',
    impact: 'Extra functionality nobody uses is still attack surface and clutters your data.',
    fix: 'Set EXAMPLE_FEATURE=0 or remove it from .env.',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const on = env['EXAMPLE_FEATURE'] === '1' || env['EXAMPLE_FEATURE']?.toLowerCase() === 'true';
    return { passed: !on, summary: on ? 'EXAMPLE_FEATURE is enabled in .env.' : 'EXAMPLE_FEATURE is off (or unset).', file: '.env' };
  },
};

export const testModeNotInEnv: ConfigCheckDef = {
  meta: meta({
    id: 'config.test-mode-not-in-env',
    title: 'Test mode enabled in .env',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-489'],
    asvs: ['V15.2.3', 'V6.3.2'],
    aisvs: [],
    sbd: [],
    exploitability: 'trivial',
    description: 'SECUREVIBE_TEST_MODE=1 is present in .env.',
    impact: 'Test mode seeds known accounts with a known password and exposes helper endpoints — a ready-made back door in production.',
    fix: 'Remove the SECUREVIBE_TEST_MODE line from .env and restart.',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const on = !!env['SECUREVIBE_TEST_MODE'] && env['SECUREVIBE_TEST_MODE'] !== '0';
    return { passed: !on, summary: on ? 'SECUREVIBE_TEST_MODE is set in .env.' : 'SECUREVIBE_TEST_MODE is not set in .env.', file: '.env' };
  },
};

export const tlsModeConsistent: ConfigCheckDef = {
  meta: meta({
    id: 'config.tls-mode-consistent',
    title: 'TLS settings are inconsistent',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-319'],
    asvs: ['V12.1.1', 'V3.3.1'],
    aisvs: [],
    sbd: ['AC-01'],
    exploitability: 'requires-network-exposure',
    description: 'TLS_MODE=proxy but TRUST_PROXY_HOPS is 0, or TLS_MODE=selfsigned but no certificates exist in certs/.',
    impact: 'Secure cookies and HSTS may be set wrongly, or the app may think requests are HTTPS when they are not.',
    fix: 'Match TLS_MODE to your setup: proxy + TRUST_PROXY_HOPS >= 1 behind a reverse proxy, or selfsigned with certs/ generated by npm run gen-cert.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const tlsMode = env['TLS_MODE'] ?? 'off';
    const hops = Number.parseInt(env['TRUST_PROXY_HOPS'] ?? '0', 10);
    if (tlsMode === 'proxy' && (!Number.isFinite(hops) || hops < 1)) {
      return { passed: false, summary: 'TLS_MODE=proxy but TRUST_PROXY_HOPS is 0.', file: '.env' };
    }
    if (tlsMode === 'selfsigned') {
      const certOk = existsSync(join(ctx.appDir, 'certs/cert.pem')) && existsSync(join(ctx.appDir, 'certs/key.pem'));
      if (!certOk) return { passed: false, summary: 'TLS_MODE=selfsigned but certs/cert.pem or certs/key.pem is missing.', file: 'certs' };
    }
    return { passed: true, summary: `TLS_MODE=${tlsMode} is internally consistent.`, file: '.env' };
  },
};

export const trustProxyHops: ConfigCheckDef = {
  meta: meta({
    id: 'config.trust-proxy-hops',
    title: 'Proxy trust setting is wrong',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-348'],
    asvs: ['V4.1.3', 'V15.3.4'],
    aisvs: [],
    sbd: [],
    exploitability: 'requires-network-exposure',
    description: 'TRUST_PROXY_HOPS does not match the deployment (non-zero with no proxy, or not a whole number).',
    impact: 'Either visitors can spoof their IP address (too trusting) or rate limits are computed incorrectly.',
    fix: 'Set TRUST_PROXY_HOPS to the exact number of proxies in front of the app (0 when there is none).',
    references: ['https://expressjs.com/en/guide/behind-proxies.html'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const raw = env['TRUST_PROXY_HOPS'] ?? '0';
    const hops = Number.parseInt(raw, 10);
    if (!/^\d+$/.test(raw.trim())) return { passed: false, summary: `TRUST_PROXY_HOPS="${raw}" is not a non-negative whole number.`, file: '.env' };
    const tlsMode = env['TLS_MODE'] ?? 'off';
    if (hops > 0 && tlsMode !== 'proxy') return { passed: false, summary: `TRUST_PROXY_HOPS=${hops} but TLS_MODE is "${tlsMode}", not proxy.`, file: '.env' };
    return { passed: true, summary: `TRUST_PROXY_HOPS=${hops} matches TLS_MODE=${tlsMode}.`, file: '.env' };
  },
};

export const sessionPolicy: ConfigCheckDef = {
  meta: meta({
    id: 'config.session-policy',
    title: 'Session timeouts are too long',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-613'],
    asvs: ['V7.3.1', 'V7.3.2', 'V7.1.2'],
    aisvs: [],
    sbd: [],
    exploitability: 'theoretical',
    description: 'SESSION_IDLE_MINUTES, SESSION_ABSOLUTE_HOURS or SESSION_MAX_CONCURRENT exceed the values the design settled on.',
    impact: 'A session left open on a shared or stolen device stays usable for much longer than intended.',
    fix: 'Restore the documented session policy values in .env.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const policy = ctx.buildSpec?.sessionPolicy ?? { idleMinutes: 30, absoluteHours: 12, maxConcurrent: 5 };
    const problems: string[] = [];
    const checkMax = (key: string, max: number, label: string): void => {
      const raw = env[key];
      if (raw === undefined) return;
      const n = Number.parseInt(raw, 10);
      if (!Number.isFinite(n) || n > max) problems.push(`${key}=${raw} exceeds the documented ${label} (${max})`);
    };
    checkMax('SESSION_IDLE_MINUTES', policy.idleMinutes, 'idle timeout in minutes');
    checkMax('SESSION_ABSOLUTE_HOURS', policy.absoluteHours, 'absolute timeout in hours');
    checkMax('SESSION_MAX_CONCURRENT', policy.maxConcurrent, 'maximum concurrent sessions');
    return { passed: problems.length === 0, summary: problems.length === 0 ? 'Session timeouts are within the documented policy.' : problems.join('; '), file: '.env' };
  },
};

function expandProtectedPaths(ctx: ScanContext): string[] {
  const patterns = ctx.manifest?.protectedPaths ?? [];
  if (patterns.length === 0) return [];
  const positive = patterns.filter((p) => !p.startsWith('!')).map(globToRegex);
  const negative = patterns.filter((p) => p.startsWith('!')).map((p) => globToRegex(p.slice(1)));
  const files = listAppFiles(ctx.appDir, ctx.ignore);
  return files.map((f) => f.relPath).filter((p) => positive.some((re) => re.test(p)) && !negative.some((re) => re.test(p)));
}

export const protectedFilesUnchanged: ConfigCheckDef = {
  meta: meta({
    id: 'config.protected-files-unchanged',
    title: 'Protected files differ from the template',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-693'],
    asvs: ['V15.2.3'],
    aisvs: ['AC.4.4'],
    sbd: ['MT-03'],
    exploitability: 'theoretical',
    description: 'One or more protected files (security modules, config, security tests, manifest, package files) do not match the hashes recorded at scaffold time.',
    impact: 'A control may have been weakened, and the compliance report can no longer credit template controls for those files.',
    fix: 'Restore the changed files from the template or review each change deliberately, then re-run verification.',
    references: ['https://owasp.org/www-project-secure-by-design-framework/'],
  }),
  run: (ctx) => {
    const hashes = ctx.provenance?.protectedFileHashes;
    if (!hashes) return { passed: false, summary: 'No provenance record was found to verify protected files against.' };
    const paths = expandProtectedPaths(ctx);
    const problems: string[] = [];
    for (const relPath of paths) {
      // Apps built before this was fixed still carry the provenance file's own hash in their record, and it can
      // never match: writing the hash in changes the file. Skipping it here as well as at the point it is
      // recorded means those apps stop reporting it without needing to be built again.
      if (relPath === NOT_SELF_HASHABLE) continue;
      const expected = hashes[relPath];
      if (!expected) continue; // not every protected path is necessarily tracked individually
      const actual = sha256File(join(ctx.appDir, relPath));
      if (actual !== expected) problems.push(`${relPath} ${actual === undefined ? 'is missing' : 'was modified'}`);
    }
    return { passed: problems.length === 0, summary: problems.length === 0 ? `${paths.length} protected files match their recorded hashes.` : problems.join('; ') };
  },
};

export const provenancePresent: ConfigCheckDef = {
  meta: meta({
    id: 'config.provenance-present',
    title: 'Provenance record is missing',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-1059'],
    asvs: [],
    aisvs: ['AC.10.1', 'AC.7.1'],
    sbd: ['MT-05'],
    exploitability: 'theoretical',
    description: 'securevibe.provenance.json is missing or unreadable.',
    impact: 'You cannot tell which files were AI-generated, by which model and in which run, which breaks the audit trail.',
    fix: 'Re-run the build so SecureVibe writes provenance; do not edit the file by hand.',
    references: ['https://owasp.org/www-project-ai-security-verification-standard/'],
  }),
  run: (ctx) => {
    const parsed = readJson<unknown>(ctx, 'securevibe.provenance.json');
    return { passed: parsed !== undefined, summary: parsed !== undefined ? 'securevibe.provenance.json is present and readable.' : 'securevibe.provenance.json is missing or is not valid JSON.', file: 'securevibe.provenance.json' };
  },
};

export const bindLoopbackDefault: ConfigCheckDef = {
  meta: meta({
    id: 'config.bind-loopback-default',
    title: 'App listens on all network interfaces without TLS',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-668'],
    asvs: ['V12.2.1'],
    aisvs: [],
    sbd: ['AS-01', 'AC-01'],
    exploitability: 'requires-network-exposure',
    description: 'BIND_LAN=1 is set while TLS_MODE=off, so the app accepts plain-HTTP connections from other computers on the network.',
    impact: 'Anyone on the same network can reach the app, and their traffic (including passwords) is not encrypted.',
    fix: 'Either remove BIND_LAN, or keep it and set TLS_MODE=selfsigned (npm run gen-cert) or put the app behind a TLS proxy.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const env = readEnv(ctx) ?? {};
    const lan = env['BIND_LAN'] === '1';
    const tlsOff = (env['TLS_MODE'] ?? 'off') === 'off';
    const problem = lan && tlsOff;
    return { passed: !problem, summary: problem ? 'BIND_LAN=1 with TLS_MODE=off: the app is reachable over the network without encryption.' : 'The app is not exposed to the network without TLS.', file: '.env' };
  },
};

export const securityMdPresent: ConfigCheckDef = {
  meta: meta({
    id: 'config.security-md-present',
    title: 'docs/SECURITY.md is missing',
    severity: 'low',
    confidence: 'high',
    cwe: ['CWE-1059'],
    asvs: ['V6.1.1'],
    aisvs: [],
    sbd: ['MT-06'],
    exploitability: 'theoretical',
    description: 'The security policy document (contact, disclosure process) is missing.',
    impact: 'People who find a problem do not know whom to tell.',
    fix: 'Run npm run docs:build in the app folder.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const exists = existsSync(join(ctx.appDir, 'docs/SECURITY.md'));
    return { passed: exists, summary: exists ? 'docs/SECURITY.md is present.' : 'docs/SECURITY.md was not found.', file: 'docs/SECURITY.md' };
  },
};

export const readmeRunInstructions: ConfigCheckDef = {
  meta: meta({
    id: 'config.readme-run-instructions',
    title: 'README lacks run instructions',
    severity: 'info',
    confidence: 'medium',
    cwe: ['CWE-1059'],
    asvs: [],
    aisvs: [],
    sbd: ['MT-05'],
    exploitability: 'theoretical',
    description: 'README.md does not describe how to set up and run the app safely.',
    impact: 'Someone may skip the setup step that generates secrets and creates the first administrator.',
    fix: 'Add the steps: npm install, npm run setup, npm start.',
    references: ['https://owasp.org/www-project-secure-by-design-framework/'],
  }),
  run: (ctx) => {
    const text = read(ctx, 'README.md') ?? '';
    const hasSetup = /npm run setup/.test(text);
    const hasStart = /npm start/.test(text);
    const ok = hasSetup && hasStart;
    return { passed: ok, summary: ok ? 'README.md documents the setup and start commands.' : 'README.md does not mention both "npm run setup" and "npm start".', file: 'README.md' };
  },
};

export const packageJsonUnmodified: ConfigCheckDef = {
  meta: meta({
    id: 'config.package-json-unmodified',
    title: 'package.json was modified',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-1104'],
    asvs: ['V15.1.2'],
    aisvs: ['AC.13.3'],
    sbd: ['RR-01'],
    exploitability: 'theoretical',
    description: 'package.json differs from the tested template version (new dependencies or changed scripts).',
    impact: 'New packages were not reviewed or locked; changed scripts may disable checks or enable debug flags.',
    fix: 'Restore package.json from the template and implement the feature with allowed modules only.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html'],
  }),
  run: (ctx) => {
    const expected = ctx.provenance?.protectedFileHashes['package.json'];
    if (!expected) return { passed: false, summary: 'No provenance record was found to verify package.json against.', file: 'package.json' };
    const actual = sha256File(join(ctx.appDir, 'package.json'));
    const ok = actual === expected;
    return { passed: ok, summary: ok ? 'package.json matches the recorded hash.' : 'package.json does not match the hash recorded at scaffold time.', file: 'package.json' };
  },
};

export const CONFIG_CHECKS: ConfigCheckDef[] = [
  envExamplePresent,
  gitignoreCoversEnv,
  secretsStrength,
  noDefaultAdmin,
  nodeEnginePinned,
  lockfilePresent,
  ignoreScripts,
  noDebugFlags,
  exampleFeatureDisabled,
  testModeNotInEnv,
  tlsModeConsistent,
  trustProxyHops,
  sessionPolicy,
  protectedFilesUnchanged,
  provenancePresent,
  bindLoopbackDefault,
  securityMdPresent,
  readmeRunInstructions,
  packageJsonUnmodified,
];
