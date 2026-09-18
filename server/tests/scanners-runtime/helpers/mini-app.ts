/**
 * Builds a ProbeContext around the fixture app (server/tests/fixtures/scanners-runtime/mini-app) running inside
 * the test process, so the probes and the runner can be exercised without binding a listening socket.
 */
import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BuildSpec } from '@shared/design.js';
import { buildProbeContext, type DastContextBuild } from '../../../src/scanners/dast/runner.js';
import { base32Encode } from '../../../src/scanners/dast/totp.js';
import type { AppInstance, ProbePhase } from '../../../src/scanners/dast/types.js';
import { LoopbackHttpClient } from './loopback.js';

// The fixture app is plain JavaScript with a hand-written .d.ts beside it.
import { createApp } from '../../fixtures/scanners-runtime/mini-app/src/app.js';

export const MINI_APP_DIR = fileURLToPath(new URL('../../fixtures/scanners-runtime/mini-app/', import.meta.url));

export const TEST_PASSWORD = 'probe-password-0123456789';

export function buildSpecFor(overrides: Partial<BuildSpec['features']> = {}): BuildSpec {
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
    packageName: 'mini-app',
    sessionPolicy: { idleMinutes: 30, absoluteHours: 12, maxConcurrent: 5 },
    brief: 'Fixture application for the runtime scanner tests.',
  };
}

export interface MiniAppHandle extends DastContextBuild {
  client: LoopbackHttpClient;
  env: Record<string, string>;
  logs: string[];
  close(): void;
}

export interface StartMiniAppOptions {
  phase?: ProbePhase;
  tlsMode?: 'off' | 'proxy' | 'selfsigned';
  trustProxyHops?: number;
  buildSpec?: BuildSpec;
  extraEnv?: Record<string, string>;
}

/** Creates a fresh fixture app plus the ProbeContext the probes receive. */
export async function startMiniApp(opts: StartMiniAppOptions = {}): Promise<MiniAppHandle> {
  const phase = opts.phase ?? 'test';
  const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-mini-'));
  const env: Record<string, string> = {
    NODE_ENV: phase === 'test' ? 'test' : 'production',
    DATA_DIR: dataDir,
    TLS_MODE: opts.tlsMode ?? (phase === 'test' ? 'off' : 'proxy'),
    TRUST_PROXY_HOPS: String(opts.trustProxyHops ?? (phase === 'test' ? 0 : 1)),
    SECUREVIBE_TEST_PASSWORD: TEST_PASSWORD,
    SECUREVIBE_TEST_TOTP_SEED: base32Encode(randomBytes(20)),
    ...(phase === 'test' ? { SECUREVIBE_TEST_MODE: '1' } : {}),
    ...(opts.extraEnv ?? {}),
  };

  const app = createApp(env);
  const client = new LoopbackHttpClient(app);
  const logs: string[] = [];

  const instance: AppInstance = {
    phase,
    baseUrl: client.baseUrl,
    port: 8080,
    pid: process.pid,
    dataDir,
    env,
    tlsMode: (env['TLS_MODE'] as AppInstance['tlsMode']) ?? 'off',
    sandboxMode: 'none',
    output: () => ({ stdout: '', stderr: '' }),
    stop: async () => {},
  };

  const built = await buildProbeContext({
    app: instance,
    appDir: MINI_APP_DIR,
    buildSpec: opts.buildSpec ?? buildSpecFor(),
    auth: undefined,
    http: client,
    log: (msg) => logs.push(msg),
  });

  return { ...built, client, env, logs, close: () => client.close() };
}
