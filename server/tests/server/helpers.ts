/** Shared test scaffolding for the server module: a throw-away workspace, a wired-up `createApp`, and a session cookie. */
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Express } from 'express';
import { createApp, type AppDeps } from '../../src/app.js';
import { loadConfig, type SecureVibeConfig } from '../../src/config.js';
import { loadFrameworks, loadKnowledge, createProvider, type LlmProvider } from '../../src/integration.js';
import { RunBusRegistry } from '../../src/pipeline/bus.js';
import { createLogger } from '../../src/security/logger.js';
import { SessionManager } from '../../src/security/token.js';
import { ProjectStore } from '../../src/store/index.js';

export interface TestHarness {
  app: Express;
  /** Already listening on 127.0.0.1 with an ephemeral port — pass this (not `app`) to supertest's `request()`, since
   * the sandbox this runs in refuses a bind to 0.0.0.0, which is what supertest defaults to when given a bare app. */
  server: Server;
  config: SecureVibeConfig;
  sessions: SessionManager;
  store: ProjectStore;
  deps: AppDeps;
  cleanup(): void;
}

export async function buildHarness(opts: { port?: number; provider?: LlmProvider; logLines?: Record<string, unknown>[] } = {}): Promise<TestHarness> {
  const home = mkdtempSync(join(tmpdir(), 'securevibe-test-'));
  const env = { ...process.env, SECUREVIBE_HOME: home, SECUREVIBE_PORT: String(opts.port ?? 4173) };
  const config = loadConfig(env);
  const sessions = new SessionManager({ token: 'test-token-0123456789abcdef0123456789abcdef' });
  const store = new ProjectStore(config.paths.home);
  const knowledge = loadKnowledge();
  const frameworks = loadFrameworks();
  const busRegistry = new RunBusRegistry();
  // With `logLines`, log entries at the default level are collected there (parsed), so tests can check what is recorded.
  const logLines = opts.logLines;
  const logger = logLines
    ? createLogger({
        destination: { write: (line: string) => void logLines.push(JSON.parse(line) as Record<string, unknown>) } as unknown as NodeJS.WritableStream,
      })
    : createLogger({ silent: true });
  const provider = opts.provider ?? createProvider({ forceProvider: 'null' });

  const deps: AppDeps = { config, sessions, logger, store, knowledge, frameworks, getProvider: () => provider, busRegistry };
  const app = createApp(deps);
  const server = createServer(app);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

  return {
    app,
    server,
    config,
    sessions,
    store,
    deps,
    cleanup: () => {
      server.close();
      rmSync(home, { recursive: true, force: true });
    },
  };
}

/** Exchanges the harness's fixed startup token for a session cookie + CSRF token, as a browser would. */
export async function signIn(harness: TestHarness): Promise<{ cookie: string; csrfToken: string }> {
  const request = (await import('supertest')).default;
  const tokenRes = await request(harness.server).get(`/auth/token?t=${harness.sessions.startupToken}`).set('Host', '127.0.0.1');
  const setCookie = tokenRes.headers['set-cookie'];
  const cookie = Array.isArray(setCookie) ? setCookie[0]! : (setCookie as unknown as string);
  const statusRes = await request(harness.server).get('/api/status').set('Host', '127.0.0.1').set('Cookie', cookie);
  return { cookie, csrfToken: statusRes.body.csrfToken as string };
}
