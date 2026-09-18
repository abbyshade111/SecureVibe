/**
 * Entry point: load config, run preflight, sweep stale child processes, mark interrupted runs, start the server
 * on 127.0.0.1, print (and open) the one-time token URL, and shut down cleanly on SIGINT/SIGTERM.
 */
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { loadFrameworks, loadKnowledge } from './integration.js';
import { providerFactory } from './llm/active-provider.js';
import { removeDir, sweepStalePids } from './pipeline/process.js';
import { markInterruptedRunsAtStartup, reconcileProjectStatusAtStartup, RunBusRegistry, workerIsAlive } from './pipeline/index.js';
import { isRunId } from './store/ids.js';
import { runPreflight } from './api/preflight.js';
import { multistream, type Level } from 'pino';
import { createLogger } from './security/logger.js';
import { securityEventStream } from './security/event-log.js';
import { SessionManager } from './security/token.js';
import { ProjectStore, isProjectId } from './store/index.js';

function sweepAllProjectPids(store: ProjectStore): void {
  let projectIds: string[];
  try {
    projectIds = readdirSync(store.projectsDir).filter(isProjectId);
  } catch {
    return;
  }
  for (const projectId of projectIds) {
    // App previews left behind by a SecureVibe that did not shut down cleanly: stop them and drop their data.
    const tmpDir = join(store.projectsDir, projectId, 'tmp');
    try {
      for (const name of readdirSync(tmpDir).filter((n) => n.startsWith('preview-'))) {
        sweepStalePids(join(tmpDir, name));
        removeDir(join(tmpDir, name));
      }
    } catch {
      // no tmp folder
    }
    const pipelineDir = join(store.projectsDir, projectId, 'pipeline');
    let runIds: string[];
    try {
      runIds = readdirSync(pipelineDir);
    } catch {
      continue;
    }
    for (const runId of runIds) {
      // A live worker owns the processes under its run folder. (Other folders here, like the cache, are not runs.)
      if (isRunId(runId) && workerIsAlive(store, projectId, runId)) continue;
      sweepStalePids(join(pipelineDir, runId));
    }
  }
}

function openBrowser(url: string): void {
  const platform = process.platform;
  try {
    if (platform === 'darwin') spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    else if (platform === 'win32') spawn('cmd', ['/c', 'start', '""', url], { stdio: 'ignore', detached: true, windowsHide: true }).unref();
    else spawn('xdg-open', [url], { stdio: 'ignore', detached: true }).unref();
  } catch {
    // Printing the URL below is the fallback; a failure to launch a browser is never fatal.
  }
}

async function main(): Promise<void> {
  const config = loadConfig();
  // Everything goes to the terminal; security events are also kept on disk for the Dashboard.
  // The logger itself must pass info, so a quieter terminal setting does not drop security events.
  const quieterThanInfo = ['warn', 'error', 'fatal', 'silent'].includes(config.logLevel);
  const logger = createLogger({
    level: quieterThanInfo ? 'info' : config.logLevel,
    destination: multistream([
      { level: config.logLevel as Level, stream: process.stdout },
      { level: 'info', stream: securityEventStream(config.paths.securityEventsFile) },
    ]) as unknown as NodeJS.WritableStream,
  });
  const store = new ProjectStore(config.paths.home);

  const preflight = await runPreflight(config, { alreadyBound: false });
  const blocking = preflight.filter((c) => c.blocking && !c.ok);
  for (const check of preflight) {
    const line = `${check.ok ? 'ok' : check.blocking ? 'FAIL' : 'warn'}  ${check.title}: ${check.detail}`;
    if (check.ok) logger.info(line);
    else if (check.blocking) logger.error(line);
    else logger.warn(line);
  }
  if (blocking.length > 0) {
    process.stderr.write(`\nSecureVibe cannot start:\n${blocking.map((c) => `  - ${c.detail}`).join('\n')}\n\n`);
    process.exit(1);
  }

  sweepAllProjectPids(store);
  const interrupted = markInterruptedRunsAtStartup(store);
  // An app whose build finished shows as "built"; one left mid-build goes back to where it was.
  reconcileProjectStatusAtStartup(store);
  if (interrupted.length > 0) logger.info(`Marked ${interrupted.length} run(s) as interrupted from a previous session.`);

  const knowledge = loadKnowledge();
  const frameworks = loadFrameworks();
  const sessions = new SessionManager();
  const busRegistry = new RunBusRegistry();

  const app = createApp({
    config,
    sessions,
    logger,
    store,
    knowledge,
    frameworks,
    getProvider: providerFactory(config),
    busRegistry,
  });

  const server = app.listen(config.port, config.host, () => {
    const url = sessions.tokenUrl(config.host, config.port);
    if (config.testMode) {
      process.stdout.write(`${JSON.stringify({ securevibe: 'listening', port: config.port, pid: process.pid, url })}\n`);
    } else {
      process.stdout.write(`\nSecureVibe is ready.\n\nOpen this link in your browser (keep it private — it is the key to this session):\n\n  ${url}\n\n`);
    }
    if (config.openBrowser && !config.testMode) openBrowser(url);
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;

  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info(`Received ${signal}, shutting down…`);
    sweepAllProjectPids(store);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  process.stderr.write(`SecureVibe could not start: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
