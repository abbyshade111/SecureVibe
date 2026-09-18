/**
 * Process entry point: opens the database, applies migrations, checks the password hashing algorithm, builds
 * the app and listens on 127.0.0.1 (or all interfaces with BIND_LAN=1). Timeouts protect against slow clients,
 * and SIGINT/SIGTERM trigger a graceful shutdown that closes connections and the database.
 */
import { existsSync, readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { Socket } from 'node:net';
import { resolve } from 'node:path';
import { APP_ROOT, config } from './config.ts';
import { closeDb, openDb } from './db/index.ts';
import { runMigrations } from './db/migrate.ts';
import { createApp } from './app.ts';
import { logger } from './lib/logger.ts';
import { seedTestData } from './lib/test-mode.ts';
import { pruneAudit } from './security/audit.ts';
import { emit } from './security/events.ts';
import { activeAlgorithm, assertStoredHashesSupported } from './security/password.ts';
import { cleanupSessions } from './security/session.ts';

export const HEADERS_TIMEOUT_MS = 10_000;
export const REQUEST_TIMEOUT_MS = 30_000;
/** With web search on, an assistant answer legitimately takes longer than an ordinary page. */
export const SEARCH_REQUEST_TIMEOUT_MS = 120_000;
export const KEEP_ALIVE_TIMEOUT_MS = 5_000;
const SHUTDOWN_GRACE_MS = 10_000;
const MAINTENANCE_INTERVAL_MS = 10 * 60_000;

function tlsOptions(): https.ServerOptions {
  const keyFile = resolve(APP_ROOT, 'certs', 'key.pem');
  const certFile = resolve(APP_ROOT, 'certs', 'cert.pem');
  if (!existsSync(keyFile) || !existsSync(certFile)) {
    throw new Error('TLS_MODE=selfsigned needs certs/key.pem and certs/cert.pem. Run "npm run gen-cert" first.');
  }
  return {
    key: readFileSync(keyFile),
    cert: readFileSync(certFile),
    minVersion: 'TLSv1.2',
    ciphers: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_GCM_SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
    ].join(':'),
    honorCipherOrder: true,
  };
}

/**
 * A connection has HEADERS_TIMEOUT_MS to deliver a complete set of request headers, otherwise it is dropped.
 * Node applies its own `headersTimeout` on a periodic sweep of the connection list; this timer is the explicit,
 * observable guarantee that a client which opens a socket and then stalls mid-request (a slowloris) cannot hold
 * the connection — and the socket is armed again after each response, for the next request on a kept-alive one.
 */
function enforceHeadersTimeout(server: http.Server): void {
  const timers = new WeakMap<Socket, NodeJS.Timeout>();
  const disarm = (socket: Socket): void => {
    const timer = timers.get(socket);
    if (timer) {
      clearTimeout(timer);
      timers.delete(socket);
    }
  };
  const arm = (socket: Socket): void => {
    disarm(socket);
    if (socket.destroyed) return;
    const timer = setTimeout(() => {
      timers.delete(socket);
      if (!socket.destroyed) socket.destroy();
    }, HEADERS_TIMEOUT_MS);
    timer.unref();
    timers.set(socket, timer);
  };
  // For TLS the timer starts once the handshake is done, so it measures the same thing in both modes: the time a
  // client may take to send request headers.
  const connectionEvent = config.TLS_MODE === 'selfsigned' ? 'secureConnection' : 'connection';
  server.on(connectionEvent, (socket: Socket) => {
    arm(socket);
    socket.once('close', () => disarm(socket));
  });
  const inFlight = new WeakMap<Socket, number>();
  server.on('request', (req, res) => {
    const socket = req.socket;
    disarm(socket);
    inFlight.set(socket, (inFlight.get(socket) ?? 0) + 1);
    res.on('finish', () => {
      const left = (inFlight.get(socket) ?? 1) - 1;
      inFlight.set(socket, left);
      // Only once nothing is in flight: the next request's headers get their own window.
      if (left <= 0) arm(socket);
    });
  });
}

export async function startServer(): Promise<http.Server> {
  openDb();
  const migrations = runMigrations();
  if (migrations.changedAfterApply.length > 0) {
    logger.warn({ files: migrations.changedAfterApply }, 'Some migration files changed after they were applied. Add a new migration instead of editing old ones.');
  }
  assertStoredHashesSupported();

  // Feature registration (inside createApp) is what populates the entity registry (registerEntity), so the app
  // must be built before test data is seeded — otherwise listEntities() is empty and no sample records are seeded.
  const app = await createApp();
  if (config.testMode) seedTestData();
  // Node enforces the header/request timeouts on a periodic sweep; a short interval makes the cut-off predictable.
  const timeouts = {
    headersTimeout: HEADERS_TIMEOUT_MS,
    // Raised only when the assistant may search the web; every other setting (headers, keep-alive) is unchanged.
    requestTimeout: config.aiWebSearch ? SEARCH_REQUEST_TIMEOUT_MS : REQUEST_TIMEOUT_MS,
    keepAliveTimeout: KEEP_ALIVE_TIMEOUT_MS,
    connectionsCheckingInterval: 2_000,
  };
  const server = config.TLS_MODE === 'selfsigned' ? https.createServer({ ...tlsOptions(), ...timeouts }, app) : http.createServer(timeouts, app);
  enforceHeadersTimeout(server);

  const host = config.BIND_LAN ? '0.0.0.0' : '127.0.0.1';
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(config.PORT, host, () => {
      server.off('error', reject);
      resolveListen();
    });
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : config.PORT;

  emit('config.startup', { algorithm: activeAlgorithm(), tlsMode: config.TLS_MODE, port, host });
  if (config.testMode) {
    process.stdout.write(`${JSON.stringify({ securevibe: 'listening', port, pid: process.pid, tlsMode: config.TLS_MODE })}\n`);
  } else {
    const scheme = config.TLS_MODE === 'selfsigned' ? 'https' : 'http';
    process.stdout.write(`${config.appName} is running at ${scheme}://${config.BIND_LAN ? 'localhost' : '127.0.0.1'}:${port}/\n`);
  }

  const maintenance = setInterval(() => {
    try {
      cleanupSessions();
      pruneAudit(config.AUDIT_RETENTION_DAYS);
    } catch (err) {
      logger.warn({ err: (err as Error).message }, 'maintenance task failed');
    }
  }, MAINTENANCE_INTERVAL_MS);
  maintenance.unref();

  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'shutting down');
    clearInterval(maintenance);
    const force = setTimeout(() => {
      logger.warn('forcing exit after grace period');
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    force.unref();
    server.close(() => {
      closeDb();
      process.exit(0);
    });
    server.closeIdleConnections();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  return server;
}

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(APP_ROOT, 'src', 'server.ts');
if (isMain) {
  startServer().catch((err: Error) => {
    process.stderr.write(`\nThe app could not start.\n${err.message}\n\n`);
    process.exit(1);
  });
}
