/**
 * Starts the fixture app and prints the one ready line the DAST harness waits for (CONTRACTS §1.16).
 * The app itself lives in app.js so the scanner's own tests can drive it inside the test process.
 */
import { createApp } from './app.js';

const PORT = Number(process.env.PORT ?? 0);
const TEST_MODE = process.env.NODE_ENV === 'test' && process.env.SECUREVIBE_TEST_MODE === '1';
const TLS_MODE = process.env.TLS_MODE ?? 'off';

const app = createApp(process.env);

const server = app.listen(PORT, '127.0.0.1', () => {
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : PORT;
  if (TEST_MODE) {
    process.stdout.write(`${JSON.stringify({ securevibe: 'listening', port, pid: process.pid, tlsMode: TLS_MODE })}\n`);
  } else {
    process.stdout.write(`listening on ${port}\n`);
  }
});

server.headersTimeout = 10_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;

server.on('error', (err) => {
  process.stderr.write(`could not listen: ${err.message}\n`);
  process.exit(1);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
