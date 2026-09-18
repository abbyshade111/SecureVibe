#!/usr/bin/env node
/** `tsx src/cli/doctor.ts`: prints the same preflight checks the server runs at startup, for the terminal. */
import { runPreflight } from '../api/preflight.js';
import { loadConfig } from '../config.js';

async function main(): Promise<void> {
  const config = loadConfig();
  process.stdout.write(`SecureVibe doctor — checking this computer…\n\n`);
  const checks = await runPreflight(config, { alreadyBound: false });
  let hasBlockingFailure = false;
  for (const check of checks) {
    const mark = check.ok ? 'OK  ' : check.blocking ? 'FAIL' : 'WARN';
    process.stdout.write(`[${mark}] ${check.title}\n      ${check.detail}\n`);
    if (!check.ok && check.blocking) hasBlockingFailure = true;
  }
  process.stdout.write('\n');
  if (hasBlockingFailure) {
    process.stdout.write('SecureVibe cannot start until the FAIL items above are fixed.\n');
    process.exitCode = 1;
  } else {
    process.stdout.write('SecureVibe is ready to run. Start it with "npm start".\n');
  }
}

main().catch((err) => {
  process.stderr.write(`doctor failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exitCode = 1;
});
