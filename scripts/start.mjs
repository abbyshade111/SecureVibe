#!/usr/bin/env node
/**
 * `npm start` — builds the web app on first run, then starts the SecureVibe server.
 * Kept dependency-free so it works right after `npm install`.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const webDist = path.join(root, 'web', 'dist', 'index.html');
const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 13)) {
  console.error(`SecureVibe needs Node.js 22.13 or newer (you have ${process.versions.node}). Download it from https://nodejs.org`);
  process.exit(1);
}

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: root, stdio: 'inherit', shell: false, ...opts });
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} ${args.join(' ')} exited with ${code}`))));
    child.on('error', reject);
  });
}

// Packages may not run their own install scripts (see .npmrc), so esbuild — which tsx and vite both need — has to
// be rebuilt once by hand after `npm install`. Saying so here beats a stack trace from deep inside a build tool.
const esbuildBinary = path.join(root, 'node_modules', 'esbuild', 'bin', 'esbuild');
if (!existsSync(esbuildBinary)) {
  console.error('One build tool still needs setting up after installing. Run this once, then start again:\n\n  npm run rebuild-tools\n');
  process.exit(1);
}

if (!existsSync(webDist) || process.env.SECUREVIBE_REBUILD_WEB === '1') {
  console.log('Building the SecureVibe web app (first run only)…');
  await run(npmCmd, ['run', 'build', '-w', 'web']);
}

await run(npmCmd, ['run', 'start', '-w', 'server'], { env: { ...process.env } });
