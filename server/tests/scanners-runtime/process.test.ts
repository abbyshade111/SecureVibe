/**
 * The process sandbox (CONTRACTS §9.3): what every child process SecureVibe starts for a generated app goes
 * through. The behavior that matters here is the behavior the reports depend on — a run that cannot be stopped,
 * an output that fills memory, or a silent loss of the file-system restriction would all be reported dishonestly.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_OUTPUT_BYTES,
  TRUNCATED_MARKER,
  buildChildEnv,
  detectPermissionSupport,
  killProcessGroup,
  resetPermissionDetection,
  resolveNpm,
  runNode,
  runNpm,
  spawnSandboxed,
  sweepStalePids,
} from '../../src/pipeline/process.js';

let projectDir: string;

beforeEach(() => {
  projectDir = mkdtempSync(join(tmpdir(), 'securevibe-process-'));
});

afterEach(() => {
  resetPermissionDetection();
  rmSync(projectDir, { recursive: true, force: true });
});

describe('runNode', () => {
  it('captures stdout, stderr and the exit code', async () => {
    const result = await runNode(['-e', 'process.stdout.write("out");process.stderr.write("err");process.exit(3)'], {
      cwd: projectDir,
      projectDir,
    });
    expect(result.stdout).toBe('out');
    expect(result.stderr).toBe('err');
    expect(result.code).toBe(3);
    expect(result.timedOut).toBe(false);
  });

  it('kills the whole process group when the time limit is reached', async () => {
    const started = Date.now();
    const result = await runNode(['-e', 'setInterval(() => {}, 1000)'], { cwd: projectDir, projectDir, timeoutMs: 700 });
    expect(result.timedOut).toBe(true);
    expect(result.code === null || result.code !== 0).toBe(true);
    expect(Date.now() - started).toBeLessThan(20_000);
    expect(result.warnings.join(' ')).toMatch(/time limit/);
  }, 30_000);

  it('kills grandchildren too, so a stray server cannot outlive the run', async () => {
    const marker = join(projectDir, 'grandchild.pid');
    const script = `
      const { spawn } = require('node:child_process');
      const fs = require('node:fs');
      const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
      fs.writeFileSync(${JSON.stringify(marker)}, String(child.pid));
      setInterval(() => {}, 1000);
    `;
    const result = await runNode(['-e', script], { cwd: projectDir, projectDir, timeoutMs: 1500 });
    expect(result.timedOut).toBe(true);
    const grandchild = Number(readFileSync(marker, 'utf8'));
    // Give the signal a moment to land on the whole group.
    await new Promise((r) => setTimeout(r, 300));
    let alive = true;
    try {
      process.kill(grandchild, 0);
    } catch {
      alive = false;
    }
    if (alive) killProcessGroup(grandchild);
    expect(alive).toBe(false);
  }, 30_000);

  it('caps the captured output and marks it as truncated', async () => {
    const result = await runNode(['-e', 'for (let i = 0; i < 5000; i++) process.stdout.write("x".repeat(100))'], {
      cwd: projectDir,
      projectDir,
      maxOutputBytes: 1000,
    });
    expect(result.truncated).toBe(true);
    expect(result.stdout.length).toBeLessThan(1000 + TRUNCATED_MARKER.length + 200);
    expect(result.stdout).toContain('[truncated]');
  }, 30_000);

  it('uses a generous default output cap', () => {
    expect(DEFAULT_MAX_OUTPUT_BYTES).toBeGreaterThanOrEqual(1024 * 1024);
  });

  it('stops a child when the run is aborted', async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 300);
    const result = await runNode(['-e', 'setInterval(() => {}, 1000)'], { cwd: projectDir, projectDir, abort: controller.signal });
    expect(result.aborted).toBe(true);
  }, 30_000);

  it('does not hang when the command cannot be started', async () => {
    const proc = spawnSandboxed({ cmd: 'node', args: ['--this-flag-does-not-exist'], cwd: projectDir, projectDir, timeoutMs: 10_000 });
    const result = await proc.wait();
    expect(result.code).not.toBe(0);
  }, 30_000);
});

describe('the environment handed to a child', () => {
  it('passes only the allow-list plus the caller variables, and never ANTHROPIC_*', () => {
    process.env['SECUREVIBE_PROCESS_TEST_SECRET'] = 'must-not-leak';
    process.env['ANTHROPIC_API_KEY'] = 'sk-ant-must-not-leak';
    try {
      const { env, home, tmp } = buildChildEnv({ projectDir, cwd: projectDir, cmd: 'node', env: { APP_FLAG: '1', ANTHROPIC_API_KEY: 'nope' } });
      expect(env['APP_FLAG']).toBe('1');
      expect(env['PATH']).toBeTruthy();
      expect(env['HOME']).toBe(home);
      expect(env['TMPDIR']).toBe(tmp);
      expect(env['SECUREVIBE_PROCESS_TEST_SECRET']).toBeUndefined();
      expect(env['ANTHROPIC_API_KEY']).toBeUndefined();
      expect(existsSync(home)).toBe(true);
      expect(existsSync(tmp)).toBe(true);
    } finally {
      delete process.env['SECUREVIBE_PROCESS_TEST_SECRET'];
      delete process.env['ANTHROPIC_API_KEY'];
    }
  });

  it('really keeps the parent environment out of the child process', async () => {
    process.env['SECUREVIBE_PROCESS_TEST_SECRET'] = 'must-not-leak';
    try {
      const result = await runNode(['-e', 'process.stdout.write(String(process.env.SECUREVIBE_PROCESS_TEST_SECRET))'], {
        cwd: projectDir,
        projectDir,
      });
      expect(result.stdout).toBe('undefined');
    } finally {
      delete process.env['SECUREVIBE_PROCESS_TEST_SECRET'];
    }
  }, 30_000);
});

describe('the Node permission model', () => {
  it('detects whether this Node accepts --permission', () => {
    expect(typeof detectPermissionSupport()).toBe('boolean');
  });

  it('confines writes to the allowed folders when the permission model is available', async () => {
    if (!detectPermissionSupport()) return; // reported as sandboxMode 'none' below instead
    const allowed = join(projectDir, 'allowed');
    mkdirSync(allowed, { recursive: true });
    const forbidden = join(projectDir, 'forbidden');
    mkdirSync(forbidden, { recursive: true });
    const script = `
      const fs = require('node:fs');
      try { fs.writeFileSync(${JSON.stringify(join(allowed, 'ok.txt'))}, 'ok'); process.stdout.write('wrote-allowed '); }
      catch (e) { process.stdout.write('allowed-denied '); }
      try { fs.writeFileSync(${JSON.stringify(join(forbidden, 'bad.txt'))}, 'bad'); process.stdout.write('wrote-forbidden'); }
      catch (e) { process.stdout.write('forbidden-denied:' + e.code); }
    `;
    const result = await runNode(['-e', script], {
      cwd: projectDir,
      projectDir,
      permission: { read: [projectDir], write: [allowed] },
    });
    // With the OS network fence available the mode says so; without it, the permission model alone.
    expect(['node-permission-model', 'node-permission-model+loopback-only']).toContain(result.sandboxMode);
    expect(result.stdout).toContain('wrote-allowed');
    expect(result.stdout).toContain('forbidden-denied');
    expect(existsSync(join(forbidden, 'bad.txt'))).toBe(false);
  }, 30_000);

  it('falls back to running unsandboxed with a recorded warning when the flag is not accepted', async () => {
    resetPermissionDetection(false);
    const result = await runNode(['-e', 'process.stdout.write("ran")'], {
      cwd: projectDir,
      projectDir,
      permission: { read: [projectDir], write: [projectDir] },
    });
    expect(result.stdout).toBe('ran');
    expect(result.sandboxMode).toBe('none');
    expect(result.warnings.join(' ')).toMatch(/permission model/i);
  }, 30_000);

  it('asks for the permission flags only when the caller wants them', async () => {
    const result = await runNode(['-e', 'process.stdout.write(JSON.stringify(process.execArgv))'], { cwd: projectDir, projectDir });
    expect(result.stdout).not.toContain('--permission');
    expect(result.sandboxMode).toBe('none');
  }, 30_000);
});

describe('npm', () => {
  it('resolves npm next to the running Node, or falls back to PATH', () => {
    const npm = resolveNpm();
    expect(['node-script', 'path']).toContain(npm.kind);
    if (npm.kind === 'node-script') expect(existsSync(npm.script)).toBe(true);
  });

  it('runs npm without a shell', async () => {
    const result = await runNpm(['--version'], { cwd: projectDir, projectDir, timeoutMs: 60_000 });
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
    expect(result.code).toBe(0);
  }, 90_000);
});

describe('pid files', () => {
  it('writes a pid file while a child runs and removes it afterwards', async () => {
    const pidDir = join(projectDir, 'pipeline', 'run-1');
    const proc = spawnSandboxed({ cmd: 'node', args: ['-e', 'setTimeout(() => {}, 400)'], cwd: projectDir, projectDir, pidDir, timeoutMs: 10_000 });
    expect(readdirSync(pidDir).filter((f) => f.endsWith('.pid'))).toHaveLength(1);
    await proc.wait();
    expect(readdirSync(pidDir).filter((f) => f.endsWith('.pid'))).toHaveLength(0);
  }, 30_000);

  it('sweeps pid files that an earlier crash left behind', () => {
    const pidDir = join(projectDir, 'pipeline', 'run-2');
    mkdirSync(pidDir, { recursive: true });
    writeFileSync(join(pidDir, '999999.pid'), JSON.stringify({ pid: 999999, command: 'node app.js', startedAt: new Date().toISOString() }));
    writeFileSync(join(pidDir, 'broken.pid'), 'not json');
    const swept = sweepStalePids(pidDir);
    expect(swept).toHaveLength(2);
    expect(readdirSync(pidDir)).toEqual([]);
  });

  it('returns nothing for a folder that does not exist', () => {
    expect(sweepStalePids(join(projectDir, 'nope'))).toEqual([]);
  });
});
