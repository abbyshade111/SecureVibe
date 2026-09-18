import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { externalArgs } from '../../src/scanners/external/index.js';

const appDir = mkdtempSync(join(tmpdir(), 'sv-ext-app-'));
const workDir = mkdtempSync(join(tmpdir(), 'sv-ext-work-'));
afterAll(() => {
  rmSync(appDir, { recursive: true, force: true });
  rmSync(workDir, { recursive: true, force: true });
});
const run = { appDir, workDir, reportFile: join(workDir, 'out.json'), exclude: ['node_modules', 'templates/**'] };

describe('extra scanner settings', () => {
  it('names semgrep rule sets and passes the folders SecureVibe leaves out', () => {
    const args = externalArgs('semgrep', { ...run, version: '1.176.0' });
    expect(args).toEqual(expect.arrayContaining(['--config', 'p/owasp-top-ten', '--metrics=off']));
    expect(args.join(' ')).toContain('--exclude node_modules --exclude templates');
  });

  it('lets trivy update its database and skips excluded folders and secret files', () => {
    const args = externalArgs('trivy', { ...run, version: '0.74.0' });
    expect(args).not.toContain('--skip-db-update');
    expect(args.join(' ')).toContain('--skip-dirs **/node_modules --skip-dirs templates');
    expect(args.join(' ')).toContain('--skip-files **/.env');
  });

  it('gives gitleaks a config that keeps its rules and skips folders, .env and hash files', () => {
    const args = externalArgs('gitleaks', { ...run, version: '8.30.1' });
    const config = readFileSync(args[args.indexOf('--config') + 1]!, 'utf8');
    expect(config).toContain('useDefault = true');
    expect(config).toContain('node_modules');
    expect(config).toContain('\\.env');
    expect(config).toContain('securevibe\\.provenance\\.json');
  });

  it('points osv-scanner at the lockfile, in the form its version expects', () => {
    writeFileSync(join(appDir, 'package-lock.json'), '{}');
    expect(externalArgs('osv-scanner', { ...run, version: '2.6.0' })).toEqual(['scan', 'source', '--format', 'json', '--lockfile', join(appDir, 'package-lock.json')]);
    expect(externalArgs('osv-scanner', { ...run, version: '1.9.0' })).toEqual(['--format', 'json', '--lockfile', join(appDir, 'package-lock.json')]);
  });
});
