/** "What only you can do" comes from facts: an empty setting, a service without an address, a feature not built. */
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DesignProfileSchema, type DesignProfile } from '@shared/profile.js';
import { emptyEnvKeys, ownerTasks } from '../../src/pipeline/owner-tasks.js';
import { habitTracker } from '../fixtures/design/profiles.js';

function appWithEnv(env: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'sv-owner-tasks-'));
  writeFileSync(join(dir, '.env'), env);
  return dir;
}

function profileWith(patch: Partial<DesignProfile['capabilities']>): DesignProfile {
  return DesignProfileSchema.parse({ ...habitTracker, capabilities: { ...habitTracker.capabilities, ...patch } });
}

describe('what only you can do', () => {
  it('is empty for an app whose answers ask for nothing that needs the owner', () => {
    const appDir = appWithEnv('SMTP_URL=\nMAIL_FROM=\n');
    expect(ownerTasks({ profile: habitTracker, appDir, planCoverage: [{ featureId: 'F1', title: 'Notes', status: 'built', evidence: 'Found.' }] })).toEqual([]);
  });

  it('names the empty mail settings when email was asked for, and what stays off', () => {
    const appDir = appWithEnv('SMTP_URL=\nMAIL_FROM=owner@example.com\n');
    const tasks = ownerTasks({ profile: profileWith({ email: true }), appDir });
    expect(tasks.map((t) => t.id)).toEqual(['setting-email']);
    expect(tasks[0]!.staysOff).toMatch(/file in its data folder/);
    // Filled in: nothing to do.
    expect(ownerTasks({ profile: profileWith({ email: true }), appDir: appWithEnv('SMTP_URL=smtp://x\nMAIL_FROM=a@b\n') })).toEqual([]);
    // A key that is not in the file at all is as empty as one left blank: the first version of this check was
    // caught treating "missing" as "set" by exactly one assertion, so this case is now its own witness.
    expect(ownerTasks({ profile: profileWith({ email: true }), appDir: appWithEnv('PORT=3000\n') }).map((t) => t.id)).toEqual(['setting-email']);
  });

  it('never copies a value out of .env, only whether a key is empty', () => {
    const appDir = appWithEnv('SMTP_URL=smtp://user:hunter2@mail.example\nMAIL_FROM=\nSESSION_SECRET=verysecretvalue\n');
    expect(emptyEnvKeys(appDir, ['SMTP_URL', 'MAIL_FROM', 'MISSING'])).toEqual(new Set(['MAIL_FROM', 'MISSING']));
    const text = JSON.stringify(ownerTasks({ profile: profileWith({ email: true }), appDir }));
    expect(text).not.toContain('hunter2');
    expect(text).not.toContain('verysecretvalue');
  });

  it('asks for an outside service address, or a key, or the allowed-hosts setting, from the answers', () => {
    const noAddress = profileWith({ externalApis: [{ name: 'Weather', purpose: 'forecasts', sendsPersonalData: false, host: '', credentials: 'have' }] });
    expect(ownerTasks({ profile: noAddress, appDir: appWithEnv('') }).map((t) => t.id)).toEqual(['service-address-weather']);

    const noKey = profileWith({ externalApis: [{ name: 'Weather', purpose: 'forecasts', sendsPersonalData: false, host: 'api.weather.example', credentials: 'not-yet' }] });
    const tasks = ownerTasks({ profile: noKey, appDir: appWithEnv('OUTBOUND_ALLOWED_HOSTS=api.weather.example\n') });
    expect(tasks.map((t) => t.id)).toEqual(['service-key-weather']);
    expect(tasks[0]!.because).toMatch(/do not have a key/);

    const listEmpty = ownerTasks({ profile: profileWith({ externalApis: noKey.capabilities.externalApis.map((a) => ({ ...a, credentials: 'have' as const })) }), appDir: appWithEnv('OUTBOUND_ALLOWED_HOSTS=\n') });
    expect(listEmpty.map((t) => t.id)).toEqual(['service-allow-weather']);
    expect(listEmpty[0]!.title).toContain('api.weather.example');
  });

  it('names the virus scanner as something the owner keeps running when the app takes uploads', () => {
    // ADR-011: uploads are refused without a scanner, and SecureVibe's fence keeps its own checks from ever
    // showing a scan, so the dependency is the owner's to keep, like an outside service.
    const withUploads = profileWith({ fileUploads: true });
    const on = ownerTasks({ profile: withUploads, appDir: appWithEnv('MALWARE_SCANNER=clamd\n') });
    expect(on.map((t) => t.id)).toEqual(['setting-malware-scanner']);
    expect(on[0]!.staysOff).toMatch(/every upload is refused/);
    expect(on[0]!.staysOff).toMatch(/never a scan/);
    // The default (nothing set) is the daemon on this machine, so the dependency stands; "off" means no uploads at all.
    expect(ownerTasks({ profile: withUploads, appDir: appWithEnv('') }).map((t) => t.id)).toEqual(['setting-malware-scanner']);
    expect(ownerTasks({ profile: withUploads, appDir: appWithEnv('MALWARE_SCANNER=off\n') })).toEqual([]);
    expect(ownerTasks({ profile: habitTracker, appDir: appWithEnv('MALWARE_SCANNER=clamd\n') })).toEqual([]);
  });

  it('turns a feature that came back not built into something to try, with the evidence', () => {
    const tasks = ownerTasks({
      profile: habitTracker,
      appDir: appWithEnv(''),
      planCoverage: [
        { featureId: 'F1', title: 'Notes', status: 'built', evidence: 'Found.' },
        { featureId: 'F2', title: 'Charts', status: 'files-in-place', evidence: 'The page exists; no test showed it draws anything.' },
        { featureId: 'F3', title: 'Export', status: 'not-built', evidence: 'No page or record was found.' },
        { featureId: 'F4', title: 'Sharing', status: 'left-out', evidence: 'Left out at your request.' },
      ],
    });
    expect(tasks.map((t) => t.id)).toEqual(['feature-F2', 'feature-F3']);
    expect(tasks[0]!.because).toContain('no test showed it draws anything');
    expect(tasks[1]!.staysOff).toMatch(/does not exist in the app/);
  });
});
