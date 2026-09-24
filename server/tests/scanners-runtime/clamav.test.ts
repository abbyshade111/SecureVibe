/**
 * The virus scanner's adapter. These are all pure-function tests on the two things that decide whether the
 * result is honest: how ClamAV's exit code is read, and what the report says about the age of the signatures.
 */
import { describe, expect, it } from 'vitest';
import {
  clamavArgs,
  excludeRegex,
  parseClamavOutput,
  parseClamavVersion,
  readClamavExit,
  scanIsMandatory,
  signatureAgeInDays,
  signatureNote,
  runClamavScan,
  toClamavSeed,
} from '../../src/scanners/external/clamav.js';

describe('the virus scanner adapter', () => {
  it('reads the engine, the signature database and the date that database was built', () => {
    // Taken from the real binary on this machine on 20 September 2026, rather than invented: the shape of this
    // string is the only thing that tells a report how current a clean result is, so it is worth having a
    // fixture somebody actually saw rather than one that looks right.
    const v = parseClamavVersion('ClamAV 1.5.4/28129/Sun Sep 20 02:26:26 2026');
    expect(v.engine).toBe('1.5.4');
    expect(v.database).toBe('28129');
    expect(v.databaseDate?.getUTCFullYear()).toBe(2026);
    // An older build prints the engine on its own, and that must not be read as a date of any kind.
    expect(parseClamavVersion('ClamAV 0.103.11').databaseDate).toBeUndefined();
    expect(parseClamavVersion('something else entirely')).toEqual({});
  });

  it('says how old the signatures are, because a clean result means nothing without it', () => {
    const now = new Date('2026-09-20T12:00:00Z');
    const fresh = { databaseDate: new Date('2026-09-19T12:00:00Z') };
    expect(signatureAgeInDays(fresh, now)).toBe(1);
    expect(signatureNote(fresh, now)).toContain('yesterday');

    const stale = { databaseDate: new Date('2026-01-01T12:00:00Z') };
    expect(signatureAgeInDays(stale, now)).toBeGreaterThan(30);
    expect(signatureNote(stale, now)).toContain('means less than it looks');
    expect(signatureNote(stale, now)).toContain('freshclam');

    // Not knowing is said out loud rather than being left to look like freshness.
    expect(signatureNote({}, now)).toContain('unknown');
  });

  it('reads a clean run, a detection and a failure as three different things', () => {
    expect(readClamavExit(0, '', '')).toEqual({ kind: 'clean' });

    // Also real: this is what clamscan printed for the standard EICAR test file, which exists for this purpose.
    const found = readClamavExit(1, '/app/uploads/x.pdf: Eicar-Test-Signature FOUND', '', '/app');
    expect(found.kind).toBe('infected');
    expect(found.kind === 'infected' && found.detections).toEqual([{ file: 'uploads/x.pdf', signature: 'Eicar-Test-Signature' }]);

    const broken = readClamavExit(2, '', "ERROR: Can't connect to clamd through /var/run/clamav/clamd.sock");
    expect(broken.kind).toBe('error');
    // "could not be reached" rather than "not running": observed on this machine, a caller that is not allowed
    // to open the socket gets the same exit code as a daemon that was never started.
    expect(broken.kind === 'error' && broken.reason).toContain('could not be reached');
    expect(broken.kind === 'error' && broken.daemonUnreachable).toBe(true);

    const denied = readClamavExit(2, '', 'ERROR: Access denied');
    expect(denied.kind === 'error' && denied.reason).toContain('could not read the files');
  });

  it('recognizes the scanner that is installed but has no virus signatures yet', () => {
    // Taken from the real binary on 20 September 2026, immediately after "brew install clamav" and before
    // freshclam had ever run. Note the second line: ClamAV says it cannot open the file, when the truth is it
    // has no signatures. Anything reading the last line concludes the file was unreadable and moves on, which
    // is how an installed-but-useless scanner comes to look like a scanner that checked something.
    const stderr = [
      "LibClamAV Error: cli_loaddbdir: No supported database files found in /opt/homebrew/var/lib/clamav",
      "ERROR: Can't open file or directory",
    ].join('\n');
    const outcome = readClamavExit(2, '', stderr);
    expect(outcome.kind).toBe('error');
    expect(outcome.kind === 'error' && outcome.reason).toContain('has not downloaded its virus signatures');
    expect(outcome.kind === 'error' && outcome.reason).toContain('freshclam');
    // And emphatically not the access-denied reason, which would send someone fixing file permissions.
    expect(outcome.kind === 'error' && outcome.reason).not.toContain('could not read the files');
  });

  it('never reports a run it could not understand as clean', () => {
    // Exit 1 means ClamAV found something. If we cannot parse what, the honest answer is "we do not know",
    // and the one answer that must never come out of this branch is "clean".
    const unreadable = readClamavExit(1, 'some output we did not expect', '');
    expect(unreadable.kind).toBe('error');
    expect(unreadable.kind === 'error' && unreadable.reason).toContain('could not be read');
  });

  it('picks out only the FOUND lines, and leaves the rest of the output alone', () => {
    const output = [
      '/app/a.txt: OK',
      '/app/b.doc: Doc.Downloader.Emotet-9812345-0 FOUND',
      '/app/c: Access denied. ERROR',
      '/app/d.zip: Win.Trojan.Agent-1234 FOUND',
      '----------- SCAN SUMMARY -----------',
      'Infected files: 2',
    ].join('\n');
    expect(parseClamavOutput(output, '/app')).toEqual([
      { file: 'b.doc', signature: 'Doc.Downloader.Emotet-9812345-0' },
      { file: 'd.zip', signature: 'Win.Trojan.Agent-1234' },
    ]);
  });

  it('hands the daemon a file descriptor, because otherwise an ordinary setup reports access denied', () => {
    expect(clamavArgs('clamdscan', '/app')).toContain('--fdpass');
    expect(clamavArgs('clamdscan', '/app')).toContain('--no-summary');
    const plain = clamavArgs('clamscan', '/app', ['node_modules', 'templates/**']);
    expect(plain).toContain('--recursive');
    expect(plain.join(' ')).toContain('--exclude-dir=(^|/)node_modules(/|$)');
    expect(plain.at(-1)).toBe('/app');
  });

  it('turns a glob into the regular expression clamscan actually wants', () => {
    expect(excludeRegex('node_modules/**')).toBe('(^|/)node_modules(/|$)');
    expect(excludeRegex('/dist/')).toBe('(^|/)dist(/|$)');
    // A dot in a folder name is a dot, not "any character".
    expect(excludeRegex('.git')).toBe('(^|/)\\.git(/|$)');
  });

  it('reports a detection at the top severity, with the signature age attached', () => {
    const seed = toClamavSeed({ file: 'uploads/x.pdf', signature: 'Eicar-Test-Signature' }, { databaseDate: new Date() });
    expect(seed.severity).toBe('critical');
    expect(seed.ruleId).toBe('external.clamav.Eicar-Test-Signature');
    expect(seed.file).toBe('uploads/x.pdf');
    expect(seed.description).toContain('signatures last updated');
    expect(seed.evidence).toContain('FOUND');
  });

  it('is part of the ordinary run for an app we were handed, and opt-in for one we built', () => {
    expect(scanIsMandatory('uploaded')).toBe(true);
    expect(scanIsMandatory('built')).toBe(false);
    expect(scanIsMandatory(undefined)).toBe(false);
  });
});

describe('running the virus scanner', () => {
  const base = {
    appDir: '/app',
    exclude: ['node_modules'],
    timeoutMs: 60_000,
    log: () => {},
  };
  const version = { stdout: 'ClamAV 1.5.4/28129/Sun Sep 20 02:26:26 2026', stderr: '', code: 0, timedOut: false };

  it('does not run at all unless this project is one it runs for', async () => {
    let called = false;
    const result = await runClamavScan({
      ...base,
      enabled: false,
      find: () => '/usr/bin/clamdscan',
      run: async () => {
        called = true;
        return version;
      },
    });
    expect(called).toBe(false);
    expect(result.ran).toBe(false);
    expect(result.reason).toContain('not switched on');
  });

  it('says it is not installed rather than saying it found nothing', async () => {
    const result = await runClamavScan({ ...base, enabled: true, find: () => undefined, run: async () => version });
    expect(result.ran).toBe(false);
    expect(result.installed).toBe(false);
    expect(result.reason).toContain('not installed');
    expect(result.seeds).toEqual([]);
  });

  it('prefers the daemon, which holds the signatures in memory', async () => {
    const asked: string[] = [];
    await runClamavScan({
      ...base,
      enabled: true,
      find: (name) => {
        asked.push(name);
        return `/usr/bin/${name}`;
      },
      run: async () => version,
    });
    expect(asked[0]).toBe('clamdscan');
  });

  it('reports a detection, with the age of the signatures behind it', async () => {
    const result = await runClamavScan({
      ...base,
      enabled: true,
      find: () => '/usr/bin/clamdscan',
      run: async (_file, args) =>
        args.includes('--version') ? version : { stdout: '/app/uploads/x.doc: Doc.Downloader.Emotet-1 FOUND', stderr: '', code: 1, timedOut: false },
    });
    expect(result.ran).toBe(true);
    expect(result.seeds).toHaveLength(1);
    expect(result.seeds[0]?.severity).toBe('critical');
    expect(result.seeds[0]?.file).toBe('uploads/x.doc');
    expect(result.note).toContain('signatures last updated');
  });

  it('a scanner with no signature database is never recorded as a scan that happened', async () => {
    const result = await runClamavScan({
      ...base,
      enabled: true,
      find: () => '/usr/bin/clamscan',
      run: async (_file, args) =>
        args.includes('--version')
          ? { stdout: 'ClamAV 1.5.4', stderr: '', code: 0, timedOut: false }
          : { stdout: '', stderr: "LibClamAV Error: cli_loaddbdir: No supported database files found in /var/lib/clamav\nERROR: Can't open file or directory", code: 2, timedOut: false },
    });
    expect(result.ran).toBe(false);
    expect(result.seeds).toEqual([]);
    expect(result.reason).toContain('has not downloaded its virus signatures');
  });

  it('falls back to the slow scanner when the daemon cannot be reached, rather than reporting nothing', async () => {
    // Observed for real: a caller that is not allowed to open clamd's socket gets "Could not connect to clamd
    // ... Operation not permitted" from clamdscan, while clamscan does the same work with the same signatures.
    // Reporting "not scanned" there would be true of the first command and false of the situation.
    const used: string[] = [];
    const result = await runClamavScan({
      ...base,
      enabled: true,
      find: (name) => `/usr/bin/${name}`,
      run: async (file, args) => {
        if (args.includes('--version')) return version;
        used.push(file);
        return file.endsWith('clamdscan')
          ? { stdout: '', stderr: 'ERROR: Could not connect to clamd on LocalSocket /var/run/clamav/clamd.sock: Operation not permitted', code: 2, timedOut: false }
          : { stdout: '/app/x.doc: Eicar-Test-Signature FOUND', stderr: '', code: 1, timedOut: false };
      },
    });
    expect(used).toEqual(['/usr/bin/clamdscan', '/usr/bin/clamscan']);
    expect(result.ran).toBe(true);
    expect(result.seeds).toHaveLength(1);
  });

  it('does not retry the other scanner for a problem both of them would have', async () => {
    // No signature database is a property of the installation, not of which command asked.
    const used: string[] = [];
    const result = await runClamavScan({
      ...base,
      enabled: true,
      find: (name) => `/usr/bin/${name}`,
      run: async (file, args) => {
        if (args.includes('--version')) return version;
        used.push(file);
        return { stdout: '', stderr: 'LibClamAV Error: cli_loaddbdir: No supported database files found', code: 2, timedOut: false };
      },
    });
    expect(used).toEqual(['/usr/bin/clamdscan']);
    expect(result.ran).toBe(false);
    expect(result.reason).toContain('has not downloaded its virus signatures');
  });

  it('a scan stopped at the time limit is not a clean scan', async () => {
    const result = await runClamavScan({
      ...base,
      enabled: true,
      find: () => '/usr/bin/clamscan',
      run: async (_file, args) => (args.includes('--version') ? version : { stdout: '', stderr: '', code: null, timedOut: true }),
    });
    expect(result.ran).toBe(false);
    expect(result.reason).toContain('time limit');
  });
});
