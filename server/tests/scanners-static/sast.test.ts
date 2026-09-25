/**
 * SAST rule coverage (CONTRACTS §3): every rule id fires at least once, at the expected file and line,
 * against `fixtures/scanners-static/dirty-app`; the clean fixture (template conventions, including the
 * EJS allow-list: nonce, csrfField, include(...), safeHtml(...)) raises nothing.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Finding } from '@shared/findings.js';
import { RULE_IDS, runSast } from '../../src/scanners/sast/index.js';
import { fixtureDir, makeScanContext } from './helpers.js';

interface Expectation {
  ruleId: string;
  file: string;
  line: number;
}

/**
 * One row per rule (CONTRACTS §3 lists 56). Built from an actual scan of `dirty-app` — see that
 * fixture's comments for what each file is demonstrating. `sast.protected-file-modified` is exercised
 * separately below because it depends on provenance, not on source content.
 */
const EXPECTED: Expectation[] = [
  { ruleId: 'sast.eval-usage', file: 'src/lib/exec-example.ts', line: 15 },
  { ruleId: 'sast.new-function', file: 'src/lib/exec-example.ts', line: 19 },
  { ruleId: 'sast.vm-module', file: 'src/lib/exec-example.ts', line: 3 },
  { ruleId: 'sast.child-process-exec', file: 'src/lib/exec-example.ts', line: 7 },
  { ruleId: 'sast.child-process-user-input', file: 'src/lib/exec-example.ts', line: 11 },
  { ruleId: 'sast.deserialize-untrusted', file: 'src/lib/exec-example.ts', line: 27 },
  { ruleId: 'sast.xml-external-entities', file: 'src/lib/xml-example.ts', line: 5 },
  { ruleId: 'sast.sql-string-concat', file: 'src/features/notes/repo.ts', line: 5 },
  { ruleId: 'sast.db-raw-outside-wrapper', file: 'src/features/notes/legacy-db.ts', line: 2 },
  { ruleId: 'sast.res-raw-db-row', file: 'src/features/notes/routes.ts', line: 16 },
  { ruleId: 'sast.multiple-writes-no-transaction', file: 'src/features/notes/repo.ts', line: 10 },
  { ruleId: 'sast.ejs-unescaped-output', file: 'src/views/notes/show.ejs', line: 4 },
  { ruleId: 'sast.inline-script-in-view', file: 'src/views/notes/show.ejs', line: 5 },
  { ruleId: 'sast.inline-event-handler', file: 'src/views/notes/show.ejs', line: 6 },
  { ruleId: 'sast.secret-question-field', file: 'src/views/notes/show.ejs', line: 8 },
  { ruleId: 'sast.sensitive-in-get-param', file: 'src/features/notes/routes.ts', line: 29 },
  { ruleId: 'sast.innerhtml-assignment', file: 'public/js/features/widget.js', line: 4 },
  { ruleId: 'sast.document-write', file: 'public/js/features/widget.js', line: 8 },
  { ruleId: 'sast.dangerously-set-inner-html', file: 'src/features/admin/widget.tsx', line: 3 },
  { ruleId: 'sast.href-from-data', file: 'public/js/features/widget.js', line: 12 },
  { ruleId: 'sast.postmessage-no-origin-check', file: 'public/js/features/widget.js', line: 19 },
  { ruleId: 'sast.weak-hash-security-context', file: 'src/lib/crypto-example.ts', line: 9 },
  { ruleId: 'sast.math-random-security', file: 'src/lib/crypto-example.ts', line: 18 },
  { ruleId: 'sast.crypto-createcipher', file: 'src/lib/crypto-example.ts', line: 13 },
  { ruleId: 'sast.hardcoded-secret', file: 'src/lib/crypto-example.ts', line: 27 },
  { ruleId: 'sast.tls-reject-unauthorized-false', file: 'src/lib/net.ts', line: 8 },
  { ruleId: 'sast.cors-wildcard-credentials', file: 'src/app.ts', line: 18 },
  { ruleId: 'sast.cors-any-origin', file: 'src/app.ts', line: 25 },
  { ruleId: 'sast.cookie-missing-httponly', file: 'src/lib/cookies-example.ts', line: 7 },
  { ruleId: 'sast.cookie-missing-samesite', file: 'src/lib/cookies-example.ts', line: 7 },
  { ruleId: 'sast.helmet-disabled-csp', file: 'src/app.ts', line: 13 },
  { ruleId: 'sast.unsafe-regex', file: 'src/lib/regex-example.ts', line: 2 },
  { ruleId: 'sast.regex-from-user-input', file: 'src/lib/regex-example.ts', line: 5 },
  { ruleId: 'sast.path-join-user-input', file: 'src/lib/fs-example.ts', line: 6 },
  { ruleId: 'sast.fs-user-path', file: 'src/lib/fs-example.ts', line: 7 },
  { ruleId: 'sast.open-redirect', file: 'src/security/misc-handlers.ts', line: 14 },
  { ruleId: 'sast.res-raw-db-row', file: 'src/features/notes/routes.ts', line: 16 },
  { ruleId: 'sast.req-body-unvalidated', file: 'src/features/notes/routes.ts', line: 25 },
  { ruleId: 'sast.route-outside-registry', file: 'src/features/notes/routes.ts', line: 37 },
  { ruleId: 'sast.missing-authz-declaration', file: 'src/features/notes/routes.ts', line: 20 },
  { ruleId: 'sast.fetch-outside-http-client', file: 'src/lib/net.ts', line: 15 },
  { ruleId: 'sast.http-request-outside-client', file: 'src/lib/net.ts', line: 5 },
  { ruleId: 'sast.mailer-header-user-input', file: 'src/security/misc-handlers.ts', line: 18 },
  { ruleId: 'sast.object-assign-user-input', file: 'src/lib/merge-example.ts', line: 3 },
  { ruleId: 'sast.proto-pollution-merge', file: 'src/lib/merge-example.ts', line: 6 },
  { ruleId: 'sast.log-sensitive-field', file: 'src/lib/log-example.ts', line: 5 },
  { ruleId: 'sast.console-log', file: 'src/lib/log-example.ts', line: 9 },
  { ruleId: 'sast.default-secret-fallback', file: 'src/lib/crypto-example.ts', line: 29 },
  { ruleId: 'sast.express-static-dotfiles-allow', file: 'src/app.ts', line: 32 },
  { ruleId: 'sast.trust-proxy-true', file: 'src/app.ts', line: 9 },
  { ruleId: 'sast.timing-unsafe-compare', file: 'src/lib/crypto-example.ts', line: 22 },
  { ruleId: 'sast.jwt-none-alg', file: 'src/lib/crypto-example.ts', line: 25 },
  { ruleId: 'sast.secret-question-field', file: 'src/views/notes/show.ejs', line: 8 },
  { ruleId: 'sast.password-composition-rule', file: 'src/features/auth/password-rules.ts', line: 2 },
  { ruleId: 'sast.xml-external-entities', file: 'src/lib/xml-example.ts', line: 5 },
  { ruleId: 'sast.deserialize-untrusted', file: 'src/lib/exec-example.ts', line: 27 },
  { ruleId: 'sast.ai-output-rendered-unescaped', file: 'src/features/ai/assistant.ts', line: 7 },
  { ruleId: 'sast.ai-api-key-in-prompt', file: 'src/features/ai/assistant.ts', line: 4 },
  { ruleId: 'sast.disallowed-import', file: 'src/features/ai/assistant.ts', line: 2 },
  { ruleId: 'sast.sensitive-in-get-param', file: 'src/features/notes/routes.ts', line: 29 },
  { ruleId: 'sast.todo-security', file: 'src/views/notes/show.ejs', line: 1 },
  { ruleId: 'sast.assistant-form-no-working-state', file: 'src/views/research/index.ejs', line: 1 },
];

/** Rules that legitimately fire more than once in this fixture, and how many times. */
const EXTRA_OCCURRENCES: Record<string, number> = {
  'sast.db-raw-outside-wrapper': 2, // the import, and the .prepare() call on the same object
  'sast.fs-user-path': 2, // two request-driven file reads
  'sast.req-body-unvalidated': 4, // every raw req.body/query/params read in the fixture
  'sast.assistant-form-no-working-state': 3, // the unmarked forms only (through a helper, direct, with a path parameter): the marked one, the other route and the GET form are left alone
};

describe('sast rule coverage (dirty-app fixture)', () => {
  const ctx = makeScanContext(fixtureDir('dirty-app'));
  let findings: Finding[];

  it('runs without error', async () => {
    const result = await runSast(ctx);
    findings = result.findings;
    expect(result.status).not.toBe('skipped');
  });

  it('every rule id from CONTRACTS §3 is implemented', () => {
    const covered = new Set(EXPECTED.map((e) => e.ruleId));
    covered.add('sast.protected-file-modified'); // covered by its own test below
    const missing = RULE_IDS.filter((id) => !covered.has(id));
    expect(missing).toEqual([]);
  });

  for (const { ruleId, file, line } of new Map(EXPECTED.map((e) => [e.ruleId, e])).values()) {
    it(`${ruleId} fires at ${file}:${line}`, () => {
      const hits = findings.filter((f) => f.ruleId === ruleId);
      expect(hits.length).toBeGreaterThanOrEqual(1);
      expect(hits.some((f) => f.location?.file === file && f.location?.line === line)).toBe(true);
    });
  }

  it('rules known to fire more than once do so exactly as expected, no more', () => {
    for (const [ruleId, count] of Object.entries(EXTRA_OCCURRENCES)) {
      expect(findings.filter((f) => f.ruleId === ruleId).length, ruleId).toBe(count);
    }
  });

  it('every finding carries a stable fingerprint, mappings and remediation', () => {
    for (const f of findings) {
      expect(f.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(f.source).toBe('sast');
      expect(f.remediation.summary.length).toBeGreaterThan(0);
      expect(f.introducedBy).toBe('unknown'); // no provenance was supplied for this run
    }
  });
});

describe('sast.protected-file-modified', () => {
  it('fires when a protected file no longer matches its recorded provenance hash', async () => {
    const appDir = fixtureDir('dirty-app');
    const relPath = 'src/security/headers.ts';
    const actualHash = createHash('sha256').update(readFileSync(join(appDir, relPath))).digest('hex');
    const ctx = makeScanContext(appDir, {
      provenance: {
        reportSchemaVersion: '1',
        tool: 'SecureVibe test',
        securevibeVersion: '0.0.0',
        templateVersion: '0.0.0',
        frameworkVersions: { asvs: '5.0.0', aisvs: '1.0.0', sbd: '0.5.0' },
        toolVersions: {},
        runId: 'test-run-1',
        projectId: 'p_test',
        generatedAt: new Date().toISOString(),
        mode: 'full',
        humanInvolvement: { summary: 'test', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
        designProfileHash: 'x',
        designHash: 'x',
        codeTreeHash: 'x',
        generatedFiles: [],
        protectedFileHashes: { [relPath]: `${actualHash.slice(0, -4)}dead` },
        sandbox: { mode: 'node-permission-model', note: 'file system restricted to the project folder' },
      },
    });
    const result = await runSast(ctx);
    const hit = result.findings.find((f) => f.ruleId === 'sast.protected-file-modified');
    expect(hit).toBeDefined();
    expect(hit?.location?.file).toBe(relPath);
  });

  it('does not fire when the hash matches', async () => {
    const appDir = fixtureDir('dirty-app');
    const relPath = 'src/security/headers.ts';
    const actualHash = createHash('sha256').update(readFileSync(join(appDir, relPath))).digest('hex');
    const ctx = makeScanContext(appDir, {
      provenance: {
        reportSchemaVersion: '1',
        tool: 'SecureVibe test',
        securevibeVersion: '0.0.0',
        templateVersion: '0.0.0',
        frameworkVersions: { asvs: '5.0.0', aisvs: '1.0.0', sbd: '0.5.0' },
        toolVersions: {},
        runId: 'test-run-1',
        projectId: 'p_test',
        generatedAt: new Date().toISOString(),
        mode: 'full',
        humanInvolvement: { summary: 'test', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
        designProfileHash: 'x',
        designHash: 'x',
        codeTreeHash: 'x',
        generatedFiles: [],
        protectedFileHashes: { [relPath]: actualHash },
        sandbox: { mode: 'node-permission-model', note: 'file system restricted to the project folder' },
      },
    });
    const result = await runSast(ctx);
    expect(result.findings.some((f) => f.ruleId === 'sast.protected-file-modified')).toBe(false);
  });
});

describe('sast.assistant-form-no-working-state', () => {
  const only = async (ctx: ReturnType<typeof makeScanContext>) => (await runSast(ctx)).findings.filter((f) => f.ruleId === 'sast.assistant-form-no-working-state');

  it('reports each unmarked form that posts to a route asking the assistant, and no other form', async () => {
    const hits = await only(makeScanContext(fixtureDir('dirty-app')));
    const forms = hits.map((h) => h.location?.line).sort();
    // Line 1 (a route that reaches the assistant through a helper), 18 (direct use), 22 (a path parameter).
    // Not: the marked form at 6, the note form at 11, the GET form at 15.
    expect(forms).toEqual([1, 18, 22]);
    expect(hits.every((h) => h.location?.file === 'src/views/research/index.ejs')).toBe(true);
    expect(hits.every((h) => h.severity === 'low')).toBe(true);
  });

  it('says in the evidence which route and file the form posts to', async () => {
    const hits = await only(makeScanContext(fixtureDir('dirty-app')));
    const first = hits.find((h) => h.location?.line === 1)!;
    expect(JSON.stringify(first)).toContain('/research/run');
    expect(JSON.stringify(first)).toContain('src/features/research/routes.ts');
  });

  it('leaves the same forms alone once the pages are the template’s own (the template checks its own assistant page)', async () => {
    const appDir = fixtureDir('dirty-app');
    const files = ['src/features/research/routes.ts', 'src/views/research/index.ejs'];
    const ctx = makeScanContext(appDir, {
      provenance: {
        reportSchemaVersion: '1', tool: 'SecureVibe test', securevibeVersion: '0.0.0', templateVersion: '0.0.0',
        frameworkVersions: { asvs: '5.0.0', aisvs: '1.0.0', sbd: '0.5.0' }, toolVersions: {}, runId: 'test-run-1', projectId: 'p_test',
        generatedAt: new Date().toISOString(), mode: 'full',
        humanInvolvement: { summary: 'test', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
        designProfileHash: 'x', designHash: 'x', codeTreeHash: 'x',
        generatedFiles: files.map((path) => ({ path, origin: 'template' as const, sha256: createHash('sha256').update(readFileSync(join(appDir, path))).digest('hex') })),
        protectedFileHashes: {}, sandbox: { mode: 'node-permission-model', note: 'file system restricted to the project folder' },
      },
    });
    expect(await only(ctx)).toEqual([]);
  });

  it('finds nothing in the real template, whose assistant page carries data-working', async () => {
    const template = join(fixtureDir('dirty-app'), '..', '..', '..', '..', '..', 'templates', 'secure-web-app');
    expect(readFileSync(join(template, 'src/views/ai/index.ejs'), 'utf8')).toContain('data-working');
    expect(await only(makeScanContext(template))).toEqual([]);
  });
});

describe('sast on the clean fixture (template conventions)', () => {
  it('raises no findings, including the EJS allow-list (nonce, csrfField, include, safeHtml)', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runSast(ctx);
    expect(result.findings).toEqual([]);
    expect(result.status).toBe('passed');
  });
});
