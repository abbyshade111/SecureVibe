import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { RemediationEntrySchema } from '@shared/knowledge.js';
import { readKnowledge, unknownRequirementIds, unknownSbdIds } from './helpers.js';

/** Hard-coded from docs/CONTRACTS.md §3 (id → severity). */
const SAST_RULES: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  'sast.eval-usage': 'high',
  'sast.new-function': 'high',
  'sast.vm-module': 'high',
  'sast.child-process-exec': 'high',
  'sast.child-process-user-input': 'critical',
  'sast.sql-string-concat': 'critical',
  'sast.db-raw-outside-wrapper': 'medium',
  'sast.ejs-unescaped-output': 'high',
  'sast.inline-script-in-view': 'medium',
  'sast.inline-event-handler': 'medium',
  'sast.innerhtml-assignment': 'high',
  'sast.document-write': 'medium',
  'sast.dangerously-set-inner-html': 'high',
  'sast.href-from-data': 'medium',
  'sast.postmessage-no-origin-check': 'medium',
  'sast.weak-hash-security-context': 'medium',
  'sast.math-random-security': 'high',
  'sast.crypto-createcipher': 'high',
  'sast.hardcoded-secret': 'critical',
  'sast.tls-reject-unauthorized-false': 'critical',
  'sast.cors-wildcard-credentials': 'high',
  'sast.cors-any-origin': 'medium',
  'sast.cookie-missing-httponly': 'medium',
  'sast.cookie-missing-samesite': 'low',
  'sast.helmet-disabled-csp': 'high',
  'sast.unsafe-regex': 'medium',
  'sast.regex-from-user-input': 'medium',
  'sast.path-join-user-input': 'high',
  'sast.fs-user-path': 'high',
  'sast.open-redirect': 'high',
  'sast.res-raw-db-row': 'medium',
  'sast.req-body-unvalidated': 'medium',
  'sast.route-outside-registry': 'high',
  'sast.missing-authz-declaration': 'high',
  'sast.fetch-outside-http-client': 'medium',
  'sast.http-request-outside-client': 'medium',
  'sast.mailer-header-user-input': 'high',
  'sast.object-assign-user-input': 'medium',
  'sast.proto-pollution-merge': 'medium',
  'sast.log-sensitive-field': 'medium',
  'sast.console-log': 'low',
  'sast.default-secret-fallback': 'high',
  'sast.express-static-dotfiles-allow': 'medium',
  'sast.trust-proxy-true': 'medium',
  'sast.multiple-writes-no-transaction': 'low',
  'sast.timing-unsafe-compare': 'medium',
  'sast.jwt-none-alg': 'critical',
  'sast.secret-question-field': 'medium',
  'sast.password-composition-rule': 'low',
  'sast.xml-external-entities': 'high',
  'sast.deserialize-untrusted': 'critical',
  'sast.ai-output-rendered-unescaped': 'high',
  'sast.ai-api-key-in-prompt': 'critical',
  'sast.disallowed-import': 'medium',
  'sast.sensitive-in-get-param': 'medium',
  'sast.protected-file-modified': 'high',
  'sast.todo-security': 'info',
};

/** Hard-coded from docs/CONTRACTS.md §4. */
const CONFIG_CHECKS = [
  'config.env-example-present',
  'config.gitignore-covers-env',
  'config.secrets-strength',
  'config.no-default-admin',
  'config.node-engine-pinned',
  'config.lockfile-present',
  'config.ignore-scripts',
  'config.no-debug-flags',
  'config.example-feature-disabled',
  'config.test-mode-not-in-env',
  'config.tls-mode-consistent',
  'config.trust-proxy-hops',
  'config.session-policy',
  'config.protected-files-unchanged',
  'config.provenance-present',
  'config.bind-loopback-default',
  'config.security-md-present',
  'config.readme-run-instructions',
  'config.package-json-unmodified',
];
const SECRETS_RULES = [
  'secrets.anthropic-key',
  'secrets.aws-access-key',
  'secrets.aws-secret-key',
  'secrets.github-token',
  'secrets.slack-token',
  'secrets.stripe-key',
  'secrets.google-api-key',
  'secrets.private-key-block',
  'secrets.jwt',
  'secrets.high-entropy-assignment',
  'secrets.password-assignment',
  'secrets.connection-string-password',
  'secrets.env-file-committed',
];
const DEPS_CHECKS = [
  'deps.vulnerability',
  'deps.lockfile-missing',
  'deps.install-scripts-present',
  'deps.deprecated-package',
  'deps.license-copyleft',
  'deps.sbom-generated',
];

/** Hard-coded from docs/CONTRACTS.md §1.15 (manifest checks) and §2 (extra probes). */
const DAST_PROBES = [
  'dast.headers.csp',
  'dast.headers.nosniff',
  'dast.headers.referrer-policy',
  'dast.headers.hsts',
  'dast.headers.content-type-charset',
  'dast.cors.origin-not-reflected',
  'dast.cache.no-store-authenticated',
  'dast.cookie.session-attributes',
  'dast.cookie.secure-host-prefix',
  'dast.tls.min-version',
  'dast.csrf.missing-token-rejected',
  'dast.csrf.cross-origin-rejected',
  'dast.csrf.get-does-not-mutate',
  'dast.session.logout-clear-site-data',
  'dast.leak.dotfiles',
  'dast.leak.directory-listing',
  'dast.leak.trace',
  'dast.leak.health-minimal',
  'dast.errors.no-stack-trace',
  'dast.errors.404-generic',
  'dast.errors.500-generic',
  'dast.input.oversized-body',
  'dast.input.duplicate-param',
  'dast.input.proto-pollution',
  'dast.input.unknown-field',
  'dast.input.type-confusion',
  'dast.authz.anonymous-denied',
  'dast.authz.wrong-role-denied',
  'dast.authz.non-owner-denied',
  'dast.auth.weak-password-rejected',
  'dast.auth.password-field-type',
  'dast.auth.login-rate-limited',
  'dast.auth.uniform-unknown-user',
  'dast.auth.reset-uniform-response',
  'dast.auth.mfa-rate-limited',
  'dast.auth.admin-mfa-enforced',
  'dast.session.id-format',
  'dast.session.rotated-on-login',
  'dast.session.reuse-after-logout-denied',
  'dast.session.logout-visible',
  'dast.rate.registration-limited',
  'dast.rate.reset-limited',
  'dast.rate.xff-spoof-ignored',
  'dast.redirect.open-redirect-blocked',
  'dast.xss.reflected-smoke',
  'dast.upload.oversize-413',
  'dast.upload.type-mismatch-415',
  'dast.upload.svg-refused',
  'dast.upload.not-served-from-public',
  'dast.upload.download-headers',
  'dast.upload.non-owner-denied',
  'dast.ai.control-chars-rejected',
  'dast.ai.oversized-input-422',
  'dast.ai.injection-blocked-and-logged',
  'dast.ai.output-escaped',
  'dast.ai.killswitch-503',
  'dast.ai.action-requires-confirmation',
  'dast.apikey.query-string-rejected',
  'dast.health.readyz',
  'dast.api.idempotency-key',
  'dast.log.login-failure-logged',
  'dast.log.authz-denial-logged',
  'dast.log.validation-rejected-logged',
  // §2 extras
  'dast.leak.test-endpoints-absent',
  'dast.health.healthz',
  'dast.api.json-content-type',
  'dast.authz.unregistered-route',
  'dast.session.cookie-not-in-url',
  'dast.xss.stored-smoke',
  'dast.input.sql-smoke',
  'dast.input.path-traversal-smoke',
  'dast.errors.method-not-allowed',
  'dast.ai.prompt-not-in-response',
  'dast.upload.quota-enforced',
];

const ALL_RULE_IDS = [...Object.keys(SAST_RULES), ...CONFIG_CHECKS, ...SECRETS_RULES, ...DEPS_CHECKS, ...DAST_PROBES];

const raw = readKnowledge<unknown>('remediation.json');

describe('data/knowledge/remediation.json', () => {
  const entries = z.array(RemediationEntrySchema).parse(raw);
  const byId = new Map(entries.map((e) => [e.ruleId, e]));

  it('validates against RemediationEntrySchema with unique rule ids', () => {
    expect(byId.size).toBe(entries.length);
  });

  it('has an entry for every SAST, config, secrets, deps rule and every DAST probe in CONTRACTS', () => {
    const missing = ALL_RULE_IDS.filter((id) => !byId.has(id));
    expect(missing).toEqual([]);
  });

  it('contains no rule ids outside the CONTRACTS lists', () => {
    const known = new Set(ALL_RULE_IDS);
    const extra = entries.map((e) => e.ruleId).filter((id) => !known.has(id));
    expect(extra).toEqual([]);
  });

  it('SAST severities match CONTRACTS §3', () => {
    const wrong = Object.entries(SAST_RULES)
      .filter(([id, sev]) => byId.get(id)?.severity !== sev)
      .map(([id, sev]) => `${id}: expected ${sev}, got ${byId.get(id)?.severity}`);
    expect(wrong).toEqual([]);
  });

  it('every entry explains what, why, how to fix, how to confirm, and how exploitable it is', () => {
    for (const e of entries) {
      expect(e.title.length, e.ruleId).toBeGreaterThan(5);
      expect(e.description.length, `${e.ruleId} description`).toBeGreaterThan(30);
      expect(e.impact.length, `${e.ruleId} impact`).toBeGreaterThan(30);
      expect(e.remediation.summary.length, `${e.ruleId} summary`).toBeGreaterThan(10);
      expect(e.remediation.steps.length, `${e.ruleId} steps`).toBeGreaterThan(0);
      expect(e.remediation.references.length, `${e.ruleId} references`).toBeGreaterThan(0);
      for (const ref of e.remediation.references) expect(ref, `${e.ruleId} reference`).toMatch(/^https:\/\//);
      expect(e.howToConfirmFixed, `${e.ruleId} howToConfirmFixed`).toBeTruthy();
      expect(e.exploitability, `${e.ruleId} exploitability`).toBeDefined();
      // Informational notices (e.g. a copyleft licence) are not weaknesses and need no CWE.
      if (e.severity !== 'info') expect(e.cwe.length, `${e.ruleId} cwe`).toBeGreaterThan(0);
      for (const c of e.cwe) expect(c, `${e.ruleId} cwe format`).toMatch(/^CWE-\d+$/);
    }
  });

  it('every SAST rule ships a code example written in the template conventions', () => {
    const conventionMarkers = /defineRoute|db\.(?:all|get|run|q)\(|withTransaction|outboundFetch|safeRedirect|<%=|encryptField|config\.|logger|events\.emit|validateBody|requireRole|requireOwner|nonce|node:crypto|z\.object|http-client|import|process\.env|\.env|password|argon2|scrypt|timingSafeEqual|Content-Security-Policy|helmet|app\.use|express\.|res\.|req\.|router|schema|await|const |function|\/\/|return/;
    for (const id of Object.keys(SAST_RULES)) {
      const e = byId.get(id)!;
      expect(e.remediation.example, `${id} example`).toBeTruthy();
      expect(e.remediation.example!, `${id} example should look like code in the template's conventions`).toMatch(conventionMarkers);
    }
  });

  it('references only ASVS/AISVS/SbD ids that exist', () => {
    const bad: string[] = [];
    for (const e of entries) {
      for (const id of unknownRequirementIds([...e.asvs, ...e.aisvs])) bad.push(`${e.ruleId} → ${id}`);
      for (const id of unknownSbdIds(e.sbd)) bad.push(`${e.ruleId} → ${id}`);
      for (const id of e.asvs) if (!id.startsWith('V')) bad.push(`${e.ruleId}: ${id} is not an ASVS id`);
      for (const id of e.aisvs) if (!/^(C|AC\.)/.test(id)) bad.push(`${e.ruleId}: ${id} is not an AISVS id`);
    }
    expect(bad).toEqual([]);
  });

  it('every entry maps to at least one requirement or checklist control', () => {
    const unmapped = entries.filter((e) => e.asvs.length + e.aisvs.length + e.sbd.length === 0).map((e) => e.ruleId);
    expect(unmapped).toEqual([]);
  });
});
