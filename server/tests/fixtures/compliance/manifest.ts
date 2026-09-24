/**
 * A compact TemplateManifest for compliance tests: a handful of controls covering every check type and every
 * gating rule (requiresFeature, tlsModes), independent of the real templates/secure-web-app manifest.
 */
import type { TemplateManifest } from '@shared/knowledge.js';

export const manifestFixture: TemplateManifest = {
  name: 'fixture-secure-web-app',
  version: '0.0.1-test',
  description: 'Fixture manifest for compliance-engine tests.',
  stack: ['node', 'express'],
  engines: { node: '>=22.13.0' },
  features: [
    { id: 'auth', description: 'Sign-in', paths: [] },
    { id: 'ai', description: 'AI assistant', paths: [] },
  ],
  protectedPaths: ['src/app.ts'],
  writablePaths: ['src/features/**'],
  allowedImports: ['express', 'zod', 'node:*'],
  controls: [
    // File-contains is a supporting check only: it must never carry a control on its own.
    {
      id: 'TPL-FILEONLY-01',
      title: 'Headers module still present',
      description: 'A supporting check that only looks at file contents.',
      asvs: [{ id: 'V3.4.4', proves: 'Security headers are configured.', coverage: 'full' }],
      aisvs: [],
      sbd: [],
      checks: [{ type: 'file-contains', file: 'src/security/headers.ts', pattern: 'helmet\\(' }],
      files: ['src/security/headers.ts'],
    },
    // A named test plus a supporting file check: credited by the test.
    {
      id: 'TPL-AUTH-01',
      title: 'Password policy',
      description: 'Minimum length, no composition rules, common-password check.',
      requiresFeature: 'auth',
      asvs: [
        { id: 'V6.2.1', proves: 'Passwords under 12 characters are rejected.', coverage: 'full' },
        { id: 'V6.2.4', proves: 'No composition rules are enforced.', coverage: 'full' },
      ],
      aisvs: [],
      sbd: [{ id: 'AC-03', proves: 'Authentication is in place.', coverage: 'partial' }],
      checks: [
        { type: 'test', name: 'V6.2.1' },
        { type: 'file-contains', file: 'src/security/password.ts', pattern: 'MIN_LENGTH' },
      ],
      files: ['src/security/password.ts'],
    },
    // A runtime probe: credited by DAST, partial coverage of the mapped requirement.
    {
      id: 'TPL-HEADERS-01',
      title: 'Nonce-based CSP',
      description: 'Every response carries a strict Content-Security-Policy.',
      asvs: [{ id: 'V3.4.3', proves: 'Every response carries a per-request CSP nonce.', coverage: 'partial' }],
      aisvs: [],
      sbd: [],
      checks: [{ type: 'dast', probe: 'dast.headers.csp' }],
      files: ['src/security/headers.ts'],
    },
    // A named AST check: credited by ast.
    {
      id: 'TPL-DB-01',
      title: 'Parameterised queries only',
      description: 'All database access goes through the db wrapper.',
      asvs: [{ id: 'V1.2.4', proves: 'Queries never concatenate untrusted input.', coverage: 'full' }],
      aisvs: [],
      sbd: [],
      checks: [{ type: 'ast', check: 'db-wrapper-only' }, { type: 'sast-clean', rules: ['sast.sql-string-concat'] }],
      files: ['src/db/index.ts'],
    },
    // A config-value check: credited by config.
    {
      id: 'TPL-SECRETS-01',
      title: 'Strong secrets',
      description: 'Secrets are generated strong and never placeholders.',
      asvs: [{ id: 'V13.2.3', proves: 'Secrets decode to at least 32 bytes and are not placeholders.', coverage: 'full' }],
      aisvs: [],
      sbd: [{ id: 'AC-05', proves: 'Secrets are kept out of code.', coverage: 'full' }],
      checks: [{ type: 'config-value', key: 'config.secrets-strength' }],
      files: ['.env'],
    },
    // A doc-generated check only: credited, but flagged docOnly (weak "design" evidence).
    {
      id: 'TPL-VALIDATION-02',
      title: 'Validation docs',
      description: 'docs/validation.md is generated from the route schemas.',
      asvs: [{ id: 'V2.1.1', proves: 'Every input field and its validation rule is documented.', coverage: 'full' }],
      aisvs: [],
      sbd: [],
      checks: [{ type: 'doc-generated', file: 'docs/validation.md' }],
      files: ['docs/validation.md'],
    },
    // AI feature control, gated on the "ai" feature.
    {
      id: 'TPL-AI-01',
      title: 'AI input normalization',
      description: 'Untrusted text is normalized and screened before reaching the model.',
      requiresFeature: 'ai',
      asvs: [],
      aisvs: [{ id: 'C2.1.1', proves: 'Input is normalized (NFKC) and control characters are stripped.', coverage: 'full' }],
      sbd: [],
      checks: [{ type: 'test', name: 'C2.1.1' }],
      files: ['src/features/ai/index.ts'],
    },
    // TLS-gated control.
    {
      id: 'TPL-TLS-01',
      title: 'TLS 1.2+ only',
      description: 'Self-signed TLS mode uses modern ciphers only.',
      tlsModes: ['selfsigned'],
      asvs: [{ id: 'V12.1.1', proves: 'The server only negotiates TLS 1.2 or newer.', coverage: 'full' }],
      aisvs: [],
      sbd: [],
      checks: [{ type: 'dast', probe: 'dast.tls.min-version' }],
      files: ['src/server.ts'],
    },
  ],
  conventions: [],
  testMode: {
    envFlag: 'SECUREVIBE_TEST_MODE',
    readyLinePrefix: '{"securevibe":"listening"',
    routesEndpoint: '/__securevibe/routes',
    seededUsers: [{ role: 'admin', email: 'admin@test.local', passwordEnv: 'SECUREVIBE_TEST_PASSWORD' }],
  },
};
