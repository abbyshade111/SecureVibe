/**
 * Named AST checks (CONTRACTS §3, `server/src/scanners/ast-checks.ts`) referenced by the template manifest
 * (`{ type: 'ast', check, file? }`). Each check is exercised once against the clean fixture (should pass)
 * and once against the dirty fixture (should fail with a plain-language reason).
 */
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { isAstCheckName, runAstCheck } from '../../src/scanners/ast-checks.js';
import { fixtureDir, makeScanContext } from './helpers.js';

describe('isAstCheckName', () => {
  it('recognizes every declared check and rejects a typo', () => {
    expect(isAstCheckName('helmet-csp-configured')).toBe(true);
    expect(isAstCheckName('not-a-real-check')).toBe(false);
  });
});

describe('runAstCheck: unknown name', () => {
  it('fails explicitly instead of throwing', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runAstCheck('nonexistent-check', ctx);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain('Unknown AST check');
  });
});

describe('helmet-csp-configured', () => {
  it('passes on the clean fixture', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runAstCheck('helmet-csp-configured', ctx, 'src/app.ts');
    expect(result.passed).toBe(true);
  });

  it('fails on the dirty fixture (contentSecurityPolicy: false)', async () => {
    const ctx = makeScanContext(fixtureDir('dirty-app'));
    const result = await runAstCheck('helmet-csp-configured', ctx, 'src/app.ts');
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/switched off/);
  });
});

describe('routes-have-schemas', () => {
  it('passes on the clean fixture', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runAstCheck('routes-have-schemas', ctx);
    expect(result.passed).toBe(true);
  });

  it('fails on the dirty fixture (a POST route with no body schema)', async () => {
    const ctx = makeScanContext(fixtureDir('dirty-app'));
    const result = await runAstCheck('routes-have-schemas', ctx);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/POST \/notes\/raw-body/);
  });

  it('accepts body-less POST routes when the registry validates a missing body as a strict empty object', async () => {
    const ctx = makeScanContext(fileURLToPath(new URL('../../../templates/secure-web-app', import.meta.url)));
    const result = await runAstCheck('routes-have-schemas', ctx);
    expect(result.detail).not.toMatch(/accepts a body but has no schema.body/);
    expect(result.passed).toBe(true);
  });
});

describe('all-routes-registered', () => {
  it('passes on the clean fixture', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runAstCheck('all-routes-registered', ctx);
    expect(result.passed).toBe(true);
  });

  it('fails on the dirty fixture (a route bypasses defineRoute, and app.ts never asserts)', async () => {
    const ctx = makeScanContext(fixtureDir('dirty-app'));
    const result = await runAstCheck('all-routes-registered', ctx);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/bypasses defineRoute/);
    expect(result.detail).toMatch(/assertAllRoutesRegistered/);
  });
});

describe('db-wrapper-only', () => {
  it('passes on the clean fixture', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runAstCheck('db-wrapper-only', ctx);
    expect(result.passed).toBe(true);
  });

  it('fails on the dirty fixture (raw SQL and a direct driver import)', async () => {
    const ctx = makeScanContext(fixtureDir('dirty-app'));
    const result = await runAstCheck('db-wrapper-only', ctx);
    expect(result.passed).toBe(false);
  });
});

describe('node-crypto-only', () => {
  it('passes on the clean fixture', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runAstCheck('node-crypto-only', ctx);
    expect(result.passed).toBe(true);
  });

  it('fails on the dirty fixture (MD5 and a deprecated cipher)', async () => {
    const ctx = makeScanContext(fixtureDir('dirty-app'));
    const result = await runAstCheck('node-crypto-only', ctx);
    expect(result.passed).toBe(false);
  });
});

describe('ai-context-user-scoped', () => {
  it('passes on the clean fixture (the AI feature scopes its read to the signed-in user)', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runAstCheck('ai-context-user-scoped', ctx);
    expect(result.passed).toBe(true);
  });

  it('fails on the dirty fixture (a query reads every user’s conversations)', async () => {
    const ctx = makeScanContext(fixtureDir('dirty-app'));
    const result = await runAstCheck('ai-context-user-scoped', ctx);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/not limited to the signed-in user/);
  });
});
