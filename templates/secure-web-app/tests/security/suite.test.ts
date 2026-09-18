/** Meta check for TPL-TESTS-01: the security suite is complete (one file per area, each with at least one test). */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const AREAS = [
  'headers',
  'csrf',
  'session',
  'password',
  'mfa',
  'authz',
  'validation',
  'errors',
  'logging',
  'crypto',
  'rate-limit',
  'uploads',
  'ai',
  'apikeys',
  'outbound',
  'db',
  'dto',
  'redirect',
];

describe('suite', () => {
  test('security suite has at least one test file per security area and every test name starts with a requirement id', () => {
    const dir = import.meta.dirname;
    const missing = AREAS.filter((a) => !existsSync(join(dir, `${a}.test.ts`)));
    assert.deepEqual(missing, [], `missing security test files: ${missing.join(', ')}`);
    const problems: string[] = [];
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.test.ts'))) {
      const src = readFileSync(join(dir, file), 'utf8');
      const names = [...src.matchAll(/\btest\(\s*(['"`])((?:\\.|(?!\1).)*)\1/g)].map((m) => m[2]!);
      if (names.length === 0) problems.push(`${file}: no tests`);
      for (const name of names) {
        if (!/^(V\d+\.\d+\.\d+|C\d+\.\d+\.\d+|AC\.\d+\.\d+|[A-Z]{2}-\d{2}|security suite)\b/.test(name)) problems.push(`${file}: "${name}" does not start with a requirement id`);
      }
    }
    assert.deepEqual(problems, [], problems.join('\n'));
    const helpers = join(dir, '..', 'helpers');
    for (const h of ['app.ts', 'conventions.ts', 'features.ts', 'totp.ts']) assert.ok(existsSync(join(helpers, h)), `helper ${h} missing`);
  });
});
