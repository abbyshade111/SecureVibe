/**
 * Security tests of the fixture app's one-time codes.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { totp, verifyTotp } from '../../src/totp.js';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

test('V6.5.1 one-time codes are six digits', () => {
  assert.match(totp(SEED), /^\d{6}$/);
});

test('V6.5.3 the code from the previous time step is still accepted', () => {
  assert.equal(verifyTotp(SEED, totp(SEED, -1)), true);
});

test('V6.5.5 a code that is not six digits is refused', () => {
  assert.equal(verifyTotp(SEED, '12345'), false);
  assert.equal(verifyTotp(SEED, 'abcdef'), false);
});

test('V6.6.3 the limit on wrong codes is checked by the runtime scanner, not here', { skip: 'covered by dast.auth.mfa-rate-limited' }, () => {
  assert.fail('never runs');
});
