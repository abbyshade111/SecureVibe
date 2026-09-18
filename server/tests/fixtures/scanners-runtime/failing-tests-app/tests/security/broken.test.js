/**
 * A deliberately failing security test: the runner must turn this into a finding, not hide it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

test('V3.4.3 sends a content security policy', () => {
  assert.equal('no policy', 'a policy');
});

test('a test that is not about a requirement and passes', () => {
  assert.ok(true);
});
