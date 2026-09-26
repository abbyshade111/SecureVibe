/**
 * Route patterns matched against request paths (src/lib/route-path.ts), which is how an API key is allowed on a
 * JSON route outside /api/, such as /account/export.
 *
 * Deliberately no requirement id on these test names: this is the matching underneath the key check, not the check.
 * The key check itself is tests/security/apikeys.test.ts. The cases are the ones the earlier regular expression
 * handled, and it matched each the same way, with one exception: a parameter in the middle of a segment
 * (`/x-:id`), which it took as a parameter and this takes as text. No route here or in SecureVibe's recipes is
 * written that way.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesRoutePath } from '../src/lib/route-path.ts';

describe('route patterns', () => {
  test('a path without parameters matches itself, with or without one trailing slash', () => {
    assert.equal(matchesRoutePath('/account/export', '/account/export'), true);
    assert.equal(matchesRoutePath('/account/export', '/account/export/'), true);
    assert.equal(matchesRoutePath('/account/export', '/account/export//'), false);
    assert.equal(matchesRoutePath('/account/export', '/account/exports'), false);
    assert.equal(matchesRoutePath('/account/export', '/account'), false);
    assert.equal(matchesRoutePath('/account/export', '/account/export/more'), false);
  });

  test('a parameter matches exactly one segment that is not empty', () => {
    assert.equal(matchesRoutePath('/notes/:id', '/notes/42'), true);
    assert.equal(matchesRoutePath('/notes/:id', '/notes/42/'), true);
    assert.equal(matchesRoutePath('/notes/:id', '/notes/'), false);
    assert.equal(matchesRoutePath('/notes/:id', '/notes'), false);
    assert.equal(matchesRoutePath('/notes/:id', '/notes/42/edit'), false);
    assert.equal(matchesRoutePath('/notes/:id/edit', '/notes/42/edit'), true);
    assert.equal(matchesRoutePath('/account/api-keys/:id/revoke', '/account/api-keys/k_1/revoke'), true);
  });

  test('characters a regular expression would treat specially are compared as themselves', () => {
    assert.equal(matchesRoutePath('/a.b', '/a.b'), true);
    assert.equal(matchesRoutePath('/a.b', '/axb'), false);
    assert.equal(matchesRoutePath('/a+b', '/aab'), false);
    assert.equal(matchesRoutePath('/x-:id', '/x-1'), false);
    assert.equal(matchesRoutePath('/x-:id', '/x-:id'), true);
  });

  test('the root route matches only the root', () => {
    assert.equal(matchesRoutePath('/', '/'), true);
    assert.equal(matchesRoutePath('/', '/notes'), false);
  });
});
