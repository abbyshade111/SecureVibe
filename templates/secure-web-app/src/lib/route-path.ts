/**
 * Whether a request path matches a route pattern such as `/notes/:id`, the way Express matches it: one segment for
 * each `:name`, and a single trailing slash allowed.
 *
 * Compared segment by segment rather than by building a regular expression from the pattern. Building one from a
 * string reads, to a scanner, like a regular expression made from input somebody could shape, and it asked for
 * escaping that had to be right. A parameter here is a whole segment, which is how every route in this template and
 * in SecureVibe's recipes is written; a `:` elsewhere in a segment is compared as the character it is.
 */
export function matchesRoutePath(pattern: string, path: string): boolean {
  const want = pattern.split('/');
  const got = (path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path).split('/');
  if (want.length !== got.length) return false;
  return want.every((segment, i) => {
    const actual = got[i]!;
    return /^:[A-Za-z0-9_]+$/.test(segment) ? actual.length > 0 : segment === actual;
  });
}
