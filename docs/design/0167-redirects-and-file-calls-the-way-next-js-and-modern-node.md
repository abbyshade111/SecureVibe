# Redirects and file calls the way Next.js and modern Node write them (5 October 2026)

H5 of the deep review: `ast.open-redirect` and `ast.file-path-from-value` read only `res.redirect(…)` and
`fs.readFile(…)` shapes, so the usual Next.js and modern Node forms went unreported while TypeScript was claimed
checked.

- **Redirects** now also read Next.js's bare `redirect(…)` from `next/navigation`, `NextResponse.redirect(…)`, and
  the browser's own: `window.location = …`, `location.href = …`, `window.location.href = …`, and
  `location.assign(…)` or `location.replace(…)`. A destination that is a path on the same site stays safe, and so
  does `new URL('/path', request.url)`, the way Next.js middleware sends someone to its own sign-in page;
  `new URL('//other.site', …)` does not count as a path.
- **File calls** now also read `fs.promises.readFile(…)` and the bare `readFile(…)`, `writeFile(…)`, `rm(…)` and
  their kin imported from `fs/promises`. A bare call is read only for the file system's own names, so a function of
  the app's that happens to be called `download` is not.
- **What it still does not read:** a redirect or file call reached through a name of the app's own, such as
  `const go = redirect` or `const fsp = require('fs').promises` named anything but `fsp`.

How it is held: `next_js_and_modern_node_redirects_and_file_calls_are_read` (`crates/sv-check/src/ast.rs`), with
twenty cases, each fixture checked to parse. Five guards were undone in turn, and each turned a case red.

**Later, 5 October 2026: five differences from a second build of H5.** A second session had built H5 at the same
time (closed unmerged as #642). At the owner's asking, the five places where it went further were ported onto the
rules above (BACKLOG, "H5 follow-up"):

- **`new URL("/path", base)` is safe only when the base is the request's own address** (`request.url`, `req.url`,
  `request.nextUrl`, or its `origin`). Before, any base was accepted, so `new URL("/login", req.query.next)`, which
  goes to whatever host the visitor named, was a clean result. A bare `"/"` with the request's base is now safe too.
- **More redirects:** `permanentRedirect()`, `Response.redirect` (the web standard's, used by route handlers),
  SvelteKit's `redirect(303, x)` with the status first, and `document.location = x`. Express's `res.location`,
  `self.location`, and `top.location` were already found, by the cross of the name patterns; they are now named on
  purpose, with witnesses.
- **A bare `location.replace(...)` is not reported:** a string called `location` has a `replace` of its own, and
  `const slug = location.replace(/\s+/g, '-')` was reported as a redirect. `window.location.replace(x)` and
  `document.location.replace(x)` still are. To say so in the data, the redirect query now captures the whole callee
  or assignment target as `@mod` (`res.redirect`, `window.location.replace`, `location.href`), so the module pattern
  lists the pairs that redirect rather than letting any listed object pair with any listed name. The name pattern
  stays plain words, which H25's test of a file that did not parse relies on.
- **The app's own folder** in the file-path guard now includes `process.cwd()` and `import.meta.dirname` beside
  `__dirname`, and `new URL('./x', import.meta.url)`: where a Next.js app reads its content from, and the ES module
  way to name a file beside the code. A path joined onto them from a value is still reported.
- **The clean result names the calls** each rule reads in JavaScript and TypeScript (`looksForIn`).

Nothing the section above chose was undone: a bare `download` is still not read, and `fs.promises` is still matched
through its `promises` part.

**Tested.** Forty witnesses in `the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one`, a found and a
not-found case for each difference in JavaScript and TypeScript, and
`a_clean_javascript_and_typescript_result_names_the_redirect_and_file_calls_it_read`
(`crates/sv-check/tests/clean_coverage.rs`). Against the rules as #641 left them, eighteen of the witnesses fail
(eleven missed, seven reported). Eleven guards broken in turn, each caught: any base accepted for `new URL` (two
witnesses), and `permanentRedirect`, `Response.redirect`, `res.location`, and the status-first `redirect` each taken
out (two each); `window` alone where `document`, `self`, and `top` were (three); a bare `location.replace` let
through (two); `process.cwd()` taken out of the guard (two), `import.meta.dirname` (one), and `import.meta.url`
(two); and the redirect rule's JavaScript and TypeScript words taken out (the clean-result test).
