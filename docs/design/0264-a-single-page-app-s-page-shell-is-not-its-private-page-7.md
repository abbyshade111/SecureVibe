# A single-page app's page shell is not its private page (7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 2.2). A single-page app, as a React or Vite build makes, sends every
visitor the same small page for every address, and the browser draws the rest from what it fetches next. Asked for
`/account` as nobody, such an app answers 200 with that page, and `probe.private-page-anonymous` reported a private
page served to anyone, high. Nothing private had been sent: the guard is on the addresses the page fetches.

- **How a shell is told.** The front page (`/`) is asked once, as nobody, before the private pages. A private page
  whose answer is a success with exactly the front page's body is the shell, provided the body is shorter than the
  part of an answer the run keeps (`sv_check::probes::KEPT_CHARS`, 4,000 characters, which `sv-run` now reads from
  there). A shell is small; a body that long may have been cut, and a server-rendered page can begin exactly as the
  front page does and differ below.
- **What follows.** A shell is set aside, neither served nor refused, and every check after this one (signing in,
  signing out, the session, caching, the sign-out link, and the rest) is given the private pages that are left. Without
  that, a shell answered after signing out would read as a session that still works.
- **What the owner is told.** When every private page is a shell, V8.2.1 is not assessed, naming them and saying to
  list the addresses the page fetches (`/api/me`) under `private`. The spec's `private` line says the same. When some
  are left, the credit counts only those and names the shells as not judged, and the run's notes say which they were.
- **What it does not do.** A shell is never counted as refused, so it never earns credit. An app whose front page is
  itself private and served to anyone, and which lists only addresses that answer the same, is not judged rather than
  found: the answers cannot tell the two apart. Listing an address that returns the data closes the gap.

ADR-021, "Later, 7 October 2026: a page shell is neither the private page served nor refused".

Eight guards broken in turn, each caught by `page_shell_tests` in `crates/sv-check/src/signed_in/mod.rs`:
- no shell ever seen (the behavior before);
- a cut body taken for a shell;
- any body taken for a shell;
- a front page that was refused compared all the same;
- an empty answer taken for a shell;
- the later checks still given the shells;
- nothing said when every private page is a shell;
- the credit silent on the shells.
