# Open redirects in the sign-in flow (3 October 2026)

An app that sends the browser back to "where you were" after signing in reads that address from the request. If it
follows any address, a link to the app's own sign-in page can pass people on to a copy of it that asks for the password
again. V3.7.2 asks that a redirect off the app go only to an allowed list. `probe.open-redirect` (CWE-601, medium)
asks the sign-in flow, signed in as A, in sessions of its own:

- **What it sends.** The address is on `sv-redirect.invalid`, a name reserved never to exist, so a redirect there
  reaches nobody. It goes in nine parameters at once: `next`, `redirect`, `redirect_to`, `returnTo`, `return_to`,
  `ReturnUrl`, `url`, `continue`, and `destination`. It is sent twice: as a full address (`https://…`), and as one
  beginning with `//`. A browser reads `//` as another site, and a check that only asks whether the address begins
  with `/` takes it for one of the app's own pages.
- **Where it is sent.** With each address, the parameters go on the sign-in page and the sign-in request, then on the
  sign-in page opened again signed in (many apps send a signed-in visitor straight on), and then on the sign-out
  request, when there is a `logout`.
- **What is read.** A redirect (3xx) whose `Location` leads to that host is the finding, reading `\` as `/` and
  ignoring case, as a browser does. A redirect anywhere else, or none, is no finding.
- **Only ever a finding.** Three places and nine names are a sample. An app that keeps people on its own pages here
  can still have a redirect elsewhere that goes anywhere, so a clean answer is never credit. `tools/coverage.py`
  lists it in `RUST_FINDINGS_ONLY`.
- **A sign-in that answers with a token in JSON** (`token-field`) is not asked: the next page is the script's choice,
  and no request sees it.

The scripted app follows `next` to its own pages, and has two flaws: following it anywhere, and following anything
that begins with `/`. Three guards were broken in turn: the `//` address left out, the host compared by its start, and
sign-out skipped. Each was caught by a test. Not yet run against a real app.
