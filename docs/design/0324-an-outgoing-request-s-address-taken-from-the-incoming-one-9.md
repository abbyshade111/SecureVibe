# An outgoing request's address taken from the incoming one (9 October 2026)

Finding 11 of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7 October 2026"): plain
`sv check` had no rule for request data flowing into an outgoing request, the flaw called server-side request forgery.
The running app's check (`probe.fetch-goes-anywhere`) finds it only when `sv run` can start the app and the manifest
names the fetching feature.

**The rule.** `ast.fetch-address-from-request` reports an outgoing request whose address is read straight from the
incoming request, or from a name set from it in the same function. It is only ever a finding, at high severity,
citing V1.3.6 and V13.2.4, as the running check does. It reads:

- **Python:** `requests` and `httpx` calls (`get`, `post`, and the rest) and `urlopen`, given a value from Flask's,
  Django's, or FastAPI's request (`request.args`, `request.form`, `request.json`, `request.GET`, `request.query_params`).
- **JavaScript and TypeScript:** `fetch`, `axios`, `got`, Node's `http` and `https`, `ky`, `superagent`, and `needle`,
  given a value from Express's or Koa's request (`req.query`, `req.body`, `req.params`, `ctx.query`) or a URL's
  `searchParams`.
- **Go:** `net/http`'s `Get`, `Post`, `Head`, `PostForm`, `NewRequest` (its second argument), and
  `NewRequestWithContext` (its third), given a value from the request's query or form or a router's parameters.

**What it leaves alone, on purpose.** An outgoing request built from a value is how every API client is written, so
the address must come from the request itself to be reported: one built from the app's settings is not. An address
that starts with a written-out `https://host/` is not reported either, since the request can then choose only the
path, never the server. A call with the same name on anything else (a cache's `get`, the app's own `app.get` route)
is not read. Other languages say so: not looked for yet, and finding none credits nothing.

**How it is held.** `crates/sv-check/src/ast/fetch_tests.rs`: for each language, the reported forms and the safe ones
side by side, and the rule only ever a finding. Six guards broken in turn, each caught: the request-data pattern
removed (the settings and cache cases reported), the fixed-host safe form removed, the finding-only mark removed,
names no longer followed, `NewRequest` judged by its first argument (the method), and any module's call read.
`docs/COVERAGE.md` and `docs/REQUIREMENTS.md` now list the rule under V1.3.6 and V13.2.4.
