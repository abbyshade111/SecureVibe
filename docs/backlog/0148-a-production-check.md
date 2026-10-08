# A production check

**Status:** done, as its markers read on 8 October 2026

`sv probe https://…`: read-only requests to the owner's own live address, for
what the repository cannot say. HSTS (V3.4.1), TLS with a publicly trusted certificate and no fallback
to plain HTTP (V12.2.1, V12.2.2), redirects to HTTPS only where a browser is the client (V4.1.2), and
the `__Host-` cookie prefix (V3.3.3), which only means anything over HTTPS. The rest of deployment
becomes a "before going live" list in the report. The fence and what the probes may send need
thinking through first: this reaches outside the machine, which nothing in `sv` does yet.
**Claimed on 26 September 2026 by session securevibe-e8.** The safety design is the substance: the
address comes from the command line and nowhere else, so a person typed it and no committed file
can aim it; GET and HEAD only, with no body, no cookies, and no Authorization header; a hard cap on
requests, so it is three or four and never a scan; and a redirect to a different host is refused
rather than followed, so nothing can drag the probe somewhere the owner did not name. TLS
verification enforced rather than skipped is itself the V12.2.2 check. **Done on 26 September
2026.** Four requirements — V12.2.2, V12.2.1, V3.4.1, V3.3.3 — and level 1 goes from 45 to 47 of
70. See DESIGN, "`sv probe`: the questions only the live site can answer". Running it against real
sites found two faults reasoning would not have: an error answer's headers read as the site's own,
and a proxy's CONNECT status line read as a response. Left over: V4.1.2 (redirecting only where a
browser is the client) needs a request shaped like an API client's and was not written, and the
rest of deployment is still a "before going live" list nobody has written.
**The "before going live" list claimed on 6 October 2026 by session securevibe-e9**, at the owner's word ("pick
your next backlog item"), in branch `claude/securevibe-e9-live-list`: for an app that will be on the internet, the
report lists the requirements only the live site can answer, says which `sv probe` asks (and the command), and
which are the owner's to check by hand. It credits nothing.
**Done the same day** (DESIGN, "Before going live: what only the live site can answer"): a section in
`compliance.md`, `report.html`, and `report.json` for an app on the internet, each line with the `sv probe` command
that asks it, or, for V12.1.2, the scanner; held to the requirements `sv probe`'s checks cite.
**V4.1.2 claimed on 6 October 2026 by session securevibe-e9**, at the owner's word ("Yes, please go ahead with
both of those", asked whether `sv probe` may make one more request), in branch `claude/securevibe-e9-api-redirect`.
**Record, `Status: proposed`** (to be a "Later" entry on ADR-027): `sv probe <address> --api <path>` asks one more
question, only when the owner names an address of the app's API on the command line: a GET over plain HTTP to that
path on the same host, shaped like a program's request (JSON accepted, no browser headers). Answered with a redirect
to HTTPS is a finding against V4.1.2; anything else credits nothing, since one address is not every endpoint. A run
with `--api` may make five requests; without it, still four. Without `--api`, V4.1.2 is not assessed, and says why.
**Done the same day**, and the record accepted (ADR-027, "Later, 6 October 2026"; DESIGN, "V4.1.2: an API asked
over plain HTTP the way a program asks").
