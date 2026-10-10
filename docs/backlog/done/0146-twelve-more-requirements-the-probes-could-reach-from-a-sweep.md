# Twelve more requirements the probes could reach, from a sweep of everything they cannot

**Status:** done, as its markers read on 8 October 2026

An analysis on 26 September 2026 (session securevibe-e9) of all 260 ASVS requirements no check
names, lowest level first. Not claimed; each line below is its own piece of work, and the machinery
each needs already exists. Counts are from `docs/COVERAGE.md` at the time: 25 uncovered at Level 1,
146 at Level 2, 89 at Level 3.

**Four of the five Level 1 lines are done on 26 September 2026 by session securevibe-e9**:
V2.2.2, V7.2.1, V15.3.1 and V14.3.1. Level 1 goes from 45 to 49 of 70. See DESIGN, "Four more
Level 1 questions". The four Level 2 lines are claimed by the same session.

**V1.2.2 was attempted and withdrawn.** The entry said "a rule in the same shape as
`ast.download-piped-to-shell`", and that was wrong: every rule in `data/ast-rules.json` matches a
*call*, with patterns for the function and the module it came from. A `javascript:` or `data:`
URL is a string literal, which may be assigned rather than passed to anything, and `sv` has no
way to scan literals on their own — the one requirement reached that way, V4.4.1, is semgrep's,
not `sv`'s. Writing it would mean a new kind of rule, which is its own piece of work and belongs
with the other "needs a new mechanism" items rather than being smuggled in here.
**V4.4.1 as `sv`'s own rule claimed on 26 September 2026 by session securevibe-e8.** Semgrep's
`detect-insecure-websocket` is in no pack the adapter runs, so the honest count lost V4.4.1. A
string literal can be matched after all, by a query that captures the literal itself; the rule is
a `ws://` address to another computer, and it needs a way to be finding-only, since not seeing one
is not every socket being encrypted. **Done the same day:** `ast.plaintext-websocket-url` in all
fourteen languages, with `findingsOnly`, a new field for AST rules; Level 1 goes from 52 to 53 of
70. See DESIGN, "A `ws://` address written into the code". The same way would reach V1.2.2's
`javascript:` literal, but that was withdrawn for what it means, not for how to match it.

**Level 1 — 25 uncovered, 5 look reachable.** The rest are documentation (V2.1.1, V6.1.1, V8.1.1,
V15.1.1 → the security-notes file), deployment (V3.4.1, V12.2.1 → the production check), the
authorization server (V10.4.1–V10.4.5, which apply to almost nobody now that they are scoped),
`manualOnly` (V2.3.1, V12.2.2), or a flow between two places that `sv`'s rules cannot follow
(V1.3.1, V9.1.3, V2.2.1).

- **V2.2.2 — validation on the server, not only in the browser.** Read the sign-up or create form
  for the constraints it states in its own HTML (`maxlength`, `pattern`, `type=number`,
  `required`), then send a value that breaks one directly. A server that accepts what its own form
  forbids is relying on the browser. `tags` and `attribute` in `signed_in.rs` already read forms
  this way for the password-field checks.
- **V7.2.1 — a made-up session token is refused.** The probes know the session cookie's name and
  shape from a real sign-in. Send a private-page request carrying a fabricated value of that shape:
  if the page opens, the token is not being checked against anything. Distinct from V7.2.3, which
  is about whether the value is guessable rather than whether it is verified.
- **V15.3.1 — a record hands back more than it should.** The `owned` record is already read back.
  Scan that response for field names that should never leave the server — `password`, `hash`,
  `salt`, `secret`, `token`. Only ever a finding: not seeing them proves nothing about the fields
  this app happens to have.
- **V14.3.1 — `Clear-Site-Data` when signing out.** The sign-out response is already in hand in
  `logout_check`. Credit on presence only: the client can also clear up by itself, so absence is
  not a failure. Partial evidence, and the report has to say so.
- **V1.2.2 — `javascript:` and `data:` URLs built in code.** A rule in the same shape as
  `ast.download-piped-to-shell`. Only ever a finding.

Worth a judgment call rather than code: **V8.3.1** (authorization enforced at a trusted service
layer) is arguably already demonstrated by `probe.admin-page-ordinary-user` — an ordinary user is
refused the admin page by the server, whatever the browser was told. Citing it would cost nothing
and settle a Level 1 requirement, but it is a citation being stretched, so somebody should decide
rather than it being slipped in.
**The owner's decision, 27 September 2026: supporting evidence only.** The admin page refused to
an ordinary user is shown beside V8.3.1 and strengthens the owner's answer, but does not settle
it: one page refused is not every rule enforced on the server, and actions sent straight to an
API are not tried. The same standing as V2.3.1's refused skips. **Claimed the same day by session
securevibe-e2.**
**Done the same day:** V8.3.1 is on `manualOnly`, and `probe.admin-page-ordinary-user` cites it
beside V8.2.1, so a refusal is listed as support and an opened page is a finding against both.
ASVS "supporting only" goes from 5 to 6; nothing more is counted as settled. See DESIGN, "The
admin page, as support for V8.3.1".

**The four Level 2 lines below are done on 26 September 2026 by session securevibe-e9** (V16.2.1,
V16.2.2, V5.4.1, V5.4.2). Level 2 goes from 36 to 40 of 183. See DESIGN, "What a log line and a
download carry".

**Level 2 — 146 uncovered, 4 look reachable now**, all of them because of machinery added in the
last few days rather than anything new:

- **V16.2.1 and V16.2.2 — what a log line carries.** The log check already finds the line holding
  its own marker. V16.2.1 asks for when, where, who and what; V16.2.2 asks that the timestamp is
  UTC or carries an explicit offset, which is a thing that can be parsed exactly. Both read the
  line that is already found, and both credit only on presence, as that check does.
- **V5.4.1 and V5.4.2 — the name a file comes back under.** The upload check already fetches a
  file back and already reads `Content-Disposition` for V3.2.1. V5.4.1 asks that the header names
  a file; V5.4.2 asks that a hostile name is encoded rather than breaking the header, which is
  tested by uploading one containing a quote and a semicolon and reading what comes back.

V7.3.1 and V7.3.2 (idle and absolute session timeouts) are reachable too, and belong to the
policy-numbers work rather than here.

**Level 3 — 89 uncovered, and this is the honest part: close to nothing is reachable.** What is
there is the authorization server's internals (5), WebRTC media (4), safe concurrency (4), MFA
(3), and HTTP message structure (4) — design and deployment questions, or protocol work for
technologies almost no small app runs. Level 3 stays a person's job, and saying so is better than
a sweep that keeps rediscovering it.
