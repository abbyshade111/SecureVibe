# One action, one race, one redirect, one SVG: checked in part (10 October 2026)


Backlog 0006, part 4, the rest: the gap analysis's finding 1.7. Built by session securevibe-e2.

**The problem.** ADR-053 made *checked in part* a status of its own, for V8.2.2 when only reading another user's record
was tried. The other running checks were left to be read one by one. An inventory of them found about fifty that give
plain *checked* from one sample where the requirement asks about every response, page, record, action, or operation.

**What was built.** The four whose own scope already said they rest on one sample are now credited in part:
`probe.create-rate-unlimited` (V2.4.1), `probe.action-done-twice` (V2.3.4), `probe.fetch-follows-redirect` (V15.3.2),
and both credits of `probe.uploaded-svg-keeps-script` (V1.3.4). A requirement is *checked in part* when every check that
credits it is in part (`sv_report::status_of`), so another full credit still makes it *checked*.

**Proposed, not built.** The rest of the inventory, in groups: (A) one or two anonymous responses for headers, cookies,
content types, and errors where the requirement says every response; (B) one private page, one sign-in, or one session
for session handling; (C) one request for cross-site requests, a flow, or a WebSocket; (D) one upload route and one
file; (E) one log line or one event; (F) one browser page or form; (G) one of several operations the requirement names
(an email change for V7.5.1, which also names phone, MFA, and recovery; a password change for V7.4.3; sign-up only for
the password checks that also name password change; TOTP or an emailed code alone for V6.5.1 and V6.5.5); and (H) the
private and admin pages the owner lists. Excluded as host-wide or one-of-a-kind: TLS, DNS, the preload list, TRACE,
`.git`, GraphQL, the app's one sign-in provider, the password policy, session timeouts, and the guessing limits. The
owner decides how far this goes, since it lowers how many requirements a report calls checked.

**Tests.** Each check's existing credited test now also asserts the credit is in part.

**Broken on purpose, each put back:** the mark removed from each of the five credits in turn; each turned its check's
test red.
