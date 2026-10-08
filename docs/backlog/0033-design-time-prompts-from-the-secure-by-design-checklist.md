# Design-time prompts from the Secure by Design checklist

**Status:** open

Proposed on 4 October 2026 by session securevibe-e2,
at the owner's asking to look at the Secure by Design documentation and checklist for prompts to add to the library
above. Prompts the owner gives the AI coding tool before any code is written. Every Secure by Design control is
manual-only, so no check can ever settle one; a prompt here is shown working only through an ASVS requirement
`data/sbd-asvs-crosswalk.json` pairs with it and `sv` does check. Left out: the controls about meshes, queues,
gateways, sagas, and cross-service contracts (AS-02 to AS-06, AS-08, DM-04, DM-06, RR-03, RR-04, AC-04), which
`data/applicability-v2.json` already drops for an app of one service, and which would push machinery onto a
beginner against the checklist's own "simplicity" principle.
**The owner's decisions, 4 October 2026:** all the suggestions, yes. The testable batch first; the rest kept here
as a resource, marked as not shown working by any check. Each prompt names the Secure by Design controls it helps
answer (never "meets": a control is still answered by a person) and the ASVS requirements its check speaks to.
The same test as the library's: an app built with the prompt passes the check, one built without fails it.

**Testable, through a check `sv` already has:**
1. **Who may do what.** Each kind of user and what they may see and change, refused by default and enforced on the
   server. SBD-AC-03 (V8.1.1, V8.2.1). Shown by `probe.private-page-anonymous`, `probe.admin-page-ordinary-user`,
   `probe.admin-action-ordinary-user`, and the record read as another user.
2. **Actions that must happen once.** Booking, paying, voting: protected against repeated and simultaneous
   requests. SBD-RR-05, SBD-DM-03 (V2.3.4). Shown by `probe.action-done-twice`.
3. **Limits on abuse.** Per-user limits decided and written into `securevibe.toml` (`requests-per-minute`,
   `failed-sign-ins`). SBD-RR-07 (V2.4.1, V6.3.1). Shown by `probe.create-rate-unlimited` and the password-guessing
   check, which run only once the numbers exist.
4. **What happens when something fails.** Time limits on every outside call, plain error pages, and what users see
   when the AI service or the database is down. SBD-RR-01, SBD-RR-06, SBD-AS-07 (V16.5.1, V16.5.2). Shown by
   `probe.error-detail-leak` and `probe.ai-service-failure-handled`.
5. **A plan for keys.** SBD-AC-05 (V13.3.1). Folded into the library's own secrets prompt rather than written twice;
   left to the session that holds the library.
6. **What gets logged.** Sign-ins, refusals, and admin actions with time and user, never passwords or personal data,
   and how long kept. SBD-MT-01, SBD-MT-07 (V16.1.1, V16.2.1). Shown by `probe.log-line-metadata`; how long logs are
   kept is not.
7. **Sign-in decisions.** A proven sign-in library or provider, two-factor sign-in for admins, short-lived tokens,
   session limits written into `securevibe.toml`. SBD-AC-02 (V7.3.1, V9.2.1). Shown by `probe.session-idle-timeout`
   (`--slow`) and `probe.app-token-expired-accepted`.

**Useful, and shown working by no check (listed apart):**
8. **The design brief.** What the app is for, who uses it, what it holds, whether it faces the internet, sign-in,
   payments, AI features: written as `securevibe.toml` before any code, which decides what applies. Process steps 1
   and 2. Extends the library's first lesson. The natural first prompt of the whole library.
9. **When to bring in a person.** The tool says plainly whether the app meets any escalation trigger (sensitive or
   regulated data, new exposure to the internet, unfamiliar technology, a service whose failure would matter a lot)
   and, if so, recommends a person's review or `sv`'s threat-modeling questions. The checklist's escalation triggers.
10. **A list of the app's data.** Each kind, how sensitive, how long kept, when deleted; collect only what is needed.
    Fills the security notes' "How each kind of sensitive data is protected". SBD-DM-01, SBD-DM-05.
11. **Everything the app talks to.** The lines between browser, server, database, AI provider, and other services,
    and what is checked where something crosses one. Fills "Everything the app talks to". SBD-AS-01, scaled down.
12. **Safe defaults, fewer moving parts.** Every feature, address, and debug switch listed; what is not needed
    removed; defaults closed. Partly reached by the debug-mode, cross-site access, and header checks.
13. **"What we do if…", on one page.** For a solo owner: taking the app offline, replacing a leaked key, telling
    users. SBD-MT-06, one of the checklist's critical controls.
14. **Which rules might apply.** Children's data, health, card payments: flagged in plain words with a pointer to a
    person, never as legal advice. SBD-AC-06.
15. **Before changing a design.** Re-read `securevibe.toml` and the security notes, say which decisions a change
    touches, and update them first. The checklist's "design-drift watch".

**Prompts 1 to 4, 6, and 7 claimed on 4 October 2026 by session securevibe-e2**, at the owner's word, in branch
`claude/securevibe-e2-design-prompts`, as a page of their own (`docs/prompts/design-time.md`) for the library's page
to link to, so the two sessions do not edit one file. Prompts 8 to 15 are not claimed.
**Prompts 1 to 4, 6, and 7 done the same day** (`docs/prompts/design-time.md`, `data/design-prompts.json`; DESIGN,
"Design-time prompts, tried"). Three were shown to work: 3, limits on abuse (V2.4.1, V6.3.1); 6, what gets logged
(V16.2.1, V16.2.2); and 7, sign-in decisions (V7.3.1). For 7, and for 3's password limit, what the prompt changed is
that the number was decided and written down: the builds without it had a timeout or lockout of their own choosing,
recorded nowhere. Three were not: 1 and 4, because both builds without them already passed; and 2, because `sv`'s
check accused the build made with it of booking twenty times when it booked once (its own item below). Prompt 6
was reworded once, after both builds with its first wording left the query string and status out of their log lines.
**Prompts 8 to 15 claimed on 4 October 2026 by session paper-facts**, at the owner's word, in branch
`claude/design-time-first` (item 8 of "Design-time help before any code", below).
**Prompts 8 to 15 done the same day** (`data/design-prompts.json`, `docs/prompts/design-time.md`, "Not tried yet,
and no check can show them"; ADR-028). Each is not tried and names no ASVS requirement; six name the Secure by Design
controls whose statements fit, two name none.
