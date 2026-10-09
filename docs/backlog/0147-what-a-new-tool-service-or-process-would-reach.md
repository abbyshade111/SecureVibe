# What a new tool, service, or process would reach

**Status:** partly done: 4 of 10 parts done, 3 claimed, 1 open, as its markers read on 8 October 2026

The follow-on question to the sweep above,
asked by the owner on 26 September 2026 and answered by session securevibe-e9. After the Level 1
and Level 2 work from that sweep, 251 ASVS requirements have no check. About 45 of them come
within reach with one of the additions below; the other ~200 are documentation (the
security-notes file), design, cryptographic internals, WebRTC, or an authorization server's own
workings, and stay a person's job. Ordered by what each buys for what it costs. Nothing is
claimed.

1. **More of the same machinery, no new tool (~6).** **Four done on 26 September 2026 by session
   securevibe-e9**: V16.2.4, V4.3.1, V4.3.2, and V4.4.2; level 2 goes from 40 to 44 of 183. See
   DESIGN, "GraphQL, WebSocket, and a log line's format". V4.4.3 and V4.4.4 (a WebSocket's own
   session) are not done: they need to know whether the connection is meant to be private, which
   no entry says yet. **V4.4.3 and V4.4.4 claimed on 26 September 2026 by session securevibe-e9**,
   with a `private-websocket` entry under `[stack.run.users]` saying which socket needs a sign-in. **Done the same day:** V4.4.4 is credited when handshakes with no
   session and with a made-up one are refused where the signed-in one upgrades, and V4.4.3 is a
   finding when a signed-out session still opens the socket. Level 2 goes from 63 to 65 of 183. Left
   over: V4.4.2 for a private socket, which the anonymous check cannot ask. See DESIGN, "V4.4.3 and
   V4.4.4, a private WebSocket's session". **V4.4.2 for a private socket
   claimed on 26 September 2026 by session securevibe-e9**: the foreign-origin handshake sent with the
   signed-in session, beside the others. **Done the same day**; no level changes, since V4.4.2 was already
   counted through the anonymous probe.
   Whether the log line the log check already finds is in a common format —
   JSON, logfmt, or the common log format (V16.2.4). And small
   manifest entries naming a GraphQL path and a WebSocket path: an introspection query and a
   request of a thousand aliases (V4.3.2, V4.3.1), and a handshake from a foreign `Origin` and
   one with no session (V4.4.2–V4.4.4).

   *Corrected from the first version of this entry*, which counted eleven. Tampering with a
   signed token cannot reach V9.2.2 or V9.2.3: changing `aud` or `typ` changes what was signed,
   so a correct app refuses it for the signature and says nothing about whether it checks the
   audience. It only shows an app that verifies no signature at all, which is V9.1.1 and already
   reached; V6.8.2 is about an identity provider's assertions and belongs to item 2. And
   parameter pollution (V15.3.7) has no result that means anything without knowing the app.
   V15.3.5 (type confusion) was in this list and is taken out of it: a probe for it sends
   sign-in requests shaped to get in without the password, and that is not a thing this
   session will build. It stays unclaimed. A
   **The owner's decision, 6 October 2026: no**; V15.3.5 is not probed ("I agree with all your recommendations", 6 October 2026). A
   "too-deep" GraphQL query needs the schema, which introspection being off withholds; a
   thousand aliases of `__typename` needs none.
2. **A mock identity provider inside the fence (~10, all Level 2).** One small container — an
   OIDC provider made for tests — that the app is pointed at for the run, so the probes can
   drive a real sign-in and then replay the code, drop the `state`, reuse the `nonce`, change
   `aud`, and serve metadata for a second provider (V10.1.2, V10.2.1, V10.2.2, V10.5.1–V10.5.4,
   V6.8.1, V6.8.2, V6.8.4). The largest single gain, and it lands exactly on the OAuth *client*
   requirements the authorization-server fix left applying to every "Sign in with Google" app.
   **Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking, scoped to the
   five a single test provider can show: V10.1.2 and V10.2.1 (a sign-in finished in a session
   that did not start it), V10.5.1 (a wrong `nonce`), V10.5.4 (a wrong `aud`), and V6.8.2 (an
   unsigned token, and one signed with the wrong key). The provider is `sv`'s own — a short
   script in a stock Node image on the fenced network — because it has to misbehave on purpose,
   which no ready-made test provider does. Left for later: V6.8.1 and V10.2.2 need two providers,
   V10.5.3 needs metadata an app reads at start-up to change, and V10.5.2 and V6.8.4 depend on
   what the app decides rather than on what the provider sends. **The five are done the same
   day:** a `[stack.run.oidc]` section starts the test provider, and Level 2 goes from 58 to 63 of
   183. On the way it found that the sidecar's `echo | nc` cut the connection before a slow Node
   route could answer, which affected every run. See DESIGN, "A pretend "Sign in with Google"
   inside the fence". **V10.2.2 claimed on 26 September 2026 by session securevibe-e8**: it needs no
   second provider after all, since the one provider can name another in the sign-in's `iss`
   parameter and in the ID token's `iss` claim, and an app that refuses both has the defense. **Done
   the same day**, credit only; Level 2 goes from 62 to 63 of 183. See DESIGN, "Which provider a
   sign-in came from".
3. **A mail sink inside the fence (~7).** A container that accepts the app's email and lets the
   probes read it. Password reset stops needing a person: the reset link can be used twice,
   used late, and inspected for how guessable its code is (V6.4.1, V6.4.3, V6.5.1, V6.5.4,
   V6.5.5, V6.6.2, V6.6.3). The unclaimed password-reset item is built on this. **Claimed on 26
   September 2026 by session securevibe-e9**, with the password-reset item it carries. **The mail
   server and password reset are done the same day:** a `reset` entry under `[stack.run.users]`
   starts Mailpit on the fenced network, and the probes follow the reset email to find a link
   that works twice, an old password that survives, a guessable code (V6.4.3), and an answer that
   tells whether an address has an account (V6.3.8). Level 2 goes from 44 to 45 of 183, Level 3
   from 3 to 4. See DESIGN, "A mail server inside the fence, and password reset". The count above
   was wrong: V6.5.1, V6.5.4, V6.5.5, V6.6.2, and V6.6.3 are about codes sent to sign *in*, and a
   reset code is not one. They need an `email-code` entry — a magic link or an emailed second
   factor — on the same mail server; V6.5.5 needs the slow mode as well, and V6.4.1 needs a
   sign-up that emails an activation code. The `email-code` entry (V6.5.1, V6.5.4, V6.6.2,
   V6.6.3) is **claimed on 26 September 2026 by session securevibe-e9, and done the same day**:
   V6.5.1, V6.5.4, V6.6.2, and V6.6.3 at Level 2, which goes from 45 to 49 of 183, with
   `[policy] failed-codes` as the stated number for guessing. See DESIGN, "Signing in with an
   emailed code".
   **V6.4.1 (an activation code emailed at sign-up) and V6.5.5 for emailed codes (their lifetime,
   with `sv run --slow`) claimed on 26 September 2026 by session securevibe-e9.** V6.4.1 is **done the
   same day**, finding only: an `activation` entry, codes that count up or are short, and a link
   that signs in twice. Level 1 goes from 52 to 53 of 70. See DESIGN, "An activation code emailed
   at sign-up". V6.5.5 for emailed codes is **done the same day** under `sv run --slow`: a code
   used ten minutes after it was asked for is a finding if it signs in, and credited only when a
   fresh code then works. V6.5.5 was already counted, through the two-factor check, so no level
   changes. See DESIGN, "How long an emailed code lasts".
4. **A seeded TOTP secret (2).** Not a tool: the `seed` script makes a user with two-factor sign-in
   and hands `sv` the secret, and `sv` computes the codes itself (RFC 6238) to try one twice and
   one late (V6.5.1, V6.5.5). **Claimed on 26 September 2026 by session securevibe-e8.** A third account, made by
   `seed` with `SV_TOTP_SECRET`, so A and B keep signing in with a password alone; a `totp`
   entry for the code step; and the codes computed by `sv` (HMAC-SHA1, RFC 6238) — the current
   one as the control, the same one again, one from five steps back, and a fresh one after the
   next step begins. V6.5.5 needs no slow mode this way: an old code is computed, not waited for.
   **Done on 26 September 2026.** Level 2 goes from 54 to 55 of 183. The order changed on the way:
   an old code tried after a used one is refused by the rule that stops reuse, whatever its age,
   so it now goes first. See DESIGN, "Two-factor codes, computed rather than waited for".
5. **A slow mode (2).** `sv run --slow`, waiting out the idle timeout the owner states, then asking
   whether the session is dead (V7.3.1, V7.3.2). Belongs with the policy numbers. **Claimed on 26
   September 2026 by session securevibe-e9, and done the same day:** `idle-timeout-minutes` and
   `session-lifetime-minutes` under `[policy]`, held to by `sv run --slow`. Level 2 gains V7.3.1
   and V7.3.2. See DESIGN, "Session timeouts, waited out".
6. **A real browser (~6, and two existing checks made stronger).** Headless Chromium, run as a
   container inside the fence. It can see what only a browser decides: whether a request needs a
   CORS preflight (V3.5.2), whether markup submitted through a form executes when the page renders
   (V1.3.1 and the rest of V1.3), and whether authorization lives only in hidden buttons (V8.3.1).
   It also turns two partial checks into real ones — storage actually emptied after sign-out
   (V14.3.1, today only the header) and a sign-out link actually visible (V7.4.4, today only
   present in the HTML). **Claimed on 26 September 2026 by session securevibe-e8**, at the
   owner's asking. **The first part is done the same day:** `[stack.run.users.browser]` starts a
   pinned headless Chromium on the fenced network, signed in with the first user's cookies. It
   settles V3.2.2 (text typed into a form is shown as text, not drawn as markup), which only a
   semgrep finding could name before, and makes V7.4.4 real (the sign-out control can be seen,
   not only found in the HTML). See DESIGN, "A real browser inside the fence". The count above was
   wrong about which requirement the typed markup reaches: it is V3.2.2, content meant as text; V1.3.1
   asks for a sanitizer for rich text, which an app that shows text as text does not need and a
   browser cannot see being used. **V14.3.1 is done the same day as well:** a sign-in of the
   browser's own is signed out with the app's control, and what the app kept in the browser's
   storage for the signed-in person has to be gone. See DESIGN, "Signing out in the browser".
   **With that, the item is done.** Not part of it: V3.5.2 needs no browser (a request without a preflight can be sent directly) and belongs with
   the cross-site checks (**claimed on 26 September 2026 by session securevibe-e8, and done the
   same day**: the `owned` create request, when it is JSON, sent from another origin as
   `text/plain`, as a form, and as multipart, none of which a browser preflights; Level 1 goes from
   53 to 54 of 70; see DESIGN, "A request another site can send without asking"); V8.3.1 is an owner's answer and stays one. And one found on the way: an
   app that sends `Referrer-Policy: no-referrer` and refuses `Origin: null` refuses its own forms
   in every real browser, which a check could say directly. **Claimed on 26 September 2026 by
   session securevibe-e9**: the `owned` create request, sent again as the app's own page would
   send it under that policy (with `Origin: null` and no `Referer`), when the app's pages ask for
   `no-referrer`. A finding of its own with no requirement behind it, since nothing in ASVS asks
   an app to accept its own forms. **Done the same day**; see DESIGN, "An app that refuses its
   own forms".
7. **Taint analysis (~5 ASVS, and most of the AISVS rules).** An adapter reading CodeQL's SARIF
   — CodeQL already runs in this repository's own CI — or semgrep's taint mode. Every rule `sv`
   writes matches a call; none follows a value from where it came in to where it is used, which
   is what blocked V1.2.2, V1.3.1, V2.2.1, V9.1.3, V15.3.2, and the AISVS entry's "user input
   placed in the system instructions". The small in-`sv` half: a rule kind that matches string
   literals, for the literal `javascript:` URL V1.2.2 was withdrawn over. The CodeQL adapter is
   **claimed on 26 September 2026 by session securevibe-e9, and done the same day** for JavaScript,
   TypeScript, and Python: V1.2.9, V15.3.5, V15.3.6, V16.4.1, and V1.2.2 (as a finding only) with
   `--tools`, Level 1 to 52 of 70 and Level 2 to 53 of 183. See DESIGN, "CodeQL: following a
   value". Left over: V1.3.1, V2.2.1, V9.1.3, and V15.3.2 have no CodeQL query that fits them; Go,
   Ruby, and Java entries are the same data change with their own maps; and reading a SARIF file
   from the owner's own CI, rather than running CodeQL here, needs the report's commit compared
   with the code's before a clean result could be credited.
8. **The live site, with a TLS scanner (~5, mostly Level 3).** Beside `sv probe`: testssl.sh or
   sslyze for OCSP stapling and Encrypted Client Hello (V12.1.4, V12.1.5), the HSTS preload list
   (V3.7.4), a spoofed `X-Forwarded-For` to see whether rate limiting trusts it (V15.3.4), and,
   carefully and only on request, request smuggling (V4.2.1). The only item here that reaches
   outside the machine, so it follows whatever `sv probe` decides about the fence.
   **V15.3.4 claimed on 26 September 2026 by session securevibe-e8**, against the running app rather
   than the live site: `sv probe` sends only read-only requests, so it cannot make wrong sign-in
   attempts, and the brute-force check that finds the limiter already runs inside the fence. Once
   that check has seen the app refuse, one more wrong attempt claims a new address in
   `X-Forwarded-For`, then one more claims nothing; the first answered like the very first attempt
   while the second is still refused is a limiter believing an address the client made up. Only
   ever a finding. **Done on 26 September 2026.** See DESIGN, "A limit that believes a made-up
   address". Against an app whose limit counts by address and trips during the suite before the
   brute-force check, it is not asked; the report says why for V6.3.1, the brute-force check's own
   requirement, and does not name V15.3.4 there.
   **V12.1.5 and V3.7.4 claimed on 26 September 2026 by session securevibe-e9, and done the same
   day**, as more of `sv probe`: an ECH configuration in the site's DNS, asked of this computer's
   resolver, and the HSTS preload list from a copy the owner downloads (`--hsts-preload FILE`).
   Level 3 goes from 4 to 6 of 92. See DESIGN, "Two more things about the live site". Left out:
   OCSP stapling (V12.1.4), which could not be observed from the machine this was built on (its
   only way out intercepts TLS); **claimed on 29 September 2026 by session securevibe-e10**, at the owner's
   asking, from a machine where a stapled answer was observed (DigiCert's and Microsoft's sites, the
   certificate seen being the site's own), in branch `claude/ocsp-stapling`; **done the same day**: `sv probe` reads
   whether the certificate names an OCSP responder from the handshake it already makes, and asks for the
   stapled status only when it does, still within four requests (DESIGN, "OCSP stapling, from the
   handshake `sv probe` already makes"); and request smuggling (V4.2.1), which means
   sending a live site deliberately malformed requests, which `sv probe`'s read-only rule does
   not allow.

9. **Named pages for sign-up, password change, and one multi-step flow (3).** No new tool: three
   addresses in `[stack.run.users]`, the way `upload` names one. Try `Password123!` (V6.2.12, L2),
   the app's own name as a password (V6.2.11, L2 — the app's name is always a context-specific
   word, so one case needs no word list), and the last step of the flow in a fresh session
   (V2.3.1, L1, on `manualOnly` today, so taking it off is a decision). The guard not to get wrong
   is the one the brute-force check got wrong first: an app that refuses *every* password has shown
   nothing, so an ordinary one must be accepted first, or the answer is *not assessed*.
   **V6.2.12 and V6.2.11 claimed on 26 September 2026 by session securevibe-e8**, through the
   `signup` entry that already exists, so no new addresses are needed for them: a password from far
   down `data/knowledge/common-passwords.txt`, and one built from a word in a new
   `[policy] context-words` list — the documented list V6.2.11 names — each beside a random
   password of the same shape. **V2.3.1 claimed on 26 September 2026 by session securevibe-e8:**
   a `flow` entry naming the steps and what the last one shows when it really finished; A goes
   through in order as the control, and B jumps to the last step, and skips the middle. V2.3.1
   stays on `manualOnly` at the owner's word, so a refusal supports it and a skip that works is
   a finding. (Asked again on 27 September 2026 whether two refused skips should settle it; the
   owner's answer: no, it stays a person's check. Trying a repeated step is the way to strengthen
   it, not a lower bar.) **Done the same day**: see DESIGN, "Skipping a step (V2.3.1)". Doing a step twice
   and other wrong orders are not tried. **A step done twice and the wrong order claimed on 7 October 2026 by session
   securevibe-e9**, at the owner's word ("Trying a repeated step is the way to strengthen it"), in branch
   `claude/securevibe-e9-flow-order`: as B in a fresh session, the first step sent as many times as there are steps
   before the last and then the last, and the steps between first and last sent before the first and then the last.
   Repeating the last step after the flow finished is left out on purpose: an app's answer cannot tell "done now"
   from "already yours", the false alarm the owner settled for `probe.action-done-twice` on 5 October 2026.
   **Done the same day** (DESIGN, "Later, 7 October 2026: a step done twice, and the wrong order"). The order of
   the tries turned out to be a guard of its own: with progress kept against the account, the skip past the middle
   left a correct app holding B at step two, and the wrong order after it finished, so the wrong order now goes
   second. Five guards broken in turn, each caught. Not yet run against a real app in a container.
   **V6.2.11 and V6.2.12 done on 26 September 2026.** Level 2 goes
   from 49 to 50 of 183: V6.2.11 can be settled; V6.2.12 is *supporting only*, because it is on
   the shared `manualOnly` list and one refused password is not the whole breached set. The
   password list's source is not recorded anywhere in the repository, and checking the chosen
   password against Have I Been Pwned was refused by this environment's network policy, so the
   finding says "one of the 100,000 most common" rather than "breached". See DESIGN, "Two more
   passwords at sign-up".

Additions from session securevibe-e8, which answered the same question separately on the same
day; the two answers are merged here rather than kept as two entries. To item 5: the alternative to
waiting is a test configuration with timeouts of seconds, which shows the mechanism works and not
that production's number is the stated one, so it is partial evidence and has to say which half it
saw. To item 6: V14.2.3 (L2 — list the requests that go to another host while signed in, and look
in them for the test account's own details; only ever a finding) and V3.4.3 (L2 — the policy
enforced, not only sent). **V14.2.3 claimed on 27 September 2026 by session securevibe-e2**, at the
owner's asking to pick a backlog item: the real browser records every request a signed-in page
tries to send to another host (the fence stops it leaving), and the test account's details found in
one are a finding. **Done the same day:** the browser driver's `outside` action lists those requests, and the
test account's email address (as written, encoded into a web address, base64, or SHA-256), password
(as written or base64), and session cookie found in one are a finding, never printed. Only ever a
finding: scripts a page loads from other sites cannot arrive inside the fence, so what they send is
not seen, and the run lists the sites the pages tried to reach so the owner can look. See DESIGN,
"What the signed-in pages send to other sites". To item 8: V12.1.1 (L1) and V12.1.2 (L2), the protocol versions and
ciphers the live site offers, where semgrep today sees only TLS settings written in code; a scan
is dozens of handshakes, so what `sv probe`'s four-request cap means for it needs deciding first.
**The owner's decision on V12.1.2, 6 October 2026:** leave it unchecked, keeping `sv probe` to four requests, and
have the report say how to check it with a dedicated scanner such as testssl.sh. **Claimed the same day by session
securevibe-e9**, in branch `claude/securevibe-e9-owner-small`.
**Done the same day** (DESIGN, "Four of the owner's decisions of 6 October 2026"): a `human-checks.json` entry the
report shows beside V12.1.2, naming testssl.sh and SSL Labs' online test.

Items 2, 3, and 6 are containers on the fenced network, so they keep `sv`'s rule that nothing
reaches outside; only item 8 does, and only to the owner's own address.

**The owner's decision, 9 October 2026**, asked by session securevibe-e2 with a recommendation for each open choice: **yes to part 7's leftover, reading a CodeQL SARIF file from the owner's own CI, as recommended:** a clean result is credited only when the file's commit is the commit of the code being checked; any other file is reported and credits nothing. Not claimed yet.
