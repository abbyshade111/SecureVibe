# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- **The fence test can pass without proving anything.** Found on 26 September 2026 running the suite
  on the owner's Mac (Docker Desktop). **Claimed on 26 September 2026 by session
  admiring-murdock-875699. Done the same day:** with `--internal` removed the test now fails
  (`Some(0)`), with `nc` renamed to a program that does not exist it fails (the control reports 127;
  the old test passed that case), and with a dead address it fails (the control reports 1).
  `the_fence_really_blocks_outbound_traffic` in
  `crates/sv-run/tests/fence.rs` counts *any* failure of `docker exec … nc` as "blocked": `nc` missing
  from the image, a flag it does not understand, or the container gone would all pass. And its only
  control is the host reaching `1.1.1.1:53`, but on Docker Desktop containers run in a separate Linux
  VM, so the host getting out does not show a container could. Fix: a control container on an
  ordinary network created the same way minus `--internal`, running the identical command, which
  must connect; and the fenced run must show that `nc` really ran and failed to connect.

- **A leaky guessing limit makes `probe.forwarded-for-trusted` say the opposite of the truth, in
  both directions.** Found on 26 September 2026 reviewing #130/#131. **Claimed on 26 September 2026
  by session securevibe-e9, and done the same day** with the fix below: two claimed attempts from two
  addresses, then two plain ones. `forwarded_check`
  in `crates/sv-check/src/signed_in.rs` sends one wrong attempt claiming `203.0.113.77` and one
  claiming nothing, and calls it a finding when the first is answered as the first attempt was and
  the second is still refused. That pattern is produced by any limiter that lets one attempt through
  per interval — a token bucket, a sliding window, `nginx limit_req`, `express-rate-limit` — whatever
  it thinks about addresses.

  Reproduced with a fake app whose limit releases one attempt each time it refuses one
  (`lockout_leaks`), a limit counting by address, `locks_out_after: Some(6)`, `policy(Some(6))`:

  | limiter | reads X-Forwarded-For | finding |
  |---|---|---|
  | steady | no | none — correct |
  | steady | **yes** | **found** — correct |
  | leaky | no | **found — a false positive on a correct app** |
  | leaky | **yes** | none — **a false negative on the real flaw** |

  The two errors swap places: the leak invents the finding on the app that ignores the header, and
  hides it on the app that trusts it, because the same leak lifts the plain control too. And the
  evidence line for the false positive is **character-for-character the one for the true positive** —
  *"answered 403, as the first attempt was; one more claiming nothing: still refused (429)"* — so
  nobody reading the report can tell them apart. The finding's own words then assert the wrong
  conclusion: *"Nothing sits in front of the app here, so the address came from the request itself."*

  **A tested fix.** Two spoofed attempts in a row, each from its own address (`.77`, `.78`), then two
  plain ones; credit the finding only when both spoofed attempts were answered as the first was and
  both plain ones were refused. A one-per-interval leak releases one of the two, so the pattern
  breaks. Measured against the same four rows: the false positive goes, the three correct outcomes
  stay, and the full suite still passes (367 tests). The false negative stays — a leaky limiter still
  hides a genuinely header-trusting app — which is the safe direction and probably needs timing to
  do better; the check is finding-only, so nothing is credited either way.

  Note also that alternating the attempts (plain, spoofed, plain, spoofed) does **not** work, and it
  is the first thing that comes to mind: a limiter releasing one attempt in two produces exactly that
  alternation.

- **The two-factor reuse check credits V6.5.1 when the time step rolls over mid-check.** Found on
  26 September 2026 reviewing the TOTP probes (#129). **Claimed on 26 September 2026 by session
  securevibe-e9.** `totp_checks` in
  `crates/sv-check/src/signed_in.rs` reads the step once, at the top, and computes `current` from it.
  Three sign-in attempts later, that code is given again to see whether the app takes it twice. If the
  30-second step has ended in between — the run starts at a uniformly random point inside its step, so
  this is ordinary, not rare — the app is refusing a code that is *stale*, not a code that is *used*,
  and the probe reads the refusal as the app doing the right thing.

  Reproduced rather than argued. A fake app with `totp_reusable` switched on, a clock that moves on
  with every request, and a run starting four seconds before a step boundary:

  | seconds per request | V6.5.1 |
  |---|---|
  | 0, 1 | finding, correctly |
  | 2 | not assessed: *"The current code ... did not sign the two-factor account in ... Check `totp` in securevibe.toml, and that `seed` enrolled the account"* |
  | 3 | **credited as verified**, and the steps line reads *"the same code again: refused"* |

  An app that reuses codes is reported as one that does not. The two paths differ in which side of the
  boundary the *control* lands on; the 2-seconds row is only noise, but it blames the owner's manifest
  for something that is not wrong with it.

  It needs an app that accepts the current step alone, with no drift tolerance either side — which is
  what V6.5.5's own sentence asks for, a 30-second lifetime. So the apps that are strictest about
  V6.5.5 are exactly the ones whose V6.5.1 failure is hidden. The existing tests cannot show it: the
  fake app's clock stands still except during `wait`, so no test run ever crosses a boundary.

  The fix is small — read the step again after the reuse attempt, and when it is not the step
  `current` was computed for, report V6.5.1 not assessed (or recompute and try once more) rather than
  crediting it. The same reasoning as the ordering fix the same pull request already made: a refusal is
  only evidence when it can have no other cause.

  **Also worth saying, smaller:** V6.5.5 says a TOTP has "a maximum lifetime of 30 seconds", and the
  probe shows a code from five steps back being refused. That demonstrates *a defined lifetime*, which
  is the requirement's first clause, and not the 30-second bound. The suite's correct app accepts one
  step either side, so an app accepting 60-second-old codes is credited with V6.5.5 today. Tolerating
  drift is the right engineering call; the evidence line should say which of the two clauses was shown.

- **The threat model's 101 citations are outside the citation guard, and it cannot be pointed at them.**
  Found on 26 September 2026 reviewing the threat model; not claimed. `data/knowledge/threats.json`
  cites 101 distinct requirements across 42 threats. Every one resolves — the `AC-NN` class is clean —
  but nothing compares a threat with the requirement it cites, and this is the fifth citation surface
  in a codebase where four of them were wrong when first read.

  Extending `crates/sv-check/tests/citations.rs` to cover it does not work, and that is the useful
  part. Running its own comparison over the file flags **52 of the 101 pairs**, and every one that was
  read is correct — T-02 "a signed-in person opens administrator pages" against V8.2.1 "function-level
  access is restricted to consumers with explicit permissions"; T-03 "someone denies having signed in"
  against V16.3.1 "all authentication operations are logged". The guard assumes a right citation shares
  vocabulary with its requirement, and that assumption breaks here by design: a threat is written in
  plain language for somebody who is not a programmer, and ASVS is written in formal terms for
  somebody who is. Turning the guard on would mean 52 false alarms, which is how a guard gets switched
  off.

  The crosswalk already solved this exact shape. `data/sbd-asvs-crosswalk.json` pairs a terse control
  with an ASVS requirement it could not share words with, so each pair carries a few words naming what
  the two ask in common, and the guard holds that phrase against *both* texts — a stricter test than
  either side alone. The same per-pair phrase would work here, and would make the 101 citations
  checkable without asking plain English and ASVS to use the same words.

  All 52 flagged pairs were read by hand on 26 September 2026 and none is wrong; this is about what
  happens to the hundred and second.

  **Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking. **Done the same
  day, without a new file:** every citation already carries a `because`, and all 115 of them (101
  distinct requirements) share vocabulary with both the requirement and the threat under the
  guard's own comparison. The guard now reads them, and holds each against its threat as well. It
  also found that an empty or wordless phrase passed every guard, here and in the crosswalk, which a
  third test now refuses. See DESIGN, "The threat model's citations, and the bridge phrases already
  written".

- **Investigate MITRE ATLAS for the threat model.** Asked for by the owner on 26 September 2026:
  how feasible it would be, whether it adds anything of value, and whether it is worth it. ATLAS
  (Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE's catalog of how AI
  systems are attacked — tactics and techniques such as prompt injection, poisoning the data a model
  learns from, and extracting a model — with case studies of attacks that really happened. The
  investigation should answer, with evidence rather than impressions:

  - **Overlap.** How much of what ATLAS covers is already reached through AISVS and its Appendix C,
    which `sv` loads, and through the AI threats already in `data/knowledge/threats.json`. What is
    left once both are subtracted is the value in question.
  - **Fit with the threat model.** Whether a threat could carry the ATLAS technique it corresponds
    to as a reference, the way threats already cite requirements, and whether that helps the owner
    — who is not a programmer — or only a security reviewer reading the report after them. ATLAS
    names describe attacks; the threat model describes what could go wrong for this app in plain
    language, and the two may not line up one to one.
  - **What it could check.** ATLAS describes attacks, not controls, so it may add nothing checkable
    on its own; say whether any technique gives a question the running-app probes or the code rules
    could ask that AISVS does not already prompt.
  - **Upkeep and terms.** How ATLAS is published (machine-readable data, and how often it changes),
    its license and what attribution it asks for, and what keeping a copy current would cost — the
    same questions the Pwned Passwords item had to answer.
  - **Applies only to apps that use AI.** Most apps `sv` sees do not, so whatever is added must be
    gated on the `ai` condition like the rest of AISVS.

  The deliverable is a short written recommendation — adopt, adopt in part, or not worth it — with
  the numbers behind it, before anything is built. Not claimed.

- **An unanswered question excludes requirements when a corroborator found nothing.** Found on
  26 September 2026 reviewing the new manifest questions; not claimed. `ci-cd` and `iac` are claim
  conditions — `securevibe.toml` asks about them — and when the manifest does not answer, a
  corroborator that looked and found nothing answers `false` for it, which marks requirements *not
  applicable* rather than *not assessed*. On a manifest holding only `manifest-version` and
  `[app] name`, that excludes twelve requirements, eleven of them AC.12's CI/CD pipeline hardening.

  The report says in the same breath that this is not valid. Its own note for that state reads:
  *"Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as
  finding it absent."* There was no manifest word to take, and the sentence says why finding nothing
  should not settle it.

  The two states are also indistinguishable in the outcome. With `ci-cd` unanswered the claim is
  `unverifiable`; with `ci-cd = false` written down it is `confirmed` and *"the manifest and the code
  agree"* — and both exclude the same twenty-eight requirements. Meanwhile `hosted-scm` and
  `outside-contributors`, claim conditions with no corroborator, correctly stay *not assessed* and say
  so: *"Nobody has said. Requirements that turn on this are not assessed rather than excluded."* So the
  same silence is handled two ways depending on whether a corroborator happens to exist for it.

  `resolve` is where it comes from: `(None, Some(false)) => Some(false)`. That is right for the derived
  conditions — no GraphQL library in the lockfile really does answer `graphql`, and the manifest never
  asks — and wrong for a claim condition, where absence of a `.github/workflows` folder in an uploaded
  app is exactly the case the note describes. Sixteen of the twenty-eight exclusions on that manifest
  are derived and sound; the twelve from `ci-cd` and `iac` are not.

  This is the direction `sv init` calls the one that matters: "A capability present but denied is the
  one mistake that matters — it is how a real requirement gets marked not applicable."

  **Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking, before the
  threat-model citations, the mock identity provider, and the real browser. **Done the same day.**
  An unanswered claim now stays unanswered whatever the scan found; the twelve are AC.12.1–AC.12.8,
  AC.7.3, AC.7.4, AC.9.1, and SBD-AC-07 (eight of them AC.12, not eleven), and all twelve are now
  not assessed. See DESIGN, "Finding nothing does not answer for the owner".

- **A checklist for what only a person can check.** Asked for by the owner on 26 September 2026,
  after the report readability work: *"perhaps a checklist for the checks that have to be verified by
  a human, with a short description of how to verify them."* **Claimed on 26 September 2026 by
  session securevibe-e8.** Measured against a real report first, because two earlier estimates of the
  size were wrong: 98 applicable requirements can only be settled by a person — 40 ASVS (7 at level
  1, 33 at level 2), 21 Secure by Design, and 37 AISVS. Of the ASVS ones, 20 have no plain-language
  question yet; the security notes and design questions already cover the other 20. So the new
  writing is `data/human-checks.json` with one how-to-verify line each, and a report section that
  gathers all three sources, level 1 first. The 58 Secure by Design and AISVS controls get a group
  explanation rather than 58 lines: those standards are checklists already, and 58 more rows is the
  wall of text this work exists to remove. Nothing here credits anything — each stays unverified with
  the instruction beside it. **Done on 26 September 2026.** `data/human-checks.json` (20 entries),
  `crates/sv-check/src/human.rs` gathering all three catalogs, and a "What only you can check"
  section above the tests, level 1 first. See DESIGN, "What only you can check". Left over: the 58
  design-review controls are counted rather than explained, which is deliberate, and the 33 ASVS
  level 2 entries could use the same treatment as the level 1 ones if the owner wants them broken
  out.

- ~~**A clean credential scan claims V11.1.1 and C9.5.4.**~~ Withdrawn on 25 September 2026 by session
  securevibe-e8: not a fault. V11.1.1 and V13.3.1 are on `manualOnly` in `data/knowledge/applicability.json`,
  so a clean scan supports them and checks neither (pinned by
  `the_requirements_a_clean_scan_cannot_settle_include_the_ones_it_was_settling` and
  `end_to_end_a_clean_scan_supports_the_secrets_controls_and_checks_none_of_them`); the coverage count
  that suggested otherwise had not read that list. C9.5.4 is classified `scanner-clean` on purpose, and
  stays; `docs/COVERAGE.md` says what a clean scan does and does not show about it.

- ~~**A coverage document, generated.**~~ Done on 25 September 2026 by session securevibe-e8.
  `docs/COVERAGE.md`, written by `tools/coverage.py` from the checks' own citations and the
  manual-only list, and kept current by `crates/sv-check/tests/coverage_doc.rs`, which fails when it
  is not what the script would write. The script stops if a requirement id or check name is written
  into `sv`'s code that it does not know about.

- ~~**Level 1 checks against the running app.**~~ Done on 25 September 2026 by session securevibe-e8.
  V4.1.1 and V13.4.1 as anonymous probes; V6.2.1, V6.2.4 and V6.2.5 through `signup`, beside a control
  password; V6.3.2, V14.2.1 and V7.2.3 as findings only. Level 1 goes from 21 to 29 of 70. See DESIGN,
  "Level 1, asked of the running app". Left over: a password change (V6.2.2, V6.2.3) needs the manifest
  to say how one is made; rate limiting (V6.3.1) is a documentation requirement as much as a behavior.

- ~~**Requirements with no test naming them.**~~ Done on 25 September 2026 by session securevibe-e8.
  The report's "Tests to write" lists every applicable requirement with no evidence and no test
  naming it, lowest level first, and leaves out and counts what an app's tests cannot show; `sv mcp`
  gives the list to the AI coding tool and `sv init` tells it to work down it. See DESIGN, "Tests to
  write".

- ~~**`sv report` understates a gap that `sv sbom` states correctly.**~~ Done on 25 September 2026 by
  session securevibe-e9. The report builds an SBOM and asks it, instead of reasoning about dependencies
  from `scan_report.unpinned`: an unreadable ecosystem is now reported as an empty list rather than an
  approximate one, a manifest-declared one as what was asked for, and a fully locked one as no gap at
  all. The sentence was also wrong about pip in the other direction — `flask==3.0.0` does pin a version,
  and it said `requirements.txt` "pins no versions". See DESIGN, "The report asks the bill of materials".
  Left over: the report still does not carry the SBOM's incompleteness finding or run the advisory
  comparison, which is the other half of the entry this shares a root with.

  As originally found, on 25 September 2026 while reviewing the nested-manifest walk. For an ecosystem
  whose manifest versions `sv` cannot
  read, the report says the list holds what was asked for, when the list holds nothing at all. The two
  commands on the same app — a `package.json` with `"react": "18.0.0"` and no lockfile:

      sv sbom    npm is in use but nothing readable says which versions are installed,
                 so none of its packages are listed
      sv report  package.json pins no versions, so the list of dependencies is what was
                 asked for rather than what is there

  `sv sbom` is right, and puts a `securevibe:unread:npm` component in the CycloneDX document so a
  downstream reader sees it too. `sv report` builds its gap from `scan_report.unpinned` with one
  sentence for every ecosystem, and that sentence is true of pip — `flask==3.0.0` really is the version
  asked for — and wrong of npm, where no version in a `package.json` is read at all and that
  ecosystem's bill of materials is empty. A reader is told the list is approximate when it is absent.

  Same root as the entry about `sv report` not running the bill of materials or the advisory
  comparison: the report reasons about dependencies from the scan alone and never asks the SBOM, which
  already knows the difference and says it well. Rewording the sentence is probably the wrong fix — one
  sentence covering two ecosystems will be wrong about one of them again. **Claimed on 25 September
  2026 by session securevibe-e9.**

- **AISVS, beyond applicability.** One AISVS requirement has a check (C9.5.4). semgrep's `ai.*` rules
  (user input in a system prompt, model output executed, MCP servers) could be mapped to AISVS the way
  its security rules were to ASVS, with the citation guard reading each back, and `sv`'s own code rules
  could look for the same. Most of AISVS is about training and operating models and stays out of reach.
- ~~**More Level 1 from the ASVS pass.**~~ Done on 25 September 2026 by session securevibe-e8. From
  the 41 Level 1 requirements no check reached: signed-in questions for V6.2.8 (a password checked
  exactly as typed, not cut short or case-folded), V6.2.6 (password fields masked), V6.2.7 (paste not
  blocked), and V3.5.3 (sign-out and creating a record refused as a plain page visit); semgrep's rules
  for text written into a page as HTML against V3.2.2 and C#'s turned-off token expiry against V9.2.1,
  as findings only; then a `change-password` entry for V6.2.2 and V6.2.3. All done, with V6.2.9 beside
  V6.2.8 (see DESIGN, "Level 1 again"); creating a record by a plain page visit was left out, because
  telling whether a GET made one needs a page that lists them.

- ~~**Three more Level 1 questions.**~~ Done on 25 September 2026 by session securevibe-e8. V7.4.2
  (every session ends when an account is deleted, through a `delete-account` entry), V6.4.2 (no password
  hints or secret questions on the sign-up and sign-in pages, only ever a finding), and V4.4.1
  (unencrypted `ws://` WebSocket addresses in the code, only ever a finding).

- **What the remaining Level 1 and 2 requirements need.** An analysis on 25 September 2026 (session
  securevibe-e8) of the 181 ASVS requirements at Level 1 and 2 that no check reached, 30 of them at
  Level 1, by the kind of answer each needs: a document (18), a document plus behavior matching it (12),
  a design decision (16), deployment and infrastructure (22), more questions for the running app (19),
  code review (24), file uploads (9), OAuth, MFA, and JWT details (40), and unusual setups such as SAML
  or LaTeX (21). The items below are what came of it, in the suggested order; none is claimed.

- **A security-notes file, and policy numbers the probes can test.** For the 30 requirements that ask for
  a document. `sv init` writes a template with one section per applicable one, headed by its id and
  filled in from what was detected (the outside services, by the package that showed them; the data
  held, from `[data]`). A section the owner has written counts as *documented by the owner*: a tier of
  its own, never *checked*, the way a test naming a requirement is. For the twelve that ask for the app
  to behave as documented, the owner states the policy as numbers in securevibe.toml (failed sign-ins
  before a lockout, the idle and absolute session timeouts, sessions allowed at once), and the probes
  test those numbers against the running app. The design questions (16) take the same shape: yes, no, or not sure in securevibe.toml, with
  where in the code, counted as *attested by the owner*; "not sure" adds nothing.
  **Claimed on 25 September 2026 by session securevibe-e8.** The notes file itself is **done**:
  `data/security-notes.json` (nineteen questions, each a requirement that asks for a written decision
  and nothing else, and twenty more named with why they are not questions), `sv notes` to write and
  rewrite `security-notes.md`, and the *documented by the owner* tier in both reports — never folded
  into *checked*, beaten by a finding and by a check that ran, and deliberately unable to settle a
  threat. See DESIGN, "The security notes". Left over, each its own piece of work: the policy numbers
  in securevibe.toml that the probes can test (about eight requirements, V6.3.1 at level 1 among
  them), and the design questions answered as *attested by the owner*.
  **All three pieces are done**, the policy numbers on 25 September 2026 by session securevibe-e8:
  `[policy] failed-sign-ins` in securevibe.toml, and a probe that makes one more wrong attempt than
  that and watches whether the app pushes back. V6.3.1 at level 1 becomes checkable, which takes
  level 1 to 41 of 70. It runs last and never guesses at the test users, because it is the one check
  that provokes an app into refusing requests. See DESIGN, "Policy numbers, and the one requirement
  they make checkable". The session timeouts (V7.3.1, V7.3.2) are left: a stated idle timeout could
  be compared against the session cookie's own lifetime, which is instant and is evidence about the
  cookie rather than about the server, so it would be findings-only.
  **The design questions are done, on 25 September 2026 by session securevibe-e8.**
  `data/design-questions.json` (sixteen questions), a `[design]` section in securevibe.toml answered
  yes, no, or not-sure with `where`, and an *attested by the owner* tier ranked below *documented*,
  because the owner asserting a property is not the property — so an attested requirement stays on
  the list of tests to write, and settles no threat. An answer of no is a finding, and so is a
  `where` naming a file the app does not have. See DESIGN, "The design questions, and the weakest
  tier there is". Writing the guards found V13.2.2's question was about the wrong thing entirely.
  Left over from the whole entry: only the policy numbers, corrected below.

  **The "about eight" in the paragraph above was wrong, and is struck out.** It was written from the
  count of requirements that ask for behavior to match a document, without reading them. There are
  eleven, and asking a running app reaches three: V6.3.1 (Level 1 — make the stated number of failed
  sign-ins and see whether the app slows down or locks out) and V7.3.1 and V7.3.2, the idle and
  absolute session timeouts, the second of which is awkward when the real answer is measured in days.
  The other eight are out of reach for reasons that will not change: V2.3.2's business limits are
  whatever the app is for; V14.2.4, V16.2.3, and V16.3.3 need the logs or the stored data read, not
  the app asked; V15.2.1 is already the advisory check's; V6.2.11 needs the word list, which is the
  document itself; and V7.6.1 needs a real identity provider. So this is worth doing for V6.3.1 at
  Level 1 and two at Level 2, which is a smaller prize than the entry promised.

- **More questions for the running app, and an `upload` entry.** Asked with what `[stack.run.users]`
  already says. Three are done on 25 September 2026 by session securevibe-e9: `Cache-Control:
  no-store` on private pages (V14.3.2), a visible sign-out link on private pages (V7.4.4), and
  directory listings (V13.4.3). The first two are signed-in checks on the pages `private` names; the
  third is an anonymous probe beside V13.4.1, because it needs no account, and it is only ever a
  finding — six guessed paths and three server signatures cannot show that nothing lists. Level 2
  goes from 30 to 33 of 183. See DESIGN, "Three more questions for the running app".

  The logging question is **done on 26 September 2026 by session securevibe-e9**. The probes plant
  three markers — a sign-in for an account that does not exist, a sign-in that works by an account
  used for nothing else, and a private page asked for by nobody with a marker in its address — and
  the container's output is read for them afterwards. Finding them credits V16.3.1 and V16.3.2;
  *not* finding them is not assessed and never a finding, because an app that logs to a file or a
  service writes nothing there and is not logging any less for it. V16.3.1 needs both sign-ins
  found, since the requirement asks for both. Level 2 goes from 33 to 35 of 183. See DESIGN, "What
  the app wrote down". Password reset is done on 26 September 2026 by session securevibe-e9,
  on the mail server from the new-tools list below. An `upload` entry lets the probes send an oversized file, a file whose contents do not match
  its extension, and a script, which reaches V5.2.1, V5.2.2, V5.3.1, and V3.2.1 at Level 1.
  **The `upload` entry is done on 26 September 2026 by session securevibe-e9.** `[stack.run.users]`
  takes an `upload` entry — the path, the file field, the other form fields, an optional
  `serves-at` saying where an upload can be fetched back, and `max-bytes`, the size the owner
  states and the app is held to. The probes send an ordinary GIF first to show the upload works at
  all, then one larger than the stated size (V5.2.1), one named `.gif` that is not a GIF (V5.2.2),
  a `.php` fetched back to see whether the server ran it (V5.3.1), and an `.html` fetched back to
  see whether a browser would render it as part of the app (V3.2.1). Level 1 goes from 41 to 45 of
  70. See DESIGN, "The upload entry". Left over from it: V5.3.2 (paths built from submitted names)
  and V5.4.1/V5.4.2 (what the app sends back) are reachable the same way and were not written.

- **Twelve more requirements the probes could reach, from a sweep of everything they cannot.**
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

- **What a new tool, service, or process would reach.** The follow-on question to the sweep above,
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
     no entry says yet. Whether the log line the log check already finds is in a common format —
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
     inside the fence".
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
     the cross-site checks; V8.3.1 is an owner's answer and stays one. And one found on the way: an
     app that sends `Referrer-Policy: no-referrer` and refuses `Origin: null` refuses its own forms
     in every real browser, which a check could say directly.
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
     only way out intercepts TLS) and is not claimed; and request smuggling (V4.2.1), which means
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
     a finding. **Done the same day**: see DESIGN, "Skipping a step (V2.3.1)". Doing a step twice
     and other wrong orders are not tried. **V6.2.11 and V6.2.12 done on 26 September 2026.** Level 2 goes
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
  enforced, not only sent). To item 8: V12.1.1 (L1) and V12.1.2 (L2), the protocol versions and
  ciphers the live site offers, where semgrep today sees only TLS settings written in code; a scan
  is dozens of handshakes, so what `sv probe`'s four-request cap means for it needs deciding first.

  Items 2, 3, and 6 are containers on the fenced network, so they keep `sv`'s rule that nothing
  reaches outside; only item 8 does, and only to the owner's own address.

- **A production check.** `sv probe https://…`: read-only requests to the owner's own live address, for
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

- **Deadlines for known vulnerabilities (V15.2.1).** Asked for by the owner on 26 September 2026.
  V15.2.1 asks that the app contains no component that has *breached the documented remediation time
  frame*; the advisory check reads every known vulnerability as a breach, so an advisory published
  yesterday and one ignored for two years look the same. The owner states the time frames as policy
  numbers (`[policy] fix-within-days`, one per severity), and each advisory's published date says how
  long it has been known. Past the deadline stays a finding on V15.2.1; within it stays a finding with
  a due date, but no longer claims V15.2.1 is breached. A clean comparison credits it exactly as now,
  and nothing here credits more than that. **Claimed on 26 September 2026 by session securevibe-e8.**
  **Done on 26 September 2026.** `[policy] fix-within-days` in securevibe.toml, the publication date
  read from each OSV record, and `sv audit` printing past the time frame first, then not judged, then
  inside it. Anything that cannot be judged — no time frame for that severity, no date, no clock — still
  counts against V15.2.1, and an unrated advisory is held to the shortest time frame. See DESIGN, "Late,
  not merely known". Left over, found while doing it: **`sv report` never runs the advisory comparison**,
  so V15.2.1 has no evidence in the report whatever `sv audit` says, and the checklist sends the owner
  to `sv audit` by hand. Bringing it into the report needs `--advisories` on `sv report`.
  **Claimed on 26 September 2026 by session securevibe-e8. Done the same day:** `sv report
  --advisories DIR` puts the findings, the clean result, and what could not be compared into the
  report, and without a database the report says it compared nothing rather than staying silent. See
  DESIGN, "In the report too". The MCP server still takes no database, deliberately.

- ~~**Keep the breached-password evidence current through the Pwned Passwords API.**~~ Asked for by the
  owner on 26 September 2026. V6.2.12's sign-up probe tries `1qaz2wsx3edc4rfv`, and the only record
  that it is a breached password is one range file the owner fetched in a browser and pasted into
  the session that day, because this environment's network policy refused
  `api.pwnedpasswords.com`. The owner has since added that host to the allowed domains, which takes
  effect for sessions started after the change. Three things to do once a session can reach it:
  a small script under `tools/` that re-fetches the range for `BREACHED` and rewrites
  `data/breached-password-evidence.json` with the new count and date; a sampled check of
  `data/knowledge/common-passwords.txt` (a few hundred entries across its ranks), so the list's
  source — recorded nowhere in the repository — is at least shown to be breach data; and a line
  in the report's V6.2.12 wording that carries the date of the last check. Only the five-character
  hash prefix is ever sent, and none of this runs inside `sv` itself: `sv` fetches nothing, and
  this is maintenance of the repository's own data, done by whoever runs the script.
  **Claimed on 26 September 2026 by session relaxed-nobel-27acfa**, which runs on a machine that
  can reach the API. **Done the same day.** `python3 tools/pwned_passwords.py` re-checks the password
  (still 133,732) and rewrites the evidence file, and the V6.2.12 wording is now built from that file,
  so it says "when last checked, on <date>" without an edit to the code. `--sample` looked up 300
  entries spread across the list's ranks: all 300 are in Pwned Passwords, with counts falling from a
  median of 391,080 in the top thousand to 8,932 in the last band. Results in
  `data/common-passwords-breach-sample.json`; see DESIGN, "V6.2.12, breached passwords". One thing
  learned: inside the Claude Code sandbox the network proxy cuts Python's reads of these answers
  short, where curl gets them whole; run outside it, every answer arrived complete.

- **Record the owner's Pwned Passwords check for V6.2.12.** The count from the range file pasted on
  26 September 2026 (133,732), in `data/breached-password-evidence.json`, with the finding's wording
  changed to say so. **Claimed on 26 September 2026 by session securevibe-e8. Done the same day**,
  with a test holding the password and the quoted count to that file.

- ~~**OAuth requirements for authorization servers are applied to OAuth clients.**~~ Done on 25 September
  2026 by session securevibe-e9. A second condition, `authorization-server`, gates V10.4, V10.6, and
  V10.7, so an app with "Sign in with Google" keeps the client's requirements (V10.1, V10.2, V10.3,
  V10.5) and is no longer asked about a server it does not run. Running one is a way of using OAuth, so
  `oauth = false` answers it without anyone rewriting a manifest, while an explicit yes always wins over
  that entailment. It has a corroborator, from which dual-purpose libraries — Authlib above all — are
  deliberately absent: putting `authlib` back in its package list undid the fix and passed the entire
  suite, so there is now a test that writes a `requirements.txt`. See DESIGN, "Using OAuth and being the
  authorization server". For v1 no requirement moves buckets; only the exclusion reason changes.

- ~~**Threat modeling that does not depend on the AI tool.**~~ Done. Asked for by the owner on 25 September
  2026. The investigation is done (session securevibe-e8): `docs/THREAT-MODELING.md`. In short, v1's
  rule-based STRIDE model (32 threats citing 80 different requirements, decided by about 20 facts about the app) needs no
  AI, and `sv` already knows nearly every fact it asks; ported to a data file, each threat would show
  what the evidence says about it (found, checked in part, not verified, cannot place) and never that
  it is mitigated. Three pull requests. The owner answered the three
  questions on 25 September 2026: no likelihood/impact scoring, v1 to read the same data file later,
  and a section of the report rather than a file of its own. **Claimed on 25 September 2026 by session
  securevibe-e8.** All three are done: the rules as data, each threat's status from the evidence,
  a "Threats" section in the reports, and twelve threats for what v1 did not model (MCP tools,
  retrieval, several services, WebSockets, several tenants): 42 threats, 115 citations. Left over: v1
  reading `data/knowledge/threats.json` in place of its own rules, a change to v1's design engine that
  the owner has agreed to and that is its own piece of work.

- ~~**AISVS, beyond applicability.**~~ Done on 25 September 2026 by session securevibe-e8. Semgrep's
  AI rules now name eight AISVS requirements (C2.1.6, C2.2.1, C7.1.2, C7.3.1, C9.1.2, C9.3.1, C9.5.4,
  C10.4.2) through a new `findings_against` list: a finding is evidence against them, and a clean run
  credits none, because these patterns can show a control missing and never present. See DESIGN,
  "AISVS from semgrep's AI rules". Left over: `sv`'s own code rules match a call and its arguments,
  and every one of these is a flow from one place to another, so none was written. Seen firing in a real
  run: 11 of the 24 rules, in Python and JavaScript; the rest are the same patterns for other vendors.

- ~~**Shell scripts.**~~ Done on 25 September 2026 by session securevibe-e8. `.sh` and `.bash` are
  read as `shell`, every rule is taught it or says why not, and a new rule,
  `ast.download-piped-to-shell` (V15.2.4), finds `curl … | sh` and its relatives. See DESIGN, "Shell
  scripts". Left over: unquoted variables are ShellCheck's, which cannot write SARIF; a request value
  copied into another variable before it reaches a path or a redirect is not followed.

- ~~**Signed-in checks in one container.**~~ Done on 25 September 2026 by session securevibe-e8. Every
  request is now an `exec` into one sidecar started per run, not a container of its own: a signed-in run
  of `examples/notes-with-users` went from 11–13 seconds to 4.3, with the same answers. See DESIGN,
  "One sidecar per run".

- **Corroborators for the remaining claims.** `multiple-services` done on 25 September 2026: gRPC and its `.proto`
  contracts, AsyncAPI documents, message-broker clients, microservice frameworks and service discovery,
  in eight ecosystems and ten languages. A `docker-compose.yml` is deliberately not evidence — most
  single apps ship one with only a database in it — and a test pins that. Left over from it: reading a
  compose file for two or more services with their own `build:` would be the strongest evidence of all,
  and needs the scanner to read YAML contents, which it does not. Services that call each other over
  plain HTTP stay invisible. Eleven of the twelve were written on 24 September 2026;
  `shared-hostname` is recorded as uncheckable instead (`noCorroborator`), because it is a fact about
  deployment that the repository does not hold. What is left is the weaker half of what was written:
  `ai-history` and `multimodal-ai` lean almost entirely on source patterns, and `public-api` cannot see
  a key checked by hand against a query parameter. Each is a data entry, not machinery.

- ~~**A `.tsx` file is read with a grammar that has no JSX, and counts as read.**~~ Done on 25 September
  2026. `<button onClick={() => eval(q)}>` in a `.tsx` file was not found, and the report then listed
  V1.3.2 as *checked (ast.dynamic-code-execution over 1 typescript file)*. `.tsx` is now parsed with the
  TSX grammar, each rule's `typescript` query compiled a second time against it. And whatever the
  grammar, a file whose parse holds an error lands in `AstScan::unparsed_files`: its findings stand, but
  no rule that reads code may claim a clean result while it is there, and `sv check` and the report say
  which files. Breaking either half turns two or three tests red. `.jsx` needed nothing: the JavaScript
  grammar reads JSX.

- ~~**Dependencies `sv` declares it read, and cannot match.**~~ Done on 25 September 2026. A Go app
  declaring and using `github.com/gorilla/websocket` had V4.4.1–V4.4.4 excluded as "No WebSocket
  library is used": `go.mod` gives full module paths, the signatures named `gorilla/websocket`, and the
  comparison was exact, so no Go package signature had ever matched. A Go signature now matches the
  module path or its tail on a `/` boundary, with a `/vN` suffix set aside. Most Go names in both data
  files were also wrong in themselves — `goth`, `stripe-go`, `go-openai` are not what `go.mod` says —
  and are now module paths, with a test refusing a bare name; `autocert` is a package inside
  `golang.org/x/crypto` and never appears in `go.mod`, so it is found in source instead. And
  `build.gradle.kts`, the Kotlin default, is now read, for dependencies and for pinning.

- ~~**Secure by Design controls excluded on too narrow a question.**~~ Done on 25 September 2026, at
  the owner's request after review. RR-02, DM-03, AS-06, RR-03 and AC-01 each gained a second rule
  (`external-apis`, `payments`/`scheduler`, `internet`) so a single app that needs them keeps them;
  AS-07 lost its gate. Pinned per control and as the whole checklist for a single-service web shop.
  The last point from the same review — derived levels reported as ASVS ones — is the crosswalk item
  below, done the same day. (This entry was deleted by accident on 25 September
  2026 by the commit that finished the nested-manifests item, and restored.)

- ~~**SBD-AC-05's "no secrets in code" is what the credential scan checks.**~~ Done on 25 September
  2026. Every credential rule cites SBD-AC-05, so a committed secret is a finding against it, and a
  clean scan is shown beside it as *supporting* evidence while it stays not verified. That rule is
  general: a satisfied check about a manual-only requirement is never "checked". It corrected two
  overclaims already in every report — V13.3.1 (use a key vault) and V11.1.1 (a documented key policy)
  were listed as checked by a scan of source files.

- ~~**Dependency manifests are only read at the top of the repository.**~~ Done on 25 September 2026.
  `ecosystems::detect` walks the whole app folder (skipping installed dependencies and build output),
  so a `client/` + `server/` app has its dependencies read, its pinning judged per project, and its
  packages in the SBOM; every path it returns is relative to the app folder. A lockfile in a parent
  folder pins a project only when that folder is a workspace root whose member list covers it (npm and
  Yarn `workspaces`, `pnpm-workspace.yaml`, Cargo `[workspace]`, uv `[tool.uv.workspace]`): a stray
  root lockfile pinning an unrelated project below it would be a wrong statement in the direction that
  hides something. A nested project is named by its folder ("npm in server/") so two read as two.
  Left over: the adapters still look for their tool's config (`pyproject.toml` and the like) at the
  top only, and a Yarn Berry or Bun lockfile is not one `sv` reads.

- ~~**Ground the Secure by Design levels in ASVS.**~~ Done on 25 September 2026, with the owner's
  agreement to the design. `data/sbd-asvs-crosswalk.json` maps each of the thirty-six controls to the
  ASVS requirements that ask the same thing — seventeen have counterparts, thirty pairs in all — and
  each pair carries a few words naming what the two share, which the citation guard holds against
  both texts. `Frameworks::apply_crosswalk` sets a control's level to the lower of its derived level and
  its counterparts' lowest, so it can only ever come into scope sooner; a control with no counterpart
  is level 1, shown at every target. Every control records where its level came from, the report lists
  the controls above the target with that basis instead of calling them "above the ASVS level", and a
  satisfied check about a counterpart is shown beside the control as supporting evidence. Loading
  refuses a crosswalk that leaves a control out or cites an id that does not exist.

- ~~**A suppressed finding makes a tool's run look clean, and it is credited.**~~ Done on 25 September
  2026 by session securevibe-e8: bandit and gosec are made to report what they were told to skip, every
  suppressed result is shown and says so, and what cannot be shown withholds the clean-run credit.
  `docs/DESIGN.md`, "A tool told to look away, corrected again". What was found: `# nosec` on a line makes bandit report nothing
  about it, so `sv` sees an empty findings list, calls the run clean, and credits every requirement
  that adapter's rules map to — including V1.2.4 for a file whose `search()` concatenates user input
  straight into SQL. Verified by running bandit, not reasoned about:

      def search(db, q):
          return db.execute("select * from notes where t = '" + q + "'").fetchall()  # nosec

  Bandit's SARIF for that file holds `"results": []` and, in `runs[0].properties.metrics._totals`,
  `"nosec": 1` and `"skipped_tests": 0`. So the tool says plainly that it was told to look away, and
  nothing reads it: `grep -rn nosec crates/ data/` finds nothing at all.

  This is the missing-tool rule again, one layer in. A tool that is not installed already reports
  *not run* rather than a clean pass, because absent must never read as clean; a tool that ran with
  its mouth taped shut over the one line that matters is the same thing in a better disguise, and it
  is worse, because the report says an automated check looked.

  The fix is cheap for bandit, since the count is already in the report: read
  `metrics._totals.nosec` and `skipped_tests`, and where either is non-zero say how many suppressions
  there were and withhold that adapter's clean-run credit. gosec's `#nosec` and semgrep's
  `// nosemgrep` need the same treatment and neither could be checked here — gosec is not installed,
  and semgrep cannot start in this sandbox (`ca-certs: empty trust anchors`) — so what their reports
  carry is unverified. If it turns out they say nothing about suppressions, the honest interim is to
  count the markers in the files that were scanned.

- ~~**Semgrep skips some folders by default and does not say so.**~~ Done on 25 September 2026 by
  session securevibe-e8. Semgrep is handed the app's code files by name, which it reads whatever any
  ignore file says, and the list of files it writes (`--json-output`) is checked against the list it
  was given; a file it was given and did not read, or no list at all, withholds the clean-run credit.
  `docs/DESIGN.md`, "Semgrep is named the files". Left as it was: `build/`, `dist/`, `vendor/` and
  the rest of `SKIP_DIRS` are not handed to it, because no check in `sv` reads them. If built output
  can be what ships, that is a question about `SKIP_DIRS` for every check at once, not about semgrep.

- **Script in a page written the way a browser reads it and a parser does not.** An unquoted
  attribute value, and a scheme written around a control character, are both named as left behind —
  correct, and each keeps a page unread. Reading them means deciding where an unquoted value ends,
  which is a question with two defensible answers.

- ~~**Dart and Swift.**~~ Done on 25 September 2026 by session securevibe-e8. Both grammars, with every
  one of the nine rules either taught each language or saying why there is nothing to find in it
  (`nothingToFind`). The same change made the claim per rule: a rule that met a language it was not
  taught claims nothing and the report names it, which showed gaps in the older languages, most filled
  at once, and the last three in the entry below. See DESIGN, "Thirteen languages".

- ~~**Three rules still untaught a language.**~~ Done on 25 September 2026 by session securevibe-e8.
  Shell commands in Rust (the `Command::new("sh").arg("-c")` chain and the `.args([...])` array), weak
  ciphers in Rust (RustCrypto's types and the `openssl` crate's functions), and redirects in C (a
  `Location:` header printed by hand). Every rule is now taught every language `sv` reads, and a test
  pins it. What each misses is in DESIGN, "Thirteen languages".

- **Grammars for C++, and for HTML's embedded scripts.** C++ is the last language the scanner counts and
  cannot parse. Assessed on 25 September 2026 against what AI coding tools actually produce: C++ matters
  least of the candidates for web apps. Dart, Swift, and shell, which were worth more, are done (above). Since the claim became per rule, a grammar added without queries
  no longer turns silence into a clean claim; it moves the silence from the whole app to the rules not
  yet taught that language, and the report names them. C++ is also what the two "no grammar" tests now stand on, so whoever adds it will find
  those two failing, which is the right way round.

- ~~**More AST rules.**~~ Done on 25 September 2026 — four more in `data/ast-rules.json`, nine in
  all. `ast.file-path-from-value` (V5.3.2), `ast.weak-hash-function` (V11.4.1), `ast.weak-cipher`
  (V11.3.1, V11.3.2) and `ast.open-redirect` (V3.7.2), across eight or nine languages each. Two new
  fields made them possible without Rust per rule: `argumentPatterns` (the call is a finding only when
  its argument says so — `createHash("md5")`, not `createHash("sha256")`) and `safeArgumentPatterns`
  (named idioms that are not findings — `redirect(url_for(...))`, `secure_filename(...)`,
  `path.join(__dirname, "a.html")`, a bare ALL-CAPS constant). A pattern for a language with no
  query is refused at load. Every (rule, language) pair has a found and a not-found witness, and a
  test fails if one is missing; breaking each filter in turn turned two to seven witnesses red.
  Left over, each its own decision rather than a data entry:
  - **Predictable randomness (V11.5.1) was not written.** `Math.random()` and `random.choice` are fine
    for shuffling a list and wrong for a reset code, and what decides it is where the value goes,
    which a single query cannot see. A rule without that would mostly report shuffles.
  - Express's two-argument `res.redirect(301, url)` is missed: the first argument is the status,
    and it is a literal. `send_file`/`redirect_to` in Ruby, `Paths.get` in Java and PHP's
    `include $x` are not covered. Kotlin and C have no path or redirect query, Rust none of the four.
  - The file-path rule is low confidence on purpose: it cannot tell a request value from an internal
    one held in a lowercase variable.

- **Read Maven and Gradle version ranges.** The lockfile check reports them as not assessed, because
  pinning lives in `pom.xml` and `build.gradle` rather than a lockfile. Reading a range out of either
  would turn an open question into an answer. **Claimed on 26 September 2026 by session relaxed-nobel-27acfa.**

- **More adapters.** Semgrep's rule map is done (25 September 2026, session securevibe-e8): 998 of the
  1,321 security rules in `semgrep/semgrep-rules`, generated by `tools/semgrep_rule_map.py` and
  checked against a real SARIF run. See DESIGN, "Semgrep: a thousand rules". Left over from it: the
  map is keyed on the registry's form of a rule id, which was reproduced rather than observed, so one
  run of `p/security-audit` on a machine that can reach semgrep.dev is owed (the fixture's README has
  the command). `staticcheck` and `phpcs-security-audit` are each a data entry.
  `eslint-plugin-security` was looked at on 25 September 2026 and not added. Semgrep's JavaScript rules
  already include its rules under their own names (`detect-child-process`,
  `detect-eval-with-expression`, `detect-non-literal-fs-filename`, `detect-non-literal-regexp`,
  `detect-pseudoRandomBytes`, and others), mapped to ASVS, so it would add the same checks twice. And
  ESLint 10 loads its plugins from the folder it runs in: run over an app, it would load an
  `eslint-plugin-security` from the app's own `node_modules`, which runs that app's code on the
  owner's machine outside the network fence, while TypeScript needs a parser the plugin does not
  bring. The shape to keep: SARIF only, not installed means not run, and a rule mapped only where it
  can be shown to be about its requirement.

- **More probes.** The first four questions are asked (`sv-check/src/probes.rs`); they are the ones that
  can be asked of any app by somebody who has not signed in. Redirects, HSTS on an HTTPS app, method
  handling per route and anything that sends data need either a manifest describing the app's routes or a
  session — both of which are their own items below.

- ~~**Seeded users.**~~ Done on 25 September 2026. `[stack.run.users]` in securevibe.toml says how
  accounts are made (`seed`, run in the app's container with the accounts in its environment, or the
  app's own `signup`), how to sign in and out, which pages are private or admin-only, and how one user
  creates a record another must not read. `crates/sv-check/src/signed_in.rs` asks seven things as two
  test users and an admin — private pages (V8.2.1), admin pages (V8.2.1), another user's records
  (V8.2.2), a forged cross-site request (V3.5.1), a new session at sign-in (V7.2.4), sign-out ending it
  (V7.4.1) and the session cookie's attributes (V3.3.2, V3.3.4) — and every one shows its own setup
  worked first or reports not assessed. Anti-forgery tokens are read from hidden fields (quoted or not),
  `<meta>` tags or cookies. Tested against a scripted app with each flaw switchable (every rule found by
  at least two tests), and under Docker against `examples/notes-with-users`: the correct app has all
  seven confirmed, and a copy with five flaws switched on had all five found. That run also found two
  bugs in the suite, both fixed: unquoted attributes hid the token, and a sign-out the app refused was
  reported as a sign-out that did not end the session. Left over: V3.3.1 (Secure) cannot be judged over
  the fence's plain HTTP; input handling (V5, V1.2) still needs knowledge of the app's forms.

- ~~**Load the Secure by Design checklist.**~~ Done on 24 September 2026. Left over: `multiple-services`
  had no corroborator until 25 September 2026 (see the corroborators item). The
  checklist's `scoring`, `processSteps`, `principles` and `escalationTriggers` are read past, not used.
  It was found on 24 September 2026 while chasing bad citations: `sv --help` had named the checklist
  since the first commit while `Frameworks::load` read ASVS, AISVS and Appendix C only.

- ~~**Clean coverage from the remaining checks.**~~ Done on 24 September 2026. Every check that can find
  something now also reports what it examined and found nothing wrong, each failing closed on its own
  coverage. Left over: `sv report` does not run the bill of materials or the advisory comparison at all
  — they live in `sv check` and `sv audit`, the latter because it needs an offline database path — so a
  report says nothing about dependencies either way. That is a bigger change than this item and is not
  what this entry asked for, but a reader of the reports would not guess it.

- ~~**Credit the app's own test suite.**~~ Done on 24 September 2026 — `crates/sv-check/src/suite.rs`.
  A test counts only for a requirement it names, and only when the suite it belongs to passed. Matching
  tests to requirements by their words was considered and refused: it would credit a requirement on the
  strength of a name somebody chose for other reasons. v1's mismatch check is ported as it was —
  reporting, never withholding credit, because about a third of its flags are honest tests phrased
  differently. What is left over from this item: the suite's coverage is still all-or-nothing on one
  exit code, so a suite with one failing test credits nothing. Reading a test runner's own report
  (JUnit XML, `pytest --junitxml`) would fix that and is its own item.

- ~~**Almost every rule-to-requirement citation is semantically wrong.**~~ Done on 24 September 2026 —
  remapped, and guarded by `crates/sv-check/tests/citations.rs`. Left over: Brakeman's rule ids had
  never been seen in a real SARIF run — done on 25 September 2026: they were mostly wrong (BRAKE0002 is
  cross-site scripting and was mapped as SQL, BRAKE0013 is eval and was mapped as OS command injection,
  BRAKE0016 is file access and was mapped as SQL, BRAKE0102 is a 2016 Rails CVE, not a secret, and
  BRAKE0000, SQL injection itself, was unmapped). Remapped from `warning_codes.rb` in Brakeman 8.0.6,
  forty ids, and tested against a real run over `crates/sv-check/tests/fixtures/brakeman/app` whose
  output is kept beside it; fifteen ids appear in that run, and the guard cannot catch a swap between requirements that
  share vocabulary. Found on 24 September 2026 by the
  test-crediting mismatch check, firing on the example app written to demonstrate it. ASVS 5.0 `V1.2.1`
  is *output encoding for an HTTP response, HTML or XML document*. It is cited by `ast.sql-built-by-hand`,
  `ast.dynamic-code-execution`, bandit's `B608` and `B307`, gosec's `G201`/`G202`, and three Brakeman
  rules — none of which have anything to do with output encoding. Parameterized queries are **V1.2.4**;
  OS command injection is **V1.2.5**, not the `V1.2.2` that nine adapter rules cite (`V1.2.2` is URL
  encoding). The pattern repeats across the file: eight rules cite `V11.3.1` (block modes and padding)
  for weak hashes, which are `V11.4.1`; `G404` (`math/rand`) cites `V11.4.1` (hash functions) when
  unpredictable randomness is `V11.5.1`; `G304` (file paths) cites `V1.2.3` (JavaScript encoding) when
  it is `V5.3.2`; `G107` (SSRF) cites `V1.2.4` (database queries) when it is `V1.3.6`; `G402`/`B501`
  (TLS verification off) cite `V13.1.1`, which asks that communication needs be *documented*.

  This is the third time this class has been found here — five checkers citing `AC-NN` ids that did not
  exist, then every probe citation being semantically wrong — and it is the failure the whole product is
  most exposed to, because a wrong citation is not visibly wrong. It puts a finding, or a green line,
  against a requirement nobody examined, and the reader has no way to tell.

  Two things are needed, and the second matters more. Remap `data/adapters.json` and `data/ast-rules.json`
  by reading each requirement's text. Then write the guard that would have caught it without an example
  app happening to exist: every citation in the data files compared against the requirement it names, by
  shared vocabulary, the same comparison `suite.rs` already makes for tests. A citation nothing checks is
  a citation that drifts.

- ~~**Read the test runner's own report.**~~ Done on 24 September 2026. Left over: matching is an exact
  identifier match, so jest — which concatenates its `describe` blocks into the reported name — mostly
  will not match and its tests stay uncredited. A runner that reports a name unlike the declaration
  loses coverage silently rather than loudly. The parser understands JUnit XML only; TAP and the
  runners that emit their own JSON are not read.

- ~~**The MCP server.**~~ Done on 25 September 2026. `sv mcp --root DIR` speaks MCP over stdio
  (`crates/sv-cli/src/mcp.rs`, no SDK) with four tools: `securevibe_spec`, `securevibe_check`,
  `securevibe_explain` and `securevibe_write_report`. `securevibe_check` is `assemble_report`, the
  function `sv report` now calls too, so a model is told exactly what the written report says, gaps first.
  Every path is resolved against `--root` and refused outside it, `..` and symlinks included; a report is
  written only below the app. Starting the app and running other people's tools are not offered: each
  runs code, and that stays the person's decision at a terminal. Left over: MCP resources (the report
  files as resources rather than paths) and progress notifications for a long check.

## Decided, not yet written down as ADRs

- Corroboration only ever moves toward more requirements applying, never fewer (`sv-manifest::resolve`).
- The OWASP data files are shared with v1, not copied.
- `sv` never writes application code, so v1's generation agent and its fence have no successor here.
