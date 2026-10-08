# A security-notes file, and policy numbers the probes can test

**Status:** claimed by securevibe-e8, as its markers read on 8 October 2026

For the 30 requirements that ask for
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
