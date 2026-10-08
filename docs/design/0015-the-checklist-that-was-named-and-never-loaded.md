# The checklist that was named and never loaded

`sv --help` said it checked against OWASP Secure by Design from the first commit. `Frameworks::load`
read ASVS, AISVS and Appendix C. The checklist contributed nothing at all, and the README carried the
admission in a footnote — which is worse than silence, because it shows somebody knew.

It is a third schema, `checklistDomains` → `controls`, with a `statement` and no level, and loading it
needed two decisions that are choices rather than readings.

**The ids are namespaced `SBD-`.** The checklist numbers its own controls `AC-01` … `AC-07`. AISVS
Appendix C already owns `AC.1.1` … `AC.13.4`. Those are different strings and would never collide in a
map — they collide in a reader's head, which is the failure that matters. This codebase has already
shipped five checkers citing `AC-05` for a family written `AC.5`, and a citation that resolves to the
*wrong framework* is worse than one that resolves to nothing, because nothing about it looks wrong. So
the checklist's controls are `SBD-AC-01` here and the prefix is printed everywhere they appear. The
guard is `no_two_requirement_ids_differ_only_by_how_they_are_punctuated`: it flattens every id anything
can be addressed by to its segments, drops separators and leading zeros, and fails if two distinct ids
come out the same. `AC-05` and `AC.5` both flatten to `AC|5`.

That guard was written comparing requirement ids alone, and in that form it did not work. `AC.5` is a
*family* — a chapter — and not a requirement at all, so the set it compared did not contain the very id
the original mistake cited, while the test passed and looked like it covered it. Removing the `SBD-`
namespace is what exposed it: four tests went red and this one did not. Applicability rules scope to
chapters and sections as well as requirements, so the comparison now covers every addressable id, and
asserts that `AC.5` is in the set before comparing anything.

**Levels are derived, because the checklist has none.** It has `critical` and `severityIfNo`. Critical
or high severity is level 1, medium is level 2, low is level 3. That is this tool's mapping and not
OWASP's, so it lives in one named function rather than three comparisons spread around.

Fifteen of the thirty-six controls are about the space between services — trust zones, service
discovery, contracts between services, sagas, circuit breakers, a bus kept highly available. On a single
service they are not passed, they are *meaningless*, and nothing the manifest already asked came close
to deciding it. So `multiple-services` is a new claim. Unanswered leaves those controls not-assessed,
which is the honest default and the one the engine already had. Two more are gated on `internet`, which
until now was a condition that decided nothing at all — the test pinning that list is what noticed.

**Corrected on 25 September 2026: "one service" was too narrow a question for five of them.** A
single app still needs a circuit breaker in front of the outside APIs it calls (RR-02), handlers that
are safe to run twice when a payment provider retries its webhooks (DM-03), and durable messaging with
defined semantics when it runs a job queue (AS-06, RR-03). "Starting up when a dependency is missing"
(AS-07) applies to anything with a database, so it lost its gate altogether and fourteen controls are
now gated on `multiple-services`. And `tls = off` had been enough on its own to exclude "all
communications use TLS" (AC-01), which excluded it for exactly the app it is most about: one on the
internet without HTTPS. Each now carries a second rule at the same scope — `external-apis`, `payments`,
`scheduler`, `internet` — and rules at one scope are OR-ed, so any one of them keeps the control. The
reasons were rewritten to name both answers, because an exclusion that says only "this runs as one
service" tells its reader half of why. It also took `payments` and `scheduler` off the list of
questions that decide nothing.

**Levels, grounded in ASVS (25 September 2026).** The derived levels above were `sv`'s own, and the
report called the controls they excluded "above the ASVS level this app targets", putting ASVS's name on
a number ASVS never gave. `data/sbd-asvs-crosswalk.json` now ties each control to the ASVS requirements
that ask the same thing, and a control's level is the lower of its derived one and its counterparts'.
Lower only, so the crosswalk cannot hide a control; and a control with no counterpart — the architecture
controls and the incident response plan — is shown at every level, because keeping it out would rest on
the derived number alone. The checklist's statements are too terse for the citation guard to compare
directly (`TLS` is shorter than its shortest word), so each pair carries a few words naming what the two
ask in common, and the guard requires them to share vocabulary with both texts, which is a stricter test
than either side alone.

### Applicable, unverified, and unverifiable are three different things

Loading the checklist could easily have made the reports worse. Its controls are applicable and every
single one is unverified — which is also true of a great many ASVS requirements, and the difference
between the two matters enormously. An ASVS requirement that nothing checked could in principle be
reached by some future check. A Secure by Design control cannot be reached by any check, ever: it asks
whether trust zones are enforced, whether an incident response plan is rehearsed, whether data has named
owners. Counted together, a reader sees one number and concludes the scanner tried and came up short.

`VerificationClass::ManualOnly` already existed and nothing read it. Now every `SBD-` id is manual-only
by construction rather than by a list somebody has to remember to extend, and `sv report` carries a gap
reading *31 requirements that are design review, not scanning*. That count is the checklist's fifteen
plus the sixteen requirements on the existing `manualOnly` list — ASVS and AISVS both — that apply to
this app, out of twenty-six listed overall. Those sixteen had been marked manual-only for as long as the
list has existed and no report had ever said so.

On `examples/tested-notes`: fifteen controls applicable, seven not-assessed because nobody answered
`multiple-services`, and fourteen above the app's target level.
