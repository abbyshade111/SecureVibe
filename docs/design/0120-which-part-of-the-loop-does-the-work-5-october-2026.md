# Which part of the loop does the work (5 October 2026)

Item 3 of "The loop", to the protocol with both amendments (`docs/prompts/loop-arms/README.md`): five arms, Sonnet 5.5
and Haiku 4.5, two builds a cell, on the pilot's `sv`. Eighteen new builds, $4.78; the Haiku loop cell is the pilot's
two amended builds.

**Results.** Without the server, no build wrote a manifest `sv` could read, so none could be tested: neither with no
`sv` at all nor with the server's instructions pasted into the request, which point to a tool those builds did not
have. With the server, in every arm, every build read the specification before any code, and ten of twelve could be
signed in to. By the protocol's rule that is a difference for both models. Between the arms with the server there is
none, and there could hardly be one: the plan was called by three of the eight builds offered it, all Haiku, and the
check by three of eight, once each, with no second round. What the testable builds share is the specification.

**What it changes.** The instructions say what the check is for, not when to call it, and the builders called it
rarely; the next trial should try saying when. The arms without `sv` can be compared on security only if somebody
writes their manifest, or every arm is given the specification: the owner's choice before item 6. An app's own
sign-in limit locked `sv` out again, as in trial 3. Each is in the backlog.
