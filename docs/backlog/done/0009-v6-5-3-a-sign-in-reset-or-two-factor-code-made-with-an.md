# V6.5.3: a sign-in, reset, or two-factor code made with an ordinary random number generator

**Status:** done, as its markers read on 8 October 2026

From
`docs/PARTIAL-CHECKS.md` (V6.5.3, level 2, "reads the code, finding only"), which no check of `sv`'s own speaks to.
Python's `random.randint` and its kin, JavaScript's `Math.random`, Java's `java.util.Random` and
`RandomStringUtils`, Go's `math/rand`, PHP's `rand` and `mt_rand`, Ruby's `rand`, C#'s `System.Random`, and Dart's
`Random()`, where the value is given a name that says it is such a code (`otp`, `verification_code`, `reset_token`,
`backup_codes`), or made inside a function so named (`generate_otp`). Only ever a finding, citing V6.5.3 and
V11.5.1: finding none says nothing about codes made elsewhere or named otherwise. The outside tools already report
weak random numbers in general under V11.5.1; this is the narrower case a reader can be sure matters.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please go ahead"), in branch
`claude/securevibe-e2-weak-random-codes`. A new rule that only ever raises findings changes no requirement's
status, so no ADR is proposed.
**Done the same day** (DESIGN, "A sign-in or reset code made with a random number generator that can be
predicted"): `ast.insecure-random-for-code`, in thirteen languages (Swift and Rust have nothing to find, and say why), with a new rule setting, `valueNamePatterns`, that
reads the names a value is given. Only ever a finding.
