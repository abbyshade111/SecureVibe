# The corroborators

The other half of the claims design. `data/claim-corroborators.json` describes how sixteen of the manifest's
claims look in real code, and `sv` checks each one. On the example app:

    The manifest and the code disagree about 1 thing. The code wins:
      securevibe.toml says payments is not used, but `stripe` is declared in requirements.txt

    Read from the code, so nobody had to be believed:
      auth             `authlib` declared in requirements.txt
      oauth            `authlib` declared in requirements.txt
      jwt              `pyjwt` declared in requirements.txt
      payments         `stripe` declared in requirements.txt

### The asymmetry the scanner did not need

For a technology like XML, absence is informative: parsing XML always leaves a trace, a library or a standard-
library import. For a claim like `auth` it is not. Sign-in can be built from a hash function and a database
table, leaving no library behind, and answering "this app has no sign-in" because no auth package appears would
switch off **fifty-three** ASVS requirements on the strength of a missing dependency.

So every corroborator declares `absenceIsEvidence`, and only two set it: `ci-cd` and `iac`. Those are files in
the repository, and a file that is not there is not there. Everywhere else, finding something proves it is
used and finding nothing proves nothing — recorded as the claim being *unverified*, not contradicted.

### Finding nothing does not answer for the owner

That paragraph was right about the file and wrong about the pipeline. A CI file that is not in the copy
`sv` read is not in the copy `sv` read: an uploaded app often leaves `.github` out, and a pipeline can be
configured on a server or a hosting console. Until 26 September 2026, `resolve` let that absence answer
`ci-cd` and `iac` for an owner who had said nothing, and on a manifest holding only a name it marked twelve
requirements not applicable — AC.12.1–AC.12.8, AC.7.3, AC.7.4, AC.9.1, and SBD-AC-07 — while the claim's
own note said finding nothing "is not the same as finding it absent".

Now a question the manifest asks stays unanswered while the owner is silent, whatever the scan found, and
the twelve are *not assessed*, with the claim shown as *unanswered* and what the scan saw beside it. A scan
that found nothing still confirms an owner's *no* and still marks an owner's *yes* unsupported; it only
never speaks for them. The conditions no one is asked — the derived ones — keep their answers from the
code. Putting the old line back fails two tests, a unit test on `resolve` and one that runs `sv report` on
the bare manifest; before, it failed none.

### A rate limiter is not an API

`public-api` counted five rate limiters as evidence (`express-rate-limit`, `@fastify/rate-limit`,
`flask-limiter`, `slowapi`, and `rack-attack`). Limiting requests is ordinary for any web app, and
one of the usual ways to slow down password guessing, so an app that added one was handed the API
requirements over the manifest's own "no", since corroboration only ever adds. It happened on the
owner's first build from scratch, to an app with no sign-in and no API at all. A rate limiter shows
that requests are limited, not who is calling, and all five are gone from the list; what remains
is what an interface for other programs leaves behind: a description of itself, and a key.

Two tests hold it. A scan of an npm and Python app carrying four of them, and of a Ruby app carrying
the fifth, does not answer `public-api`, while the same apps with an API description package do, so
the dependencies were read. And the data file itself is read for any `public-api` package whose
name says it limits or throttles, in every ecosystem. Putting each of the five back turns both red.

### Three things this turned up

**A silent field-name mismatch that defaulted to the dangerous value.** `Signature` had no `rename_all`, so
`absenceIsEvidence` in the data file never bound to `absence_is_evidence` in Rust. Every corroborator fell back
to the serde default — `true` — and the only symptom would have been requirements quietly switching off. The
guard test caught it on its first run. `Signature` now uses `deny_unknown_fields`, so a typo in the data file
stops the run instead of changing the answer.

**`.github` is a dot-directory.** The source walk skipped every directory beginning with a dot, which is
exactly where a CI pipeline lives. Left alone it would have answered "no CI/CD" for every repository that has
one — a wrong statement in a report, produced by an optimization.

**Two conditions gate nothing.** `payments` and `scheduler` are asked about in the manifest and have
plain-language reasons written for them, but no rule in the OWASP data keys on either: ASVS 5.0 has no
payment-specific requirements. Announcing that the manifest is wrong about payments without saying that it
changes no requirement would be its own small overstatement, so `sv` says both — and points at the answer that
does matter, which is that an app taking money should probably be declaring `payment-card` or `financial` in
its data categories, and that *does* raise the target level.
