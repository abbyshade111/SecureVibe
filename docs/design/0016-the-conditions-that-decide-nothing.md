# The conditions that decide nothing

Wiring up the corroborators produced a contradiction banner that announced the manifest was wrong about
`payments` — and then had nothing to report, because no applicability rule keys on `payments`. Checking properly
found **seven** such conditions, not two:

| condition | why it decides nothing |
|---|---|
| `payments`, `scheduler`, `public-api`, `internet` | asked in the manifest; no rule in ASVS 5.0, AISVS 1.0 or Appendix C keys on them |
| `level2` | redundant — the target level is applied by bucketing requirements, not by a rule |
| `no-auth` | derived from `auth`, and nothing currently uses it |
| `self-assessment` | v1's notion of checking itself, which has no meaning in `sv` |

The tempting fix is to write overlay rules so these gate something. That would be inventing ASVS scoping, which
is the same over-reach as the inherited reasons. They stay inert, and `sv` says so:

    Answered in securevibe.toml but gating nothing: public-api, payments, scheduler, internet.
    No requirement in ASVS 5.0, AISVS 1.0 or Appendix C turns on these, so answering them
    differently changes no result.

A test pins that exact set, so a future OWASP data update that gives one of them a rule — or quietly takes a
rule away from something else — has to be noticed by somebody.

### Where being wrong about payments does cost something

Not in the requirements, but one step along: an app taking money holds financial data, and the data categories
set the target level. v1's profile already says the equivalent about sign-in — `credentials` is described there
as "always present when sign-in is on". So `consistency::check` connects a claim that gates nothing to the
answer that gates a great deal:

    Worth checking in securevibe.toml:
      This app takes payments, but `financial` is not in its data categories. …
      This app has sign-in, but `credentials` is not in its data categories. …
      This app accepts file uploads, but `files` is not in its data categories. …

These are questions, not corrections: `sv` does not edit the manifest or quietly raise the level on the owner's
behalf. And each states its real consequence — an app already at level 2 is told that adding the category
changes no requirement, because saying otherwise would be the same small overstatement in a new place.
