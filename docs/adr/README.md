# Decision records

A decision record ("ADR", architecture decision record) writes down one decision: what was decided, why, what
else was considered, and what it costs. It is kept so that nobody has to reconstruct the reasoning later from
code, and so that undoing the decision is a choice made knowingly.

## Numbering

One sequence runs across both versions of SecureVibe, so a number always means one decision.

- **ADR-001 to ADR-014 are v1's.** They moved with v1 to the `v1` branch on 26 September 2026 and are at
  `docs/adr/` there, and at the tags `v1-paper` and `v1-final`. ADR-014 is the file named `ADR-011.md` there,
  whose title calls it ADR-014; v1 has no other file for either number.
- **ADR-015 onward are `sv`'s**, and are here.

## v1's records that `sv` still cites

Two of v1's decisions are rules `sv` keeps. `DESIGN.md` lists both among "the rules that carry over word
for word", and ADR-012 is also cited by number in `DESIGN.md` and in four source files:

- **ADR-006, evidence tiers.** AI review alone is never a pass, and a requirement only a person can check
  never passes on its own.
- **ADR-012, what "SecureVibe checks this app" means in another language.** Written after the first app from
  outside, a Python one, was told it was missing `package-lock.json`. `sv` cites it for the rule it drew from
  that incident: a check that does not apply is not a check that failed, a scan that did not run is not a
  clean result, and a wrong statement in a report is worse than a gap in it.

  ADR-012 also ruled out SecureVibe writing its own static-analysis rules for other languages. That ruling
  was about v1. `sv` later wrote such rules for fourteen languages (`DESIGN.md`, "Rules that read the
  code"), and no record here revisits the ruling. That is a gap in the records, not a decision.

## `sv`'s records

| Record | Decision |
|---|---|
| [ADR-015](ADR-015.md) | What the owner says can add requirements and never remove one, and silence is not a "no" |
| [ADR-016](ADR-016.md) | The OWASP data files: one copy while both versions lived here, and two since |
| [ADR-017](ADR-017.md) | `sv` never writes the app's code |
