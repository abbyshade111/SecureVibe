# Appendix C out of the report's headline numbers, into a section of its own

**Status:** done, as its markers read on 8 October 2026

Asked for by the
owner on 27 September 2026, once the coding rules gave Appendix C a place at the start of the
build. Measured the same day: Appendix C is 44 of the 284 requirements that apply to
`examples/flask-booking` and 33 of 163 for a bare manifest, every one *not verified* because no
check reaches it, so about a sixth of every report's "not verified" is about how an organization
runs its AI tooling rather than about the app. Removing them outright would read as coverage, and
the rules are not evidence, so instead:
- They leave the headline counts and the list of unverified requirements, unless something found
  a problem with one or has evidence for it, which then counts as any other requirement does.
- One section, "How the app was built with AI (OWASP AISVS Appendix C)", says how many are given
  to the AI coding tool as rules (and that the rules are not evidence), how many are the owner's
  decisions (still in the questions), how many do not apply and why, and how many are left with
  nothing reaching them.
- `compliance.md` and `report.json` still list every one of them, under that section, for anybody
  assessing against AISVS.

**Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking. **Done the same
day:** on the Flask example the headline goes from 284 to 240, and the section lists 44 (24 given
as rules, 2 the owner's decisions, 18 nothing reaches). See DESIGN, "Appendix C in a section of its
own".
