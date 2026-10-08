# What carries over unchanged

`data/frameworks/*.json` (ASVS 5.0, AISVS 1.0, AISVS Appendix C, SbD checklist) and `data/knowledge/*.json` are
pure data with no Node in them. `sv` reads the same files from the same place. One source of truth for ASVS
across both products; an ASVS correction fixes both. (True until 26 September 2026:
see `docs/adr/ADR-016.md`.)

The rules that carry over, restated in `sv`'s own terms where v1's words no longer fit:

* Evidence tiers are honest. v1 put it as "AI review alone is `ai-assessed`, never `pass`". `sv` has no AI
  review and neither status: an AI coding tool's word is *stated*, the weakest tier of evidence, and nothing a
  model says makes a requirement *checked*.
* A check that does not apply is not a check that failed (v1's ADR-012; `docs/adr/README.md` says where it
  is), and a scan that did not run is not a clean result, and a requirement that was not assessed is not a
  failed one.
* A checker that knows which requirements it verifies says so in `Evidence.requirementIds`.
