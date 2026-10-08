# The coding rules cite AC.7.4 for something it does not ask

**Status:** done, as its markers read on 8 October 2026

Found on 27 September 2026 from the
workflow check's reading of the requirement: AC.7.4 asks that *changes* to high-impact pipeline
settings, `permissions:` blocks among them, get dual control and a security-team review. The rule
"least-privilege-workflows" tells the tool to keep each workflow's `permissions:` block small, and
cites AC.7.4 for it: the same subject, a different ask. The citation goes; the rule keeps AC.12.2
and AC.12.3, which it does follow from. **Claimed on 27 September 2026 by session securevibe-e9**,
at the owner's asking. **Done the same day;** see DESIGN, "Appendix C as rules the AI coding tool follows
while it codes".
