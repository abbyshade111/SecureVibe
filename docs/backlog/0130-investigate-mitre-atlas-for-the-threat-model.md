# Investigate MITRE ATLAS for the threat model

**Status:** claimed by a session not named, as its markers read on 8 October 2026

Asked for by the owner on 26 September 2026:
how feasible it would be, whether it adds anything of value, and whether it is worth it. ATLAS
(Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE's catalog of how AI
systems are attacked — tactics and techniques such as prompt injection, poisoning the data a model
learns from, and extracting a model — with case studies of attacks that really happened. The
investigation should answer, with evidence rather than impressions:

- **Overlap.** How much of what ATLAS covers is already reached through AISVS and its Appendix C,
  which `sv` loads, and through the AI threats already in `data/knowledge/threats.json`. What is
  left once both are subtracted is the value in question.
- **Fit with the threat model.** Whether a threat could carry the ATLAS technique it corresponds
  to as a reference, the way threats already cite requirements, and whether that helps the owner
  — who is not a programmer — or only a security reviewer reading the report after them. ATLAS
  names describe attacks; the threat model describes what could go wrong for this app in plain
  language, and the two may not line up one to one.
- **What it could check.** ATLAS describes attacks, not controls, so it may add nothing checkable
  on its own; say whether any technique gives a question the running-app probes or the code rules
  could ask that AISVS does not already prompt.
- **Upkeep and terms.** How ATLAS is published (machine-readable data, and how often it changes),
  its license and what attribution it asks for, and what keeping a copy current would cost — the
  same questions the Pwned Passwords item had to answer.
- **Applies only to apps that use AI.** Most apps `sv` sees do not, so whatever is added must be
  gated on the `ai` condition like the rest of AISVS.

The deliverable is a short written recommendation — adopt, adopt in part, or not worth it — with
the numbers behind it, before anything is built. **Claimed on 26 September 2026 by session
securevibe-e8. Done the same day: adopt in part.** Cite ATLAS techniques by ID on the six AI
threats, for a reviewer; no copy of ATLAS in `sv`, no checks from it (35 of its 40 mitigations
already have an AISVS chapter, and AISVS cites ATLAS itself), and nothing in the owner's
plain-language view. See DESIGN, "MITRE ATLAS: adopt in part".
