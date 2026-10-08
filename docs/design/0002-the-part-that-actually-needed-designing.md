# The part that actually needed designing

`shared/src/profile.ts` opens by saying the wizard answers are "the ONLY input to every security decision
SecureVibe makes". Delete the wizard and every security decision loses its input. The applicability engine
reduces a design to about twenty-five booleans — `auth`, `uploads`, `payments`, `ai-actions`, `multi-tenant`,
`tls`, `internet` and so on — and those booleans decide which requirements apply *at all*. Get one wrong in the
permissive direction and the report says "not applicable" about a requirement the app needed.

Inferring them from the code is guessing, and guessing is the thing this project refuses to do elsewhere.

### Claims, and what corroborates them

The user's AI tool writes a `securevibe.toml` during the build — `sv init` prints the spec to hand it. Every
capability in that file is a **claim**, not a fact. `sv` then tries to corroborate each claim against the code,
and each one ends in one of four states:

| State | Meaning | What it does to the requirements |
|---|---|---|
| `confirmed` | Claim says yes, and the code agrees | They apply, evidence recorded |
| `contradicted` | Claim says no, and the code says otherwise | **They apply anyway**, plus a finding |
| `unsupported` | Claim says yes, nothing in the code shows it | They apply; the claim is not treated as evidence |
| `unverifiable` | No corroborator exists for this claim | They apply; reports say "asserted, not verified" |

**Corroboration only ever moves toward more requirements applying, never fewer.** A manifest cannot switch a
requirement off that the code says applies. This is the same constraint v1 puts on the second opinion and the
follow-up questions — they may only move an answer toward the safer side — and it is what stops a careless or
over-confident manifest from turning into an over-stating report.

The asymmetry is deliberate and it is the whole safety argument: a wrong claim costs the user a requirement they
did not need to meet, never a requirement they needed and were told they did not.

### A thing v2 can answer that v1 could not

`buildConditionContext` hardcodes `oauth`, `webrtc`, `jwt`, `rag`, `mcp`, `multi-tenant` and `training` to
`false`, because the wizard never asked and the template never emitted them. Whole ASVS chapters — V10 (OAuth),
V17 (WebRTC) — are switched off for every app v1 has ever built. Real code from a real tool uses those things, so
in `sv` they are claims like any other, with corroborators, and those chapters come alive.
