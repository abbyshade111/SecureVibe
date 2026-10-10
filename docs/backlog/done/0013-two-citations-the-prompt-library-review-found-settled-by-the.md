# Two citations the prompt-library review found, settled by the owner on 7 October 2026

**Status:** done, as its markers read on 8 October 2026

From the review in
`docs/prompts/reviews/language-agnostic-variant.md` (#878), put to the owner the same day. (1) `probe.security-headers`
and `probe.private-page-headers` credit V3.4.3 for any Content-Security-Policy, where V3.4.3 asks for a policy that
includes `object-src 'none'` and `base-uri 'none'` and defines an allowlist. **The owner's decision: "The check should
look for them."** (2) `ast.weak-password-key-derivation` cites only V11.4.4 (a key made from a password), where code
storing passwords is V11.4.2. **The owner's decision: "Yes, fix the citation."** (A third question, a time limit on
each tool call for C9.1.1, the owner judged not worth building.) **Claimed the same day by session
securevibe-e2**, at the owner's word, in branch `claude/securevibe-e2-csp-directives`: the header check names a
policy without `object-src 'none'`, `base-uri 'none'`, or a `default-src` or `script-src`; the rule cites V11.4.2
beside V11.4.4. **Record, `Status: proposed`: ADR-047** for the first, and a "Later" entry on ADR-018 for the second,
in the pull request that builds them. Read on `main` just before this claim: no other session had claimed either.
**Done the same day** (DESIGN, "V3.4.3's directives, and V11.4.2 for stored passwords"; ADR-047, accepted). A policy
without `object-src 'none'` (or `default-src 'none'` in its place), `base-uri 'none'`, or a `default-src` or
`script-src` is named in both header checks' findings, on public and private pages. Eight guards broken in turn, each
caught. The V11.4.2 half was built by session paper-facts in #896 (ADR-048), which claimed the same decision unseen
(#888) and merged first; this item's pull request (#889) keeps that version. The shown `security-headers` prompt asks
for neither directive, so a build made with it now gets this finding; whether to change its words is for a prompt
trial.
