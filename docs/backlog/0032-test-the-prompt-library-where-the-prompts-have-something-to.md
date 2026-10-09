# Test the prompt library where the prompts have something to fix

**Status:** done, 9 October 2026

Proposed on 6 October 2026 by session
paper-facts, reviewing the library at the owner's asking; **the owner's decision the same day: write it up, with the
trial's cost to be approved when it is ready.** Of the library's 27 prompts, 5 are shown to work, 14 are not shown,
and 8 have no check. Eleven of the fourteen were not shown because the build without the prompt was already safe:
they were tried with a strong Claude model, on one or two builds each. The loop's item 6 has the baseline that
testing them needs: in its Haiku 4.5 builds without the server, the problem a prompt is for was there in 6 of 9
(password hashing), 4 of 9 (keys in the code), 8 of 8 (security headers), 5 of 8 (no limit on wrong passwords),
6 of 8 (no limit on records), and 5 of 8 (session faults); in Sonnet 5.5's, in almost none.
1. **Prompts for the commonest problems the library has none for**, from item 6's findings: the AI feature's way in
   and way out (C2.1.3, C7.3.2, C7.3.4, the commonest running-app findings, in 3 to 7 builds an arm); a request from
   another site (V3.5.1); a private page kept in the cache (V14.3.2); and the session itself (V3.3.2, V3.3.4,
   V7.2.3, V7.4.1). Added as `untested`. No security contact (`config.security-contact`) is the commonest finding
   of all, and gets no prompt: its rule cites no requirement on purpose, and a prompt is held to the requirements
   its check cites (`tools/coverage.py`).
2. **A protocol, fixed before any build:** Haiku 4.5, the loop's plain brief with the specification, each prompt's
   builds against one shared set without any prompt; how many builds; the rule for "shown"; and harm measured in
   the same builds (every finding, and whether `sv` could still start the app and sign in).
3. **The trial,** at the size the owner approves.
4. **Then how a prompt is delivered,** for those shown to work: pasted into the request, or returned by
   `securevibe_before`.
**Claimed on 6 October 2026 by session paper-facts**, at the owner's word, in branch `claude/prompt-trial`.
**Items 1 to 3 done the same day** (`docs/prompts/library-trial/README.md`): four new prompts, the protocol, and
ninety builds for $21.12. Shown to work by the rule: `ai-feature-guard` (Sonnet, the AI feature's problems in 10 of
10 builds without it, 0 of 9 with it, no harm), and on Haiku `security-headers` (6 of 6, then 0 of 6),
`private-pages-no-store` (5 of 5, then 0 of 4), and `secrets-in-the-environment` (6 of 6, then 1 of 4), these three
with a harm flag the owner read as the median counting apps that never started, and marked shown. No reading for
`password-hashing` and `sessions-hard-to-steal`; `design-limits` stops the build to ask an owner who is away, and is
kept shown with a warning. The library: 9 shown, 13 not shown, 9 not tried. Item 4 (how a prompt is delivered) is open.
**Item 4 claimed on 6 October 2026 by session paper-facts**, at the owner's word, in branch
`claude/prompt-delivery`, with two changes first: `securevibe_before` (and `sv brief`) gives the coding prompts shown
to work for the requirements a feature brings, which it did not (it gave only the design-time ones); and the
specification's fix for unreadable settings files (the item below), re-tested on 20 Haiku builds. Then the delivery
test: 40 builds with the full server, with the prompts in the brief and without, at the owner's approved size.
**Item 4 done the same day** (`docs/prompts/library-trial/delivery.md`; ADR-044, "Later"): sixty builds,
$19.36. The specification's fix removed both named mistakes (16 of 70 Haiku builds before, 0 of 20 after) and
roughly halved unreadable settings files (34% to 15%; "partly" by the rule). Delivery through `sv` is not shown to
work for any prompt: the feature briefs mostly never reached the builders, because `securevibe_before` refuses until
`securevibe.toml` exists and they asked first; the guidance did reach them, and halved Haiku's problems, less than
pasting the prompt did. Four items below follow.
**Marked done 9 October 2026 by session securevibe-e9**, from the roadmap (Phase 4, item 2), read against `main`: items 1 to 3 and item 4 are each done above (`docs/prompts/library-trial/README.md` and `delivery.md`). The four items the delivery test raised are their own entries.
