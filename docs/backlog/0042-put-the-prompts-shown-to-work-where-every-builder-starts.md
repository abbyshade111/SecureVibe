# Put the prompts shown to work where every builder starts

**Status:** claimed by paper-facts, as its markers read on 8 October 2026

Found on 6 October 2026 by session paper-facts, in
the delivery test: a prompt pasted into the request did better than the same prompt fetched mid-build in every
comparison (Haiku's security headers 0 of 6 pasted, 2 of 6 through the guidance; keys and `.env` 1 of 4 against 4 of
9; the AI prompt 0 of 9 pasted, and seldom delivered at all through the brief). Every builder reads the server's
opening instructions and the specification before any code. A short line in either, naming the shown prompts and
where to get them, or the shortest of them in full, is the next delivery to measure, with the same harm rule.
**Claimed on 7 October 2026 by session paper-facts**, at the owner's word, in branch
`claude/prompts-at-start`: the coding prompts shown to work, in full, at the end of the MCP server's opening
instructions and of the specification `sv init` prints, read from `data/prompts.json` so they cannot drift; then a
test of 40 builds, approved by the owner.
**With it, at the owner's asking: independent reviews of the prompt library from other sessions.** Each reviewing
session writes `docs/prompts/reviews/<its name>.md` in a pull request of its own: the wording of every prompt, and
suggestions for new ones, each tied to an `sv` check and the requirement's own text. Suggestions are tried the way
the library's prompts are before any is marked shown. Asked of the two cloud sessions that build `sv`.
**The prompts at the start, done on 7 October 2026** (`docs/prompts/library-trial/start.md`): forty builds, $18.11.
For Sonnet, the keys-and-`.env` prompt works given at the start (9 of 10 builds without, 0 of 10 with), the first
delivery through `sv` the rule calls working; the AI prompt removed two of its three problems, not the third. Haiku's
baseline had already fallen (with `git` allowed and the guidance's prompts), so its comparisons have no reading. No
harm. This test and the delivery test used the loop protocol's owner-away sentence from before its Amendment 5,
said in `start.md`.
**The reviews arrived the same day** (`docs/prompts/reviews/language-agnostic-variant.md`, `second-builder.md`), and
**were applied on 7 October 2026 at the owner's word**: wording fixes to four shown prompts and five others, three
checks moved to the running app, a fallback for every design prompt that asks the owner, and five new prompts
(`limits-without-asking`, `password-rules`, `production-server`, `isolate-the-window`, `security-contact`), all to be
tried in `docs/prompts/library-trial/revision-protocol.md` before any status changes. One finding is left for the
owner: `ast.weak-password-key-derivation` cites V11.4.4 (keys made from a password) where storing passwords is
V11.4.2, so `password-hashing` cannot cite V11.4.2 until the rule's citation is decided, which changes evidence.
**The revision trial, done on 7 October 2026** (`docs/prompts/library-trial/revision.md`): 110 builds, $35.28, 38 of
them built again after the credit ran out. All four revisions kept. `isolate-the-window` shown on Sonnet (10 of 10,
then 0 of 10) and `security-contact` on Haiku (8 of 8, then 0 of 9), both marked shown by the owner the same day;
`production-server` and `limits-without-asking` not shown. No harm. With the shown prompts at the start, Haiku's
missing headers and committable `.env` were already gone without anything pasted.
