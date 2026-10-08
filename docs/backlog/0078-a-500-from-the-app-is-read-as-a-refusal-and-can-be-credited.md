# A 500 from the app is read as a refusal, and can be credited as one

**Status:** done, as its markers read on 8 October 2026

Found on 28 September 2026 by session
securevibe-e10 while fixing the 429 entry above. The signed-in checks read anything but 2xx as the app refusing
(`ok()` in `crates/sv-check/src/signed_in/mod.rs`), so a private page that crashes for a stranger with a 500 is
credited as "refused to somebody not signed in" (V8.2.1), as a 429 was. A crash is not an answer to whether the
page is private. Fix, as a suggestion: read a 5xx as no answer wherever a refusal would be credited, and say the
requirement is not assessed with the status; a finding from a 5xx (a stack trace, say) is a separate question.
**Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item, in
branch `claude/securevibe-e2-server-error`.
**Done the same day:** `Patient` records every signed-in request answered with a 5xx or not at all, and
`RESTS_ON_A_REFUSAL` names the requests each of the 29 refusal-credited passes rests on; a pass one of whose
requests crashed is not assessed, naming them, and the rest of the run's passes and all its findings stay. A test crashes every request of six setups, one at a time, and fails when a rule found at fault comes back credited; it found requests of five kinds the first list missed. Six guards, each broken in turn, each caught. See DESIGN, "A crash is
not a refusal".
