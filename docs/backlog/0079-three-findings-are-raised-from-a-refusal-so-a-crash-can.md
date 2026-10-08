# Three findings are raised from a refusal, so a crash can raise them falsely

**Status:** done, as its markers read on 8 October 2026

Found on 29 September 2026 by
session securevibe-e2 while fixing the item above. `SIGN_OUT_ON_GET` (`signin.rs`, `private-after-get-logout` not
2xx read as the session ended), and `COMPOSITION_RULES` and `LONG_PASSWORD` (`passwords.rs`, a strong or long
password that did not work read as refused). A crash on those requests reports a fault the app may not have. A fix
in the same shape: record which requests those findings rest on, and move the finding to not assessed when one of
them crashed, with a test that crashes each request of a correct app and fails when one of these appears.
**Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item, in
branch `claude/securevibe-e2-crash-findings`.
**Done the same day:** five findings, not three: the sweep that crashes each request of a correct app also raised
`RESET_REVEALS_ACCOUNT` (a reset for nobody that failed) and `NO_BRUTE_FORCE_LIMIT` (a guess that failed may not have
been counted). `RAISED_ON_A_REFUSAL` names each one's requests, and a finding one of whose requests crashed is not
assessed, naming them. The test fails on any finding a crash raises, listed or not. See DESIGN, "A crash is not a
refusal", its "Later the same day" part.
