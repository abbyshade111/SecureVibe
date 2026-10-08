# Seals as SSH signatures, so CI and a second computer can check them without being able to make one

**Status:** done, as its markers read on 8 October 2026

The owner
chose SSH signing on 6 October 2026, on the research above, and took every recommendation in the plan session
securevibe-e10 walked them through ("go with the recommendations please"). **Claimed the same day by session
securevibe-e10**, in branch `claude/ssh-seals`. **Record, `Status: proposed`:** ADR-043 (`docs/adr/ADR-043.md`),
to be made accepted in the pull request that builds it. In short: `sv review` makes a signing key of its own beside
`review-key`, with a passphrase if the owner wants one, and signs each answer (`v3:<app id>:<signature>`); a trusted
list (`~/.config/securevibe/allowed_signers`, or `SV_TRUSTED_SEALS` on CI) says which key may seal for which app; the
report names the key it trusted and where the list came from; today's `v2:` seals keep counting where they count
now, and `sv review` asks one yes to sign them again. One new dependency, `ssh-key`. Report seals are unchanged.
**Done the same day** (DESIGN, "Seals become signatures"; ADR-043 accepted, with where the build differs: the
signature in hex, the passphrase asked once per run, no `review-key` made any more, and a list `sv` cannot read in
full trusting nothing). Built first on `ssh-key`, which failed `sv`'s own audit (an RSA crate it never builds, with an
unfixed advisory, in the lockfile), so at the owner's choice OpenSSH's formats are written over `ed25519-dalek`
instead (`ssh_format.rs`); `ssh-keygen` and `sv` read each other's keys and signatures in tests. Nineteen guards broken
in turn: sixteen caught by two tests or more, and three second checks behind a stronger one, as ADR-043 says. Not tried on a real CI run with a repository variable, and the hidden
passphrase is not tested, since that needs a person's terminal.
