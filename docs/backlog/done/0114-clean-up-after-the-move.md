# Clean up after the move

**Status:** done, as its markers read on 8 October 2026

**Claimed on 27 September 2026 by session securevibe-e8**, at the owner's
asking. Found by a review of `main` after the move: the rule against printing or committing a key is
missing from the new `CLAUDE.md`; CodeQL scans only Rust, while `crates/sv-run/assets/*.mjs` is real,
unscanned JavaScript; `data/knowledge/threats.json` names two `agnostic/` paths; Dependabot does not
watch the `Dockerfile`; and the security policy stayed with v1, so `sv` has none. The owner chose
GitHub's private vulnerability reporting as the way to report a problem in `sv`.
**Done in the same pull request as this note:** the key rule is back in `CLAUDE.md`; CodeQL now scans
JavaScript and Python as well as Rust, with `examples/` excluded like the fixtures; the two paths are
fixed; the `Dockerfile`'s base images are pinned to fingerprints, which Dependabot now moves weekly (their
names carry no version, so without a fingerprint it would have had nothing to update); and `SECURITY.md`
at the root is `sv`'s policy. The owner turned private vulnerability reporting on the same day (GitHub's
API said `"enabled": false` before, `true` after). The new CodeQL legs passed on the pull request with no
new alert; alerts on `main` were not readable from the session, and any that appear in
`crates/sv-run/assets/`, whose stand-in services misbehave on purpose, are each to be read and dismissed
with its reason, or fixed.
**Closed on 7 October 2026:** the owner looked at the Security tab's code scanning page for `main`: 0 open alerts,
65 closed, and every tool working. Nothing in `crates/sv-run/assets/` was waiting to be read or dismissed, and the
recent pull requests' CodeQL checks each said "No new alerts in code changed by this pull request".
