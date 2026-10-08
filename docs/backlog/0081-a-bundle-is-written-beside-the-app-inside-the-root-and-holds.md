# `a_bundle_is_written_beside_the_app_inside_the_root_and_holds_no_secret` failed once

**Status:** done, as its markers read on 8 October 2026

Seen on 29 September
2026 by session securevibe-e2 in a whole-workspace run under load (a mutation run of the rate-limit code, which
that test does not touch); it passed three times alone. Not reproduced. A guess, marked as one: it asserts that
the four bytes `4471`, a fragment of the planted secret, appear nowhere in the zip's raw bytes
(`crates/sv-cli/src/mcp.rs`), and a zip holds timestamps and compressed data in which four given bytes can occur
by chance. If so, the fix is to read the zip's entries and look in their contents. **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take a backlog item, in
branch `claude/securevibe-e2-bundle-test`.
**Done the same day, and the guess was wrong:** the zip is stored uncompressed with fixed dates, so four bytes
do not turn up by chance. The bundle names the folder the test made, 17 times, and that folder was named with the
process id (`sv-mcp-bundle-beside-<pid>`), so the test failed whenever the process id held `4471`. Reproduced
every time by putting `4471` in the folder's name. The test now looks for the whole secret, and its folder is
named `beside-4471` on purpose, with an assertion that the bundle does carry that name, so looking for less than
the whole secret fails on every run. Broken both ways: the four-digit check put back fails it, and a `.env` let
into the bundle fails it (and `files_named_like_secrets_keys_and_databases_stay_out` in `tests/bundle.rs`).
