# From the review of 8 October 2026: the medium and low findings, for any session to pick up

**Status:** open

The four rated
high were built the same day (the entry above this one's predecessor). Each of these can be claimed on its own.
1. Ctrl-C during `--tools` leaves the tool running with no limit: tools get their own process group
   (`adapters.rs`, `process_group(0)`) and that path installs no handler, so SIGINT kills `sv` alone and the
   30-minute limit, the private folder, and the lock's `Drop` are gone. The handler `sv-run` uses, killing the
   recorded group.
2. npm lockfile `resolved` URLs are not held to the registry (`install.rs`), so the install container fetches
   wherever the lockfile says; refuse unless every entry is `https://registry.npmjs.org/` with `integrity`, as
   pip's `unpinned` refuses. And a dependency file that is a symlink is followed into the networked container
   (`symlink_metadata`, refuse a link).
3. gosec fetches modules and runs the C toolchain, undeclared: `GOPROXY=off` and `CGO_ENABLED=0` in its `env`, or
   mark it `network: true` and say so in the README. CodeQL's extractors may run the app's package manager or
   `sitecustomize.py`: test it the ADR-032 way with a planted `preinstall` and `sitecustomize.py`. gosec,
   Brakeman, and CodeQL walk the folder themselves and follow links `sv` refuses: skip them when `listing.links`
   is non-empty, or list the links in `looked_away`.
4. A planted `.securevibe-report` marker lets `securevibe_write_report` replace five named files in any app
   subfolder (`main.rs`, `refuse_someone_elses_folder`: a marker alone counts for writing). Require
   `is_sv_output` or a proven seal, else "give an empty folder".
   **Claimed 8 October 2026 by session securevibe-e2**, from the roadmap (Phase 1, item 1, first in its order), in
   branch `claude/securevibe-e2-report-marker`: a folder with the marker counts as `sv`'s own only when what is in it
   shows it is (`is_sv_output`), so a marker alone no longer lets a report replace files there. Confirmed on `main`
   just before this claim: `refuse_someone_elses_folder` lets any marked folder through, and no other session had
   claimed this part.
5. Honesty gaps: an unreadable lockfile or unparseable manifest silently drops the manifest-versus-lockfile
   comparison (`sbom.rs:281, 437`; `manifest_lock.rs` returning `None`), so an unsaid comparison reads as
   agreement: an `unread` entry naming the file. The credit census (`tools/coverage.py`, `check_credits`) checks
   per check, not per requirement: a check citing two ids whose tests only ever credit one passes; also fail on
   `ids - got`, and mirror a findings log. `model_provider.rs` passes silently without `node`: honor
   `SV_REQUIRE_BACKEND` there.
6. Low: a FIFO named `securevibe.toml` hangs the MCP server's serving thread (`app_dir` refuses links only);
   `Secret::redact` keeps four characters whatever the length, so a 4-character URL password is shown whole (show
   `min(4, len/3)`); `redact_text` masks only listed names, and `authorization`, `bearer`, `cookie`, `session`,
   `otp`, `pin` are missing, so a token a failing test prints reaches the report; a newline in a file name or a
   tool's finding title starts a fake terminal line (`main.rs`, the findings loop: use `one_line`); header values
   are quoted into findings uncapped (`production.rs`, `probes.rs`); an IDN host is not refused by `sv probe`, and
   curl's `--resolve` key would not match its punycode form; the no-sidecar fallback bypasses `prepared`, so those
   containers get no limits or run label (`docker.rs`, `inside_fence_with_input`); `image` is not validated
   against Docker's reference grammar; the typed passphrase `String` is not zeroized (`review.rs`); the DNS
   transaction id is predictable (`live_tls.rs`); a broken `adapters.json` is exit 3 with `--tools` and silent
   without; `main.rs` exits 130 in one place without the flush `exit_with` does; the bundle's scratch folder in the
   system temp dir is a write outside the root no document records; `report.html` has no Content-Security-Policy
   meta tag; the install volume's cache key is FNV-1a (use SHA-256).
7. Housekeeping: fourteen British spellings against the American standard ("cancelled" in `rust.yml`, ADR-051,
   GAP-ANALYSIS, this file, `fake_app.rs`; "honoured" in `codeql.yml`; "licence" in ADR-018 and this file;
   "labelled" here; "recognise" in `docs/prompts/trial-4`); a home path with the owner's first name in
   `docs/prompts/library-trial/recipe-summaries.txt`; `assemble_report_saying` is 1,585 lines and
   `Adapters::load` runs three times per report; `main.rs` hard-codes the tool list and omits semgrep.
