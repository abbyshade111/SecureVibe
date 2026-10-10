# The build-loop record counts findings gone, set aside, and new (10 October 2026)


Backlog 0231: ADR-084's decision 6, item D of the observability review's part 3 (backlog 0226). Built by session
securevibe-e2.

**The problem.** The record of the build loop kept only the first and the last check's counts, so a total that
dropped could be the AI coding tool fixing findings, or a person setting them aside as false alarms, or both, and the
report could not say which.

**What was built.** A check line keeps the check's findings' fingerprints (`build_loop::fingerprints_of`: sorted, each
once, at most 1,000, with `fingerprints_cut` past that). The server takes them from the check as it takes the counts
(`last_fingerprints`). `summarize` keeps the first and the last check's lists when their lines kept them whole, and
`settle`, called where the report reads the record (`report_folder.rs`), counts those gone, those of them the report
holds as a person's false alarms (its `set_aside` entries no longer among its findings), and those new, into
`build_loop.findings_moved`. The paragraph says "no longer found (fixed, or no longer reached by the check: the record
cannot tell which)", never "fixed".

**Found on the way.** `sv`'s fingerprints are not all hex: the newer ones read `v2-61eb1668992f3990`. The first rule for
what a fingerprint looks like accepted hex only, so every real check line read as unreadable; the unit tests, written
with made-up hex fingerprints, passed, and the end-to-end test through the server failed. The rule is now letters,
digits, and hyphens, which still refuses a finding's words, and the unit test holds a `v2-` fingerprint.

**Tests.** `crates/sv-cli/src/build_loop/fingerprint_tests.rs` (4: sorted, each once, capped; read back, and words or
too many refused; each finding counted once between the first check and the last; nothing said with one check, a cut
line, or an older line) and `crates/sv-cli/src/mcp/build_loop_fingerprint_tests.rs` (1, through the server: a report,
then a SECURITY.md added, code with a new finding, and a person's false alarm sealed as `sv review` seals it, a check,
and a report counting one no longer found, one set aside, and one new; the record holding hashes and no code).

**Broken on purpose, each put back:** fingerprints not written to the line (1 red), no cap (1 red), words accepted as a
fingerprint (1 red), a cut line compared (1 red), set-aside findings counted as gone (2 red), the report's false alarms
not passed (1 red), one check compared with itself (1 red), and the counts not said (1 red).

**Left for later in ADR-084:** decisions 3 (the names `sv` defines that a call asked for) and 5 (what was handed
over).
