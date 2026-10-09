# The documents and the image say StackVet, and the record is accepted (9 October 2026)


**What changed.** Step 3 of the rename (ADR-062), the last: the documents a person reads and the image's name. The
README, `CLAUDE.md`, the architecture map, the getting-started guide, the prompt library, the dashboard, partial-checks,
and threat-modeling pages, the security and contributing pages, the issue templates, the Dockerfile, the workflows,
the tools' usage lines, and `sv`'s own manifest say StackVet, `stackvet.toml`, `stackvet-report`, the `stackvet_*`
tools, and `ghcr.io/abbyshade111/stackvet-sv`, which CI publishes on the next push to `main` under the workflow's
`IMAGE`. The repository's address is written as `github.com/abbyshade111/StackVet`, which the owner's rename makes
true and GitHub's redirect covers either way. The README says once where the old image went and that the old names
are still read. The record is accepted, with its "How it is held" section naming the tests the three builds added.

**What keeps its wording.** Every sentence about SecureVibe v1 (the README, `SECURITY.md`, `CONTRIBUTING.md`,
`CLAUDE.md`, the Rust workflow's first line), the session names (`securevibe-review`, `securevibe-e2`), the
README's note that entries sealed before 6 October 2026 used `~/.config/securevibe/review-key`, which step 2b's
rename had reached and this step puts back, the two lines of `docs/DESIGN.md` about the earlier version and its
template, the gap analysis and the Semgrep measurement (dated analyses), the paper, the records, the earlier design
entries, the backlog items' text, and the trial protocols: the record's point 8.

**Held by.** The guide's tests (`did_it_connect.rs`, `guide_update.rs`, `review_container.rs`), which compare the
guide with the server's tool list, the workflow's image, and the README; the MCP server's own guide test, whose
literals name the new repository address and folder; and the decision-records test, which refuses a record naming a
test or file that does not exist.
