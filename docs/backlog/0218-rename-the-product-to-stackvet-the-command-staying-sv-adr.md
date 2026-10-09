# Rename the product to StackVet, the command staying `sv` (ADR-062)

**Status:** claimed by securevibe-review, 8 October 2026

Asked for by the owner on 8 October 2026, after a search found five other products named SecureVibe, SecureVibes,
SecVibe, SecureVibing, or SecurVibe, all in the same space, and a brainstorm of names that keep the initials. The
decision and its reasons are `docs/adr/ADR-062.md`, proposed with this claim and accepted by the pull request that
builds it. In short: the product is StackVet; the command, the crates, the `SV_*` variables, and the image's `sv`
suffix stay; every name the product carries moves into `sv_frameworks::names`; a name a user's files carry
(`securevibe.toml`, the report folder and its marker, the bundle, the config folder with the signing key, the
coding-rules markers, the MCP tool names, the Docker labels) is read under both names for a window and written
under the new; the signature namespace never changes; the paper, the `v1` branch, the tags, and the DOI keep the
old name.

The build is one pull request, or a short series: `names.rs` first, with every crate routed through it and the
old names read beside the new; then the documents (README, CLAUDE.md, ARCHITECTURE, GETTING-STARTED, the `sv init`
template, the MCP catalog); then the Docker image name in `Dockerfile` and `rust.yml`, which the owner's renaming
of the published image has to match. Each name read under its old form gets a test that the old is read, the new is
written, and both present is refused.

**Claimed 8 October 2026 by session securevibe-review**, in branch `claude/securevibe-review-stackvet`, once the
owner says go on the name; the owner's own steps (the domains, the repository's name, the image's) are theirs.

**Step 1 done 8 October 2026** (#1121; design entry 0312): the names module, the crates below `sv-cli` reading from
it, and the report folder found under either name. **Step 2a built the same day** (design entry 0313): the manifest
read as `stackvet.toml` first and `securevibe.toml` while only it exists, said once in the report and at the
terminal; both at once refused. Open after it: step 2b (the MCP server and tool names with the old answered, the
help text, the history folder, the bundle's default name, the `sv review` sentence for the old key folder), then
step 3 (the documents, the image's name, this record accepted). **Step 2b built 9 October 2026** (design entry 0314): the MCP server `stackvet` with its tools
`stackvet_*` and the old names answered, history's folder, the `sv review` note for the old key folder, the
bundle's name, the installed data's folder, and the help text and prose. Open after it: step 3.
