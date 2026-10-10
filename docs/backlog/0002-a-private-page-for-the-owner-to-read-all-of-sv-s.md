# A private page for the owner to read all of `sv`'s documentation

**Status:** done, 9 October 2026

Asked for by the owner on 8 October 2026
("build out a private page (just for me on this computer) that makes it easy for me to navigate through all the
documentation and view it"). `docs/` holds a dozen long documents, 40-odd decision records, `docs/paper/`, and
`docs/prompts/`, plus `README.md`, `CLAUDE.md`, and `data/README.md`, all as Markdown, which reads poorly as plain
text and has no way to move between documents. To build:
1. **A script in `tools/`** that turns every document into one set of pages the owner opens in a browser: a list of
   every document by section (getting started, design, decisions, the paper), each document's own headings as a
   table of contents, links between documents that work, and a search box if one can be had without a script
   fetching anything.
   **Part status:** done, with the item
2. **Private and on this computer only.** Written outside the repository (`~/securevibe-docs/`, say) or into a
   folder git ignores, never committed and never published, and fetching nothing from the internet, as `sv`'s own
   pages do. Run again to bring it up to date after a pull.
   **Part status:** done, with the item
3. **A Markdown reader that needs no download**: Python's standard library has none, and neither `markdown` nor
   `pandoc` is installed here, so either a small reader in the script, enough for these documents (headings, lists,
   tables, code, links), or a dependency, which is a decision with its own record.
   **Part status:** done, with the item
4. **Nothing that has no place in it:** the documents are already public, so nothing new is exposed, but the page
   must not pick up anything outside them (no `.env`, nothing in `target/`, nothing from the owner's apps).
   **Part status:** done, with the item
Questions for the owner before it is built: a folder of its own in the home folder, or inside the repository but
ignored by git; and whether the paper's drafts belong in it.
**The owner's answers, 8 October 2026:** "home folder for the docs page, and do not include the paper drafts
please". So the pages are written to a folder of their own in the home folder (`~/securevibe-docs/`), and
`docs/paper/` is left out. These are the owner's decisions; their record (a new ADR, governing the script) is
written as `Status: proposed` with the claim, and accepted in the pull request that builds it.
**Claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("go ahead and build the docs page
next"), in branch `claude/securevibe-e2-docs-page`: `tools/docs_page.py`, which writes `~/securevibe-docs/` from the
documents git tracks, `docs/paper/` and the example apps left out, with a small Markdown reader of its own and a
search box over an index written into the page. Its record, a new decision record governing the script, is
written and accepted in the pull request that builds it (a number cited here before its record exists fails
`every_record_number_cited_is_a_record`).
**Done the same day** (ADR-058, accepted): `python3 tools/docs_page.py` writes 87 documents to `~/securevibe-docs/`,
with the search box working and nothing fetched. Breaks: the paper left in, the search index not escaped, a folder
that was not its own written into, a place inside the repository allowed, every file in its folder removed on a
rerun, and code not escaped, each failed a test (`crates/sv-cli/tests/docs_page.rs`, which also runs its
`--self-test`).
**Parts 2 to 4 claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and pick up new
items as you merge"), from the roadmap (Phase 4, item 5), in branch `claude/stackvet-e9-docs-page-notes`. Read
against `main` just before this claim, they were met by part 1's build and are owed a done note, not a build:
`tools/docs_page.py` writes to `~/stackvet-docs/` and only into a folder it marks as its own (part 2). It reads
Markdown with a reader of its own and no dependency (part 3). It takes only the Markdown git tracks, with
`docs/paper/`, the example apps, `target/`, and `crates/` left out (part 4). No other session had claimed them.
**Parts 2 to 4 done the same day**, by part 1's build (ADR-058), read against `tools/docs_page.py` on `main`. Its
self-test passed 16 of 16, and a full run wrote 707 documents.
- Part 2: it writes to `~/stackvet-docs/`, the home folder the owner chose, and only into a folder it marks as its
  own.
- Part 3: its Markdown reader is its own, with no dependency.
- Part 4: it takes only the Markdown git tracks, with `docs/paper/`, the example apps, `target/`, and `crates/` left
  out (`crates/sv-cli/tests/docs_page.rs`).

Every part of this item is done.

**Marked done 9 October 2026 by session securevibe-e2**, from the roadmap (Phase 5): every part was built and recorded already (see the done notes above); the status line read the numbered decisions or proposals as parts still open.
