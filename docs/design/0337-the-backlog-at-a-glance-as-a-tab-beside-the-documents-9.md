# The backlog at a glance as a tab beside the documents (9 October 2026)


Asked for by the owner on 9 October 2026: "can you add the backlog tracking page just built as a tab or view off of
this page so it's all in one place?" The backlog at a glance (`backlog-board.html`, backlog item 225) is already
written into the owner's private documentation set by `tools/docs_page.py`, but it was reached only from a link on
the index page.

**What changed.**

- Every page of the set now opens its sidebar with two tabs: **Documents**, the index, and **Backlog at a glance**,
  the board. The one being read is marked.
- A page in a folder links back up to both. So from any document, a decision record or a backlog item, the board is
  one click away, and so is the way back.
- Nothing else about the set changed:
  - It is written to the same folder.
  - It reads the same documents.
  - It fetches nothing.
  - Its search box and per-document navigation are as before.

**Tests.** `crates/sv-cli/tests/docs_page_tabs.rs` writes the set and checks every page:

- that it has both tabs in that order;
- that each tab leads to a file that exists;
- that only the board's page marks the board's tab.

Three breaks each failed it:

- a link that does not climb out of a folder;
- the tabs left off;
- the board not marked as the page being read.
