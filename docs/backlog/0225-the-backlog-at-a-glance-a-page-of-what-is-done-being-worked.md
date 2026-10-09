# The backlog at a glance: a page of what is done, being worked on, and still to come

**Status:** done, 9 October 2026

Asked for by the owner on 9 October 2026 ("Just want an easy way to get a general overview of what's done, being
worked on, still to come"), choosing this over a mirror of the items into a GitHub project, which sessions could
neither read nor write from where they run. One more page in the owner's private set (`tools/docs_page.py`,
ADR-058), written from the items' own status lines: the counts, then every item under one of three headings, still
to come, being worked on, and done, each linking to the item's page, with the roadmap phase that names it and the
session that holds it. Nothing new to keep: the items stay the record, and the page is remade with the rest when
the tool runs. Held by a test that compares the page's counts with what `tools/backlog.py summary` prints.
