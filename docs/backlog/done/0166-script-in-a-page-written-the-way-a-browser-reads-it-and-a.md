# Script in a page written the way a browser reads it and a parser does not

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 27
September 2026 by session securevibe-e8. The premise was wrong in a way that mattered: where an
unquoted value ends is not a question with two answers, because the HTML standard ends it at whitespace
or `>`. And "each keeps a page unread" was not true of all of them. Checked against pages a browser
runs, three were counted as read with nothing taken out: an unquoted handler
(`<button onclick=eval(location.hash)>`), a `/` between attributes (`<img/onerror="…">`), and
`href="java&#9;script:…"`, where the entity became a tab only after the disguise check had looked. All
three were false cleans. `html_fragments` now walks start tags the way a browser's tokenizer does and
reads each value the way the URL standard does (put back character references, strip the ends, remove
tabs and newlines, then read the scheme). What is still named rather than read, and why, is in
DESIGN, "A page of markup is not a hole in the coverage". This is also the owner's decision the same
day, asked through another session: read them the way a browser does.

Verified: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and the full workspace suite.
Broke eight things on purpose and watched each go red: unquoted values dropped, tabs kept in a URL, the
`javascript:` count switched off, raw-text bodies read as tags, `/` not a separator, the near-scheme
check switched off, numeric references not decoded, and unknown named references ignored. The last one
was caught by nothing at first, because its only fixture (`&alpha;()`) was also refused by the grammar.
A second fixture, `x&alpha;(1)`, parses when the reference is left as written, and now catches it.
