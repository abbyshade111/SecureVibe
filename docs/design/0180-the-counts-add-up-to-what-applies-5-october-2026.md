# The counts add up to what applies (5 October 2026)

R5 of the deep review: an applicable requirement has one of seven statuses (needs attention, checked, documented,
checked by hand, attested, stated, not verified), and most places that counted them left some out. Reproduced on a
copy of `examples/tested-notes` with one of each: compliance.md and report.html opened "130 requirements apply. Of
those, 8 have been looked at by something and 118 have not", four short; their tables had no row for checked by
hand, attested, or stated; the terminal's summary gave three statuses and then the rest as "a further", as if on top;
and the AI coding tool's summary gave three. The short version's list and the chapter table already added up.

- **One list of every status.** `Status::ALL` and `Counts::by_status` give the seven, strongest evidence first, and
  every count table is made from them: compliance.md's and report.html's table of what applies, the short version's
  list, the terminal's summary, which is now a line per status under the total. A test with an exhaustive match fails
  to compile when a status is added without a place in the list.
- **The opening sentence has three parts**, `sv_report::lede`: looked at by something (a problem found or a check),
  resting only on somebody's word (yours or your AI coding tool's), and not looked at at all. The middle part is
  never added to the first, and it is left out when it is zero.
- **Somebody's word is shown as what it is.** Each row for checked by hand, attested, or stated says whose word it
  rests on; the paragraph after the opening sentence says such a requirement is never shown as checked; the
  terminal's lines and the AI coding tool's summary each say "your word, not a check" or "the tool's word".
- **report.json and the MCP server's structured counts** already had every status, and are unchanged; no field was
  added or renamed. security.md counts findings, not requirements, and is unchanged.

How it is held: `the_counts_add_up_to_what_applies_in_every_format` (`crates/sv-cli/tests/counts_add_up.rs`) builds an
app where every status occurs (asserted first, with the tool's answers two and the owner's one, so a count shown in
another tier's row cannot add up by chance), then holds report.json, compliance.md (the short version, the opening
sentence, the table, and each chapter's row), report.html (the same three), the terminal, and `securevibe_check`'s
text and data to the total. `every_status_has_a_row_and_the_rows_add_up` (`crates/sv-report/src/lib.rs`) holds the list
and the sentence. Seven guards were undone in turn (a status left out of each format, the old sentence, and one
status counted from another's field), and each was caught.
