# A manifest version `sv` knows, a date with nothing after it, and every collapsed list closed (5 October 2026)

Three parts of the deep review's improvement 6.

- **`manifest-version` is checked.** It was read and never looked at, so a file written for a later layout was read
  as version 1, its fields perhaps meaning something else. A version other than 1 is now refused, saying which
  version this `sv` reads (`Manifest::parse`, `MANIFEST_VERSION`). A file with no `manifest-version` line is read
  as version 1, as before.
- **A date with text after it is refused.** `Day::parse` read the first ten characters and ignored the rest, so a
  review entry dated `2026-09-27 or so` counted as dated that day. A date is now `YYYY-MM-DD` alone, or the start
  of a whole RFC 3339 timestamp (`T`, `HH:MM:SS`, a fraction if any, and `Z` or an offset), as the advisory
  databases write theirs. An entry with a date it cannot read is treated as it was before for no date at all.
- **Every collapsed list in `report.html` is closed where it was opened.** The list of requirements nobody has
  placed was closed after the next section, so it held that section too, and with nothing undecided the page had a
  `</details>` and no `<details>`; the list of requirements that do not apply had the same stray close.

The fourth part of improvement 6, a false alarm lapsing when the lines near it change, rests on the fingerprint,
which #678 (R3, A2) is changing, and is left to it.

How it is held: `a_manifest_version_this_sv_does_not_know_is_refused` (`crates/sv-manifest/src/lib.rs`),
`dates_are_read_and_written_the_same_way` with seven new dates that must be refused
(`crates/sv-check/src/advisories.rs`), and `every_collapsed_list_is_closed_where_it_was_opened`
(`crates/sv-report/src/html.rs`), over every combination of the three sections. Five guards were undone in turn and
each was caught.
