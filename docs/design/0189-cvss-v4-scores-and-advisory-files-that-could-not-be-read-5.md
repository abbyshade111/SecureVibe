# CVSS v4 scores, and advisory files that could not be read (5 October 2026)

The deep review's improvement 4. 2,340 OSV records carry only a CVSS v4 vector, and each was shown as a placeholder
medium, since only v3 was scored. And a file in the advisory database that `sv` could not parse was skipped in
silence, so a database with a broken file compared as if it were whole (ADR-033).

- **v4 is scored with FIRST's own tables.** v4 is not a formula: a vector falls in one of 270 groups whose scores
  FIRST's experts assigned, and is moved down within its group by how far it is from the group's most severe
  vectors. `tools/cvss4_tables.py` copies the tables from FIRST's reference calculator
  (`github.com/FIRSTdotorg/cvss-v4-calculator`, commit `c5b0d40`, BSD-2-Clause, its notice kept) into
  `crates/sv-check/src/cvss4_tables.rs`, and `cvss4::score` follows the calculator's `cvss_score.js` step for step,
  in the same order of arithmetic, so its rounding lands where the calculator's does. Base and threat metrics are
  read; environmental ones, which describe a deployment, take their defaults. `cvss::severity_of` takes the first
  vector it can score, v3 or v4.
- **Held to the reference's own output.** The tool asks the calculator's JavaScript to score 1,624 vectors, every
  base value and a fixed random draw each with every threat value, and the test holds `sv` to every one. All
  419,904 base and threat vectors were compared the same way and every one agreed; that file is too large to keep,
  and the test reads it when `SV_CVSS4_ALL` names it.
- **An advisory file that could not be read is named.** `advisories::read_database` keeps each file it could not
  parse, with why. `sv audit` lists them, makes no claim that nothing was missed, and exits 2; `sv report` adds them
  to what the comparison could not cover, names them under "What was not examined", and credits nothing on the
  comparison.

Two steps of the reference cannot be told apart by any base or threat vector, checked over all 419,904: which of two
equal next-lower groups is taken, and which of the group's most severe vectors the distance is measured from. They
are kept as the reference has them, so the port stays step for step with it, and no test catches undoing them.

How it is held: `every_score_equals_the_reference_calculator_s`, `the_textbook_vectors_score_as_first_publishes_them`,
and `a_vector_that_is_not_a_whole_v4_vector_is_not_scored` (`crates/sv-check/src/cvss4.rs`);
`a_record_with_only_a_v4_vector_is_rated_by_it` (`cvss.rs`) and `an_advisory_with_only_a_v4_vector_is_rated_by_it`
(`advisories.rs`); `an_advisory_file_that_cannot_be_read_makes_the_comparison_partial` (`sv audit`) and
`an_advisory_file_that_cannot_be_read_is_named_and_nothing_is_credited_on_the_comparison` (`sv report`). Eight
guards were undone in turn and each was caught; the two steps above were undone too, and, as said, nothing could.
