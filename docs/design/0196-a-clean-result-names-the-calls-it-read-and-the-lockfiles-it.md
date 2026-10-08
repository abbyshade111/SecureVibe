# A clean result names the calls it read and the lockfiles it compared (5 October 2026)

The deep review's improvement 2: a clean claim should name its limits, so "nothing found" is not read as wider than
it is. The SQL rule's part was done with H1 ("The query calls each language really uses"); this does the rest.

- **The code rules name the calls they read, language by language.** Each rule finds a fault only in the calls its
  pattern names for a language (`functionPatterns`): Python's shell rule reads `system`, `popen`, `getoutput`, and
  `getstatusoutput`, not `subprocess.run`. A clean result now says so, beside the files read: "in 1 python file (the
  calls it reads: `system`, `popen`, `getoutput`, and `getstatusoutput`)". The names are taken from the pattern
  itself, so they cannot drift from what is read. A pattern that also stands for something that is not a plain
  name, such as a shell named in quotes in Go or a family of names in C, lists its plain names and says "and others
  like them"; one with no plain names lists none. A language the rule already describes in words of its own
  (`looksForIn`: shell's commands, Node's file calls, the redirect calls) keeps those words.
- **The comparison with advisories names what it compared, and what no lockfile lists.** Its clean claim said "all
  68 packages in the bill of materials, compared against 2856 advisories". It now names how many packages of each
  ecosystem, and the lockfiles they were read from; says that is everything each lockfile lists, the packages those
  need in turn and the development packages a lockfile keeps included; and says what is not in it: anything
  installed another way, such as the system's own packages, a container image's, or a script loaded from another
  site. The inventory's own claim (V15.1.2) names the same. The claim is made only when every package came from a
  lockfile (`Sbom::is_complete`), so a lockfile is always there to name; a hash-pinned requirements file read as one
  is named as well.

How it is held: `a_clean_result_names_the_calls_it_read_in_each_language` and the two clean-result tests updated
with the calls (`crates/sv-check/tests/clean_coverage.rs`);
`a_pattern_of_names_is_read_as_its_names_and_anything_else_as_more` (`ast.rs`);
`a_clean_comparison_names_its_ecosystems_its_lockfiles_and_what_is_not_in_it` (`advisories.rs`), over a real folder
with an npm and a Pipenv lockfile, each with a development package; and
`a_requirements_file_under_another_name_that_pins_and_hashes_is_read` (`sbom.rs`). Ten guards were undone in turn.
Eight were caught; two carried no weight and were taken out: reading a pattern's outer parentheses only when they
pair, which no pattern's result depends on, and sorting the lockfiles, which are already read in a fixed order.
