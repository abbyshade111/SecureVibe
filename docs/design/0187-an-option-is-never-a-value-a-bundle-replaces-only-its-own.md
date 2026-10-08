# An option is never a value, a bundle replaces only its own, and one answer for a path (5 October 2026)

The deep review's improvement 7, three small guards on what `sv` is told.

- **An option given where a value belongs is refused.** `sv report app --out --run` wrote the report to a folder
  named `--run` and did not start the app. Now a value that starts with `--` is refused with the option named,
  and the message says a name that starts with `-` can be given as `./--run`. A single dash is still a value
  (`--out -out`), as before.
- **A bundle replaces only a zip `sv` made** (ADR-017, Later). Every bundle ends with a comment of its own in the
  zip's comment field; a file at the bundle's name that does not end that way is refused and left as it was.
- **The MCP server gives one answer for a path outside its folder and one that is not there.** "Does not exist"
  for one and "is outside" for the other told whoever asked, the model or text in an app steering it, which
  folders exist anywhere on the computer. Both now read "is not a folder inside ..., so it cannot be read: it is
  outside that folder, or nothing is there".

How it is held: `an_option_given_where_a_value_belongs_is_refused_and_nothing_is_written`
(`crates/sv-cli/tests/options.rs`), `a_bundle_replaces_only_a_zip_sv_made` (`crates/sv-cli/tests/bundle.rs`), and
`a_path_outside_the_root_gets_the_same_answer_whether_or_not_it_exists` (`crates/sv-cli/src/mcp.rs`). Five guards
were undone in turn: the option check, the one answer, the refusal to write over, the comment being checked, and the
comment being written. Each was caught.
