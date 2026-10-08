# The code-reading rules and lockfiles: five faults from the review of 1 to 4 October (6 October 2026)

Items 18, 20, 21, 22, and 23 of the review (BACKLOG). Each was confirmed with a case that failed before the fix.

- **The SQL rule read too few query calls** (item 18, `data/ast-rules.json`). A query built by hand and sent through
  a call the rule did not read went unfound, and the clean result credited V1.2.4. Now read as well:
  - Go's `QueryRowContext`, `Prepare`, and `PrepareContext`; the `Context` forms take the query second, as before.
  - Kotlin's `prepareStatement` and `prepareCall`, with `executeLargeUpdate` and `addBatch`, as Java's are.
  - C#'s `CommandText` set to a built string and then executed, as `cmd.CommandText = … + n` and inside
    `new SqlCommand { CommandText = … }`. An assignment to any other property (`l.Text = "Hello " + n`) is not read.
  The clean result names the calls it reads, so it now names these too.
- **Lockfile disagreements for dependencies the readers never list** (item 20, `manifest_lock.rs`). A dependency from
  a workspace (`workspace:*`), a folder (`file:`, `link:`, `./lib`), a repository (`git+…`, `github:…`, `user/repo`),
  an archive's address, or the registry under another name (`npm:other@1.2.3`) is listed by what it is, if at all, so
  its absence under its own name was a false "the lockfile does not have it". So was `pkg @ git+…` in
  requirements.txt. Each is now not compared when missing. A registry package missing from the lockfile still
  disagrees.
- **A panic on a build file** (item 21, `gradle_range`). `implementation 'g:a:['` sliced `[1..0]`, and a range ending
  in a letter outside ASCII would have sliced inside it. The brackets are now taken off as characters, and a range
  must end with one: `[`, `(`, `[1.0,2é`, and `[1.0,2.0` read as no range. Maven's `]1.0,2.0[` still reads.
- **`shell: true` on a fixed argument list** (item 22, `ast.rs`). `run(["ls", "-la"], shell=True)` and
  `spawn("ls", ["-la"], { shell: true })` were reported, since the check for a fixed list knew Dart's, Swift's, and
  Rust's names for a list and not Python's (`list`, `tuple`) or JavaScript's (`array`). A list holding a value
  (`["ls", folder]`) is still found.
- **`go.mod` was compared with itself** (item 23, `sbom.rs`). Since A3 the list of Go modules comes from go.mod's own
  `require` lines, and the comparison was given that list, so it could never disagree. It is now given what go.sum
  holds, while the list stays what go.mod says is built: a module go.mod requires at a version go.sum does not hold
  disagrees.

How it is held: cases added to `the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one` (items 18 and 22) and
`gradle_versions_are_read_as_gradle_resolves_them` (item 21), and two new tests,
`a_dependency_from_somewhere_other_than_the_registry_is_not_said_to_disagree` and
`go_mod_is_compared_with_go_sum_and_not_with_itself`, each with its control. Twelve guards were undone in turn, and
each was caught.
