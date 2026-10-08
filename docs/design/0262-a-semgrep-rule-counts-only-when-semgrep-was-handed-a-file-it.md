# A Semgrep rule counts only when Semgrep was handed a file it reads (7 October 2026)

The gap analysis (`docs/GAP-ANALYSIS.md`, 1.2) found Semgrep's clean runs crediting requirements through rules that had
read nothing. Many rules name the files they read, in their own `paths.include`: Rails template rules read `*.erb`,
nginx rules read `*.conf`, and the .NET cookie rule reads `web.config`. Semgrep applies that to files named on its
command line as well as to a folder. `sv` hands it the app's code files, so those rules ran over nothing, and a clean
run counted them anyway. A JavaScript app's cookie settings (V3.3.1) were credited that way through a `web.config` rule.

- **What each rule reads.** `data/adapters.json` now carries, for each mapped rule that narrows its files, `targets`
  (its `paths.include`) and `skips` (its `paths.exclude`). They are copied by `tools/semgrep_rule_map.py --targets`
  from the same semgrep-rules checkout (a84ff9c) as the map: 74 of 1,035 rules.
- **When a rule counts.** `clean_run_evidence` takes the files the tool was handed, and a rule that names its files
  counts only when one of them is a file it reads (`MappedRule::reads`). The patterns are read as gitignore reads
  them, which is how Semgrep does: a pattern with no `/` matches a file's or folder's name at any depth, `*` stays
  within a name, and `**/` crosses folders (`path_matches`). This holds for rules of one language as well. The
  WordPress plugin audit reads only `wp-content/plugins/`, so a PHP app that is not a plugin no longer has its
  anti-forgery protection (V3.5.1) credited through it.
- **What still counts.** The key-pattern rules read every file except bundles, lockfiles, and a few others, so they
  still count over code. A rule that names no files counts as before. Tools other than Semgrep name no files and keep
  their whole map.
- **The coverage count.** `tools/coverage.py` leaves out the 22 loaded rules none of whose patterns can match a file
  `sv` hands over, judged against `language_of`'s extensions. No requirement was named only by them, so no count
  moves; `docs/COVERAGE.md` says so.
- **Not done.** Handing Semgrep the templates and configuration files as well, so that these rules run at all, is in
  the backlog. It would change what `sv` gives an outside tool, and the "did not read every file it was given" check
  would first need to know which of those files Semgrep reads.
- **Guards, each broken on purpose.** Counting every rule whatever it was handed turned three tests red. The real run
  passing no files turned none red until `a_rule_for_templates_counts_only_when_a_template_was_handed_over`
  (`crates/sv-check/tests/unread_files.rs`) was written, and that test then caught it. Matching a name-only pattern
  against the whole path turned four red. Dropping the zero-folder reading of `**/` turned two red, and letting `*`
  cross folders turned one red. Ignoring `skips`, or counting a rule with only `skips` without a file, turned none
  red until `a_rule_handed_only_files_it_skips_counts_for_nothing` was written, and that test then caught both.
  Counting every rule in `tools/coverage.py` turned the coverage document's test red. Each was put back.
