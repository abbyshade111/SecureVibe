# Five findings of the documentation review (6 October 2026)

Items 1, 3, 5, 6, and 7 of "Found by the documentation review" (BACKLOG), each confirmed in the code first.

- **1. A clean run no longer credits V15.2.4** (`data/ast-rules.json`, ADR-018, Later). `ast.download-piped-to-shell`
  is findings-only: no `curl … | sh` says nothing about where dependencies come from. Held by
  `a_shell_script_with_no_download_piped_to_a_shell_credits_nothing_about_dependencies`, with the pipe still found as
  its control.
- **3. `admin-actions` make an admin** (`UsersSection::makes_an_admin`, `sv_run::accounts_for`). Only `admin` pages
  made one, so admin actions listed alone were not assessed, with a reason about `seed` that misled. Held by
  `admin_actions_alone_make_an_admin_to_send_them_as`. The one call site in `docker.rs` runs only with Docker, so the
  test holds the function it calls.
- **5. `securevibe_bundle` requires `path`**, with a description of its own: the zip goes beside the app, so the
  server's own folder, everyone else's default, is always refused. Held in
  `the_bundle_tool_is_offered_and_the_report_points_to_it`.
- **6. `docs/REQUIREMENTS.md` counts a tool's rules by rule** (`TOOL_RULE_IDS` in `tools/coverage.py`), not by
  distinct description: V1.2.4 says 74 semgrep rules, where it said 1. And each phrase of what the rules look for is
  said once, where one rule's words joined two with "; " that another said alone. Held by
  `the_coverage_document_matches_the_checks`.
- **7. A data category `sv` does not know holds the app to level 2** (`DATA_CATEGORIES`,
  `Manifest::level_from_unknown_data`, ADR-024, Later). Names are read whatever their capitals and spaces, a name not on
  the list is named in `sv check`'s output and as a gap in the report, and the spec says so. Held by
  `a_data_category_not_on_the_list_is_not_a_quiet_no_either`, `the_spec_lists_every_data_category_sv_knows`, and,
  end to end, `a_misspelled_data_category_is_named_in_the_report`.

Eight guards were undone in turn, and each was caught.
