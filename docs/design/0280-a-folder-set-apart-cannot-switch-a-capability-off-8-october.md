# A folder set apart cannot switch a capability off (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 4.3; BACKLOG, item 19; ADR-031, Later). `[repository] not-the-app` was
refused only when it set apart all of the app's code. Listing just the folder holding the AI client, or the one
example that parsed XML, turned those requirements to "does not apply". securevibe.toml is written by the AI coding
tool, so the list is not the owner's word.

- **A question, not a "no".** When the list is used, the technology scan looks a second time with it ignored. A
  condition the whole app shows and the rest of it does not is kept in `found_only_apart` with the file that showed
  it, and the scan answers nothing for it. A condition only the code answers is then undecided: an XML parser only in
  `demo/` leaves V1.5.1 waiting on "Does the app parse XML?" where it used to read "does not apply". An answer in
  securevibe.toml stands (`auth = false` with `flask-login` only in `demo/`), and the report says so beside the file.
  Each is a line under "What was not examined": "whether the app itself has `xml`".
- **The start file is the app.** An entry holding the file `[stack.run] start` runs is refused, said with the other
  refused entries: `` `demo`: it holds `demo/shop/app.py`, which the start command runs, so it is not used ``. The file
  is read from the command's words: a path, `python -m` and a module, or `module:object` for an ASGI or WSGI server.

Tests: `a_condition_found_only_in_a_folder_set_apart_is_named_and_not_a_no` (`crates/sv-scan/tests/scan.rs`),
`the_file_the_start_command_runs_is_read_and_its_folder_refused` (`crates/sv-manifest/src/lib.rs`), and
`what_only_a_folder_set_apart_shows_is_a_question_not_a_no` and `a_folder_holding_the_file_the_start_command_runs_is_refused`
(`crates/sv-cli/tests/not_the_app.rs`). Four guards broken in turn, each caught: the scan still answering "no", the
second look not taken, the start file not refused, and an entry naming the start file itself not counted as holding it.
