# A path the app stored, and a destination a function checked, say so (5 October 2026)

Items 2 and 3 of "Three false alarms on code that does the safe thing", left over from A1. Both rules already
report at low confidence, the lowest a finding has, so lowering it says nothing more; what was missing is the
reason. Each finding stays, and says why it may already be safe and what to look at.

- **A path made of the app's own stored values** (`ast.file-path-from-value`, `saysWhenReadFromDatabase`).
  `send_file(os.path.join(UPLOAD_DIR, row["id"]))`, where `row` came from `fetchone()`, is usually the id the app
  gave a file when it saved it. The finding says the path is built from fixed text and a value read back from the
  app's own database, and asks the owner to check nothing a person typed is ever stored there. A value read back
  is a name every binding of which is a database read (DB-API's `fetchone`, `fetchall`, and `fetchmany`;
  SQLAlchemy's `first`, `one`, and `scalar`; Flask-SQLAlchemy's `get_or_404`; Prisma's, Sequelize's, and
  Mongoose's `findUnique`, `findOne`, `findByPk`, and the like), a loop variable over one, or text built from those
  and fixed text. `get` is not one: `request.args.get("f")` is what the rule is for. A path with anything else in
  it, a name also set from the request elsewhere in the file, or a value from a dictionary's `get` keeps the plain
  finding.
- **A destination that passed through a checking function** (`ast.open-redirect`, `saysWhenChecked`).
  `redirect(safe_next(next_url))`, or a name only ever set from such a call, names the function: "passed through
  `safe_next` first, whose name says it checks it". A function counts when its name holds `safe`, `valid`,
  `allowed`, `check`, `clean`, `saniti`, `verif`, or `trusted`. No rule can read every such function, so the finding
  stays and asks the owner to read it. A name set from a checking function in one place and from the request in
  another keeps the plain finding; one set from two checking functions names both.
- Both read Python, JavaScript, and TypeScript, the languages whose bindings `Fixed` reads, and, like it, judge a
  name by every place in the file that sets it, not by which one reaches the call.

How it is held: `a_path_made_of_the_app_s_own_stored_values_says_so` and
`a_destination_that_passed_through_a_checking_function_names_it` (`crates/sv-check/src/ast.rs`), each with the
cases that say so and controls that must not. Fifteen guards were undone in turn. Thirteen were caught; two carried
no weight and were taken out: a second check that every binding of a checked name has a value, which the first
already made, and a check for a name with no bindings, which cannot happen.
