# SQL injection on the app's own reads (4 October 2026)

SQL injection is an app joining what a request sends into the text of a database query, so the sender can rewrite the
query. `ast.sql-built-by-hand` already looks for that in the code; `probe.sql-injection` (V1.2.4, CWE-89, critical)
asks the running app. The owner decided on 4 October 2026 to allow it with limits: only requests that read (GET), and
only on the copy of the app `sv` starts itself, with its throwaway data, so that an always-true condition can never
reach a request that changes data. The signed-in checks are only ever run by `sv run` and `sv report --run`, inside
the fence (`crates/sv-run/src/docker.rs`), never by `sv probe`, so the second limit holds by where the check lives.

How it is asked (`crates/sv-check/src/signed_in/sql.rs`), with A's session, after the flow checks:

- **Where.** The last part of the address of the record A made (`/notes/12`: the `12`), when `owned` gives one, and
  each value in the query string of each private page. A search page is asked by listing it among the private pages
  with a term, as `/search?q=test`.
- **What.** A condition added to the value, once always true and once always false: ` AND 1=1` and ` AND 1=2` for a
  number, `' AND '1'='1` and `' AND '1'='2` for quoted text, and `' OR '1'='1` and `' OR '1'='2` for quoted text as
  either-or, which makes a search that found nothing find everything. A record's last part is tried as a number and
  as quoted text; a query-string value as quoted text, as either-or, and as a number when it is one. Each version is
  percent-encoded and sent twice, in turn.
- **The finding.** Both copies of each version answered alike, the always-true one a success, and the two versions
  answered differently, by status or by length. Only a database reading the value as part of its query tells them
  apart. The two conditions of each pair are the same length, so an app that only repeats what it was sent (encoded
  or not) answers both alike; the text itself is not compared for the same reason.
- **Only ever a finding.** Nothing told apart is not credit: a few values in a few addresses is not every query the
  app builds. `tools/coverage.py` lists it in `RUST_FINDINGS_ONLY`.
- **What raises nothing.** A page that changes by itself between two asks, two refusals that differ (a 404 and a
  403), and an answer that crashed (5xx) or never came. The last is why the check needs no row in
  `RAISED_ON_A_REFUSAL`: a crash is never read as an answer here at all.

Not done: requests that change data (the owner's limit), JSON bodies and headers, conditions that work by timing or
by the database's error messages, and a difference that lies past the 4,000 characters of an answer the runner keeps.
Not tried against a real app; the fake app's search and record pages join their values under `sql_in_search` and
`sql_in_record`, with a number column that answers a stray quote with a syntax error and a text column
(`ids_are_text`) that reads only the quoted form, as a database does. That strictness is what makes dropping the
number form or the quoted form fail a test.

Twenty guards were broken in turn. Nineteen were caught at first; the one that was not, sending the condition without
percent-encoding it, went unnoticed because the fake app reads spaces and quotes in an address anyway, and the test of
a correct app now holds that every address the check sends is encoded.
