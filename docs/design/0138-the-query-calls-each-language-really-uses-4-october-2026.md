# The query calls each language really uses (4 October 2026)

H1 of the deep review: `ast.sql-built-by-hand` named a short list of calls per language and judged only the first
argument, so nine real injections through the libraries people use gave no finding, while the report marked V1.2.4
checked. Each of the nine is now a test, beside the same call written safely.

- **More calls, per language.** JavaScript and TypeScript: better-sqlite3's and node-sqlite3's `prepare`, `exec`,
  `all`, `get`, `run`, and `each`, and Prisma's `$queryRawUnsafe` and `$executeRawUnsafe` (its tagged `$queryRaw` is
  safe, and is not a call this reads). Python: pandas' `read_sql` and `read_sql_query`. PHP: PDO's `prepare`, and
  `mysqli_query`, `mysqli_real_query`, `mysqli_multi_query`, `pg_query`, and `pg_send_query`, which take the
  connection first. Java: `prepareStatement`, `prepareCall`, and Spring's `JdbcTemplate` (`query`, `queryFor…`,
  `update`, `batchUpdate`). C#: `new SqlCommand(…)` and its siblings for SQLite, PostgreSQL, MySQL, Oracle, OLE DB, and
  ODBC, and Dapper's `Query…` and `Execute…`, including `Query<T>`. Ruby: Active Record's `where`, `order`, `having`,
  `group`, `joins`, `from`, `pluck`, and their kin, and `count_by_sql`.
- **The argument that matters, in every grammar.** `argumentPositions` now reaches past the wrapper PHP, C#, and Kotlin
  put round each argument, so `mysqli_query($conn, $sql)` is judged on `$sql`. Before, it found no second argument and
  skipped the call.
- **A common name is reported only for a query.** `get`, `all`, `run`, `exec`, `update`, `Query`, and `Execute` are
  also the names of a cache, a regular expression, a route, and a hundred other things. `argumentsForCommonNames`
  gives, per language, a pattern over such names and what their argument must look like before the call is reported:
  SQL (`SELECT … FROM`, `INSERT INTO`, `UPDATE … SET`, `DELETE FROM`, and the rest), or a name containing `sql`. For
  Active Record's methods it must be a string, since `where(name: n)` is the safe form. So `cache.get(key)`,
  `re.exec(s)`, and `app.get('/notes', …)` stay quiet. What it gives up: a query held in a name without `sql` in it, such as
  `q`, `query`, or `stmt`, and sent through one of those common names is not reported; `sql` or `userSql` still is.
  Every call whose name is specific to databases is read whatever it is given.
- **The clean claim says what it covered**: "a database query, sent through the usual database libraries' query
  calls, joined together…", not every way a program can reach a database.

How it is held: `the_usual_query_calls_of_each_language_are_read_and_their_safe_forms_are_not_reported`
(`crates/sv-check/src/ast.rs`). It has twenty-nine cases, and asserts that each one parses, so a pass is not a fixture
the grammar could not read.
