# C++ calls named through `std::` or `::`, a Location header streamed to `cout`, and C's SQL calls (6 October 2026)

The two gaps "Grammars for C++" named (BACKLOG), and a fault found on the way.

- **A scoped call is read as the plain one.** `std::system(cmd)`, `std::fopen(path)`, `std::filesystem::remove(path)`,
  and `::unlink(path)` parse as a `qualified_identifier`, which the C++ queries did not match. Nine rules now take the
  whole name as `@fn`, and each C++ name pattern allows `std::`, `std::filesystem::`, or the global `::` in front.
  A call on a class of the app's own (`Logger::system(msg)`, `Cache::remove(key)`) still is not read as the library
  call: its name is not one of those. `ast.token-key-source-from-token` already took any scope, since `cpr::Get` is
  the call it is for.
- **`std::cout << "Location: " << url`** is read as `printf("Location: %s", url)` is, by a second shape in
  `ast.open-redirect`: a chain whose left end is `cout` (with or without `std::`), whose text says `Location:`, and
  whose next part is not fixed text. `std::cerr`, another header, and a fixed address are not reported.
- **C's and C++'s SQL calls judged the connection, not the query.** `sqlite3_exec`, `mysql_query`,
  `mysql_real_query`, and `PQexec` take the connection first and the query second, and `ast.sql-built-by-hand`
  judged the first argument, so every such call was reported, a fixed query included. Found by the fixed-query
  control the C++ witnesses needed; the rule now judges the second argument (`argumentPositions`), in C as in C++.

How it is held: twenty-nine new witnesses in `the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one`
(`crates/sv-check/src/ast.rs`), each rule's scoped form with a control (a class of the app's own, a fixed argument,
another stream, another header), and C's SQL calls both ways. Twenty-four guards were undone in turn, each caught; a
check that the `cout` chain's operator is `<<` was taken out, since no code puts `cout` and a header's text either
side of anything else.
