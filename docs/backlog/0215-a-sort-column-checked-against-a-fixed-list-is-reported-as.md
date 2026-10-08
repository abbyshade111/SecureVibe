# A sort column checked against a fixed list is reported as SQL built by hand

**Status:** claimed by paper-facts, 8 October 2026

Found on 8 October 2026 by the Haiku 5.5 trial (`docs/prompts/library-trial/haiku55.md`): `ast.sql-built-by-hand`
(V1.2.4, high) fired in all ten Haiku 5.5 apps, and in the four read by hand each query was safe. The sort column is
taken from a fixed list of the app's own before it reaches `ORDER BY` (`SORT_COLUMNS.get(key, "created_at")`, or `if
sort not in SORTABLE_COLUMNS: abort(400)`), the direction is `"DESC" if ... else "ASC"`, the search words go in as
placeholders, and the `WHERE` clauses are a list of fixed pieces joined with `" AND "`. A false "needs attention" on
V1.2.4 in every app of the better model is the report saying something untrue.

Why the rule fires, read in `crates/sv-check/src/ast.rs` (`Fixed`): a name is fixed text only when the whole file
binds it once, and a Flask app reuses `sort`, `clauses`, and `direction` in several routes; a choice between fixed
words, a guard on a fixed list, and a list of fixed pieces joined are not read as fixed at all.

To build, for Python, the language of all ten apps; the other languages keep the rule as it is:

1. **A name judged in its own function:** a name the enclosing function binds once, and does not take as a parameter,
   is judged by that binding, whatever other functions do with the same name.
2. **A guard on a fixed list:** after `if name not in FIXED:` whose block always leaves (`return`, `raise`, or a call
   to `abort`), the name is fixed, where `FIXED` is fixed text: a list, tuple or set of fixed items, or a name for one.
3. **A choice between fixed values:** `a if c else b` with both values fixed.
4. **Fixed pieces joined:** `SEP.join(name)` where `SEP` is fixed and the function binds `name` once to a list of
   fixed items and only ever `append`s or `extend`s fixed items to it.

Each with witnesses both ways (the safe shape quiet, the same shape with a request value still reported), and each
guard broken on purpose and seen caught. The record: a "Later" entry on ADR-018 in the pull request that builds it.
