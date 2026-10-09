# The SQL rule reads Django and Laravel (9 October)

The third part of the gap analysis's finding 1, first half (7 October 2026), after knex and GORM, then TypeORM,
Sequelize, and Drizzle. Django and Laravel come off `ast.sql-built-by-hand`'s `unreadPackages` list.

**Django** (Python). `.raw(...)` and `cursor.execute(...)` were read already. Now:
- `.extra(...)`, whose text is given as keyword arguments (`where=[...]`, `select={...}`), is reported only when the
  text is visibly built in the call: `%`, `+`, `.format(`, or an f-string. `extra(where=["name = %s"],
  params=[name])` is not.
- `RawSQL(...)`. The Python query took only a call made through a dot (`cursor.execute`), and `RawSQL` is called by
  its name, so the query has a second pattern for a bare call. The same pattern reads a bare `read_sql(...)` imported
  from pandas, which the rule named and never reached.

**Laravel** (PHP). The PHP query took a plain function call and a method call (`$db->query`), and not a static one,
so `DB::select(...)` was never reached; it has a third pattern now. Read: `DB::select`, `insert`, `update`,
`delete`, `statement`, `unprepared`, and `raw`, and the builder's `whereRaw`, `orWhereRaw`, `havingRaw`,
`orHavingRaw`, `orderByRaw`, `groupByRaw`, `selectRaw`, and `fromRaw`. `select`, `insert`, `update`, and `delete`
are names every model has (`$user->update([...])`, `$user->delete()`), so they are reported only for text built with
`.`, with `"$var"` inside double quotes, or with `sprintf`.

Held by `crates/sv-check/src/ast/orm_django_laravel_tests.rs`: each call with a case that must be found and one that
must not, and the list without the two. Broken four ways (Python's bare-call pattern, Django's built-text test, PHP's
static-call pattern, Laravel's built-text test), each caught by the test written for it. `clean_coverage.rs`'s wording
of a clean Python result now lists `extra` and `RawSQL`. `orm_held_back.rs` checks a Python package written in another
case with `PyMongo`, which is still not read.

Left on the list: Mongoose and the MongoDB drivers, Supabase's clients, and PyMongo, whose unsafe forms are a `$where`
written into a query object and filter text, not a call the rule reads.
