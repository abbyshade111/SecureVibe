# The SQL rule reads TypeORM, Sequelize, and Drizzle (9 October)

The second part of the gap analysis's finding 1, first half (7 October 2026), after knex and GORM. Three more
packages come off `ast.sql-built-by-hand`'s `unreadPackages` list.

**TypeORM.** `repo.query(...)` was read already. Its query builder is not a plain query call:
`createQueryBuilder('u').where(...)`, `andWhere`, `orWhere`, `having`, `andHaving`, `orHaving`, `orderBy`,
`addOrderBy`, `groupBy`, and `addGroupBy`. These names are common in JavaScript (an object of conditions, a
Mongoose `.where('age')`, a lodash `_.orderBy`), so each is reported only when the text is visibly built in the call:
a string joined with `+`, or a template with `${...}` in it. `where({ name })` and `where('u.name = :name', {...})`
are not. They are read on a plain call and on a chained one, as knex's are. `select` and `addSelect` are left out:
`d3.select('#' + id)` would be a false alarm on every page that draws a chart, and a test holds that.

**Sequelize.** `sequelize.query(...)` was read already; `Sequelize.literal(...)` is now, with the same built-text test.

**Drizzle.** Its one unsafe call, `sql.raw(...)`, was read already by the rule's `raw`. Its safe form, the
`` sql`...${x}` `` template, which sends `x` apart from the query, was a false alarm when passed to `db.execute`.
An argument that is an `sql` template (or `Prisma.sql`), or an `sql.raw(...)` call that is judged as a call of its
own, is no longer reported at the call it is passed to. The same template is the safe form in postgres.js, slonik, and
`@vercel/postgres`.

Held by `crates/sv-check/src/ast/orm_npm_tests.rs`, in JavaScript and TypeScript: each call with a case that must be
found and one that must not, d3's `select`, and the list without the three. Broken three ways (the built-text test,
the chained form, the safe template), each caught by the test written for it. `crates/sv-cli/tests/orm_held_back.rs`
now uses Supabase's client, which is still not read, as the package the rule cannot see into.
