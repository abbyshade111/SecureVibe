# The SQL rule reads knex's and GORM's own calls (9 October)

The first part of the gap analysis's finding 1, first half (7 October 2026). Since #1163, `ast.sql-built-by-hand`
claims nothing for an app that uses an ORM whose own query calls it does not read, and names the ORM. This teaches
it two of them, and takes them off its `unreadPackages` list.

**knex** (JavaScript and TypeScript). The `...Raw` calls: `whereRaw`, `orWhereRaw`, `andWhereRaw`, `whereNotRaw`,
`orWhereNotRaw`, `havingRaw`, `orHavingRaw`, `orderByRaw`, `groupByRaw`, `joinRaw`, and `fromRaw` (`knex.raw` was
read already). A knex query is a chain on a call's result, `db('users').whereRaw(...)`, and the rule's query took a
call only on a name, a property, `this`, and the like. Accepting any call's result as the object was tried first and
reported a test's `request(app).get('/').query({ q })`, which an existing test caught. So the chained call is a
second pattern whose name is the whole chain, matched only when it ends in one of the `...Raw` names
(`\.(?:whereRaw|...)$` after the plain names). `names_only`, which lets a file that did not parse cleanly hold back
only the rules whose call it names, reads that form as the names it repeats, and the report's "the calls it reads"
leaves it out.

**GORM** (Go). `Raw`, like the other query calls; its clause methods, `Where`, `Or`, `Not`, `Order`, `Group`,
`Having`, `Joins`, and `Select`, only when the text is visibly built in the call (it starts with a string or
`fmt.Sprintf`, or joins a string with `+`), so `Where(&User{Name: name})` and `Where(map[string]interface{}{...})`
are not reported; and its inline conditions, `Find`, `First`, `Last`, `Take`, `FirstOrInit`, and `FirstOrCreate`,
judged by their second argument the same way, so `db.First(&u, id)` is not reported.

Held by `crates/sv-check/src/ast/orm_raw_tests.rs`: each call with a case that must be found and one that must not,
in both JavaScript and TypeScript for knex; the list without knex and GORM; and the chained form read as names.
Broken four ways (the chained pattern, GORM's built-text test, its second-argument position, and `names_only`'s
reading of the chained form), each caught by the test written for it. `clean_coverage.rs`'s wording of a clean Go
result now lists GORM's calls.
