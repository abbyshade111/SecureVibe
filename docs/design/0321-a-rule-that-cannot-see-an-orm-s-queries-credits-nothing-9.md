# A rule that cannot see an ORM's queries credits nothing (9 October)

The gap analysis of 7 October 2026 (finding 1) found V1.2.4, "queries keep values apart from the query", credited
for apps that build their queries through an ORM. `ast.sql-built-by-hand` reads the usual database libraries' query
calls in fifteen languages, and some ORMs' raw calls (Prisma's `$queryRawUnsafe`, Rails' `where` with built text,
Entity Framework's `FromSqlRaw`). It does not read knex's `whereRaw`, GORM's `Raw`, Django's `.extra`, and the like,
and a rule that finds nothing where it did not look was crediting the requirement anyway.

Confirmed before the change: a scratch app with knex in its `package.json`, no lockfile, and one route,
`db("users").whereRaw("name = '" + req.query.name + "'")`, had V1.2.4 *checked* by the rule in `compliance.md`.

## What changed

- **A rule names the packages it cannot see into.** `AstRule` has `unreadPackages`: per ecosystem, as the bill of
  materials names them (`npm`, `Python`, `Go`, `PHP`), the packages that build queries through calls of their own the
  rule does not read, each with those calls in a few words. `data/README.md` lists the field, and its schema test
  requires it there.
- **The credit is held back while the app uses one.** After the code is read, `ast::hold_back_for_packages` looks
  for each listed package among the names the app's lockfiles list (the bill of materials) and the names its
  manifests declare (the scan). Both, because an npm app with no lockfile lists nothing in its bill of materials and
  still uses knex. Names compare without regard to case, `-`, `_`, or `.` (Python's rule, and harmless elsewhere).
  The rule's clean result is dropped; its findings stay.
- **The report says why.** A gap, "ast.sql-built-by-hand, for code that goes through knex", with the package, its
  ecosystem, and the calls not read, in "What was not examined", and the same words on the rule's `examined` entry.
  The scratch app now reads V1.2.4 *not verified*, with that gap.

`ast.sql-built-by-hand` lists knex, TypeORM, Sequelize, Drizzle, Mongoose and the MongoDB driver, and Supabase's
client for npm; Django, PyMongo, and Supabase's client for Python; GORM and both MongoDB drivers for Go; and Laravel
for PHP: the ORMs the finding named whose raw calls the rule does not read. The finding's first half, teaching the
rule those calls, stays open; each package comes off the list in the change that teaches its calls.

## How it is held

`crates/sv-cli/tests/orm_held_back.rs`, through the binary, four apps: knex declared with no lockfile, knex only in
the lockfile (arriving through another package), `Django==5.0.6` in `requirements.txt` (a capital letter the list
does not have), and a control with `pg`'s `pool.query` and its values passed apart, which must stay credited. Broken
four ways, each caught by the test meant for it: the hold-back not called (the three hold-back tests failed, the
control passed); the manifests' names ignored (the no-lockfile test); the bill of materials ignored (the lockfile
test); names compared exactly as written (the Django test).

## What it costs

An app that uses one of these packages and passes every value apart no longer has V1.2.4 credited by this rule. That
is the honest reading, since nothing looked at those calls. The record is ADR-018, Later, 9 October 2026.
