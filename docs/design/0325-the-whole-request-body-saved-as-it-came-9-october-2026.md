# The whole request body saved as it came (9 October 2026)

The last part of finding 11 of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7 October
2026"): plain `sv check` had no rule for a record created or updated from the whole request body, the flaw called
mass assignment. The running app's check asks it on sign-up only.

**The rule.** `ast.request-body-passed-whole` reports the whole request body handed to a create or update as it came.
It is only ever a finding, at high severity, citing V15.3.3. It reads:

- **JavaScript and TypeScript:** a model's `create`, `update`, `build`, `bulkCreate`, `upsert`, or `insert`, Mongoose's
  `findByIdAndUpdate`, `findOneAndUpdate`, `updateOne`, and `updateMany` (the body as their second argument), a model
  built with `new`, and Prisma's `data: req.body`, each given Express's or Koa's whole body (`req.body`,
  `ctx.request.body`).
- **Python:** a model built or saved from the whole of Flask's or Django's request data spread into it
  (`User(**request.json)`, `.objects.create(**request.data)`, `.update(**request.get_json())`).

**What it leaves alone.** The fields picked out (`{ name: req.body.name }`), the body checked by a schema first
(`schema.parse(req.body)`), and a spread of anything but the request. `Object.assign(user, req.body)` is not read: the
same call copies a body into an empty object as often as onto a record, and the rule would cry wolf.

**Its known limit.** In Python a schema class built from the body (`UserIn(**request.json)`) looks exactly like a model
built from it, and is reported too; a test pins it, so it is known rather than discovered.

**How it is held.** `crates/sv-check/src/ast/body_whole_tests.rs`, the reported forms and the safe ones side by side
for each language, and the rule only ever a finding. Four guards broken in turn, each caught: the body pattern removed
(the picked-out fields reported), Mongoose's second argument no longer read, the finding-only mark removed, and any
call read. `docs/COVERAGE.md` and `docs/REQUIREMENTS.md` list the rule under V15.3.3.
