# The SQL rule reads MongoDB's $where (9 October 2026)


Finding 1 of the gap analysis of 7 October 2026, its first half (BACKLOG, "From the gap analysis of 7 October
2026"). Since ADR-018's Later entry of 9 October 2026, V1.2.4 is held back for an app that uses a package whose unsafe
queries `ast.sql-built-by-hand` cannot see. Mongoose, the MongoDB drivers for npm and Go, and PyMongo were on that
list, because their unsafe form is a `$where`: text in a query object that the database runs as JavaScript, not a
call the rule read.

**What changed.**

- The rule reads a `$where` key in a query object as it reads a query call:
  - JavaScript and TypeScript: `{ $where: … }`, `{ "$where": … }`, and Mongoose's `.find().$where(…)`.
  - Python: `{"$where": …}`.
  - Go: `bson.M{"$where": …}`, `bson.D{{"$where", …}}`, and `bson.D{{Key: "$where", Value: …}}`.
- It is reported when its value is text built from pieces, judged as JavaScript's `where` and Django's `.extra`
  already are in each language:
  - joined with `+`;
  - a template with `${…}`, or an f-string;
  - `%` or `.format(…)`;
  - `fmt.Sprintf(…)`.
- It is not reported for:
  - fixed text;
  - a function written in the code;
  - a name handed over, which is how the rule treats `where` in these languages.
- The five packages come off the rule's unread list, so an app using them is credited V1.2.4 again when nothing is
  found. Supabase's filter text stays on the list.
- A file that did not parse cleanly holds back only the rules whose call names it holds. Checking whether a chained
  name like `.$where` is among a rule's names now allows the escaped `$` it starts with.
- The clean result's list of "the calls it reads" ends with `$where` in each of the four languages. It is a key
  rather than a call, but it is what was read.

**What it does not read.**

- MongoDB's other operators that run text as code: `$function`, `$accumulator`, and `mapReduce`.
- A `$where` whose built text is first put in a variable. This holds for every `where`-like name in these languages.

Neither was on the list's reason. Both are named here so that nothing reads as more than it is.

**Tests.** `crates/sv-check/src/ast/orm_mongo_tests.rs` has a case to find and one to leave for each form. The
end-to-end test of a held-back package whose name is written in another case now uses Supabase
(`crates/sv-cli/tests/orm_held_back.rs`). Breaking the guard five ways turned a test red each time:

- dropping Python's query;
- dropping JavaScript's judgment of `.$where`;
- putting Mongoose back on the list;
- breaking Go's `Key:`/`Value:` form;
- undoing the `$` in chained names.
