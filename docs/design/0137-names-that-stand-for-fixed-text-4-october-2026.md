# Names that stand for fixed text (4 October 2026)

A1 of the deep review: the SQL, redirect, and file-path rules read a name as something built, so a query held in
a constant was reported as a query joined from text. Seven of family-hub's eight SQL findings were that, and so
were the two that kept the prompt library's placeholders prompt from being shown to work (`executescript(SCHEMA)`,
and a query chosen from a dictionary of fixed queries).

**A name is fixed when the file settles it.** Before any rule runs on a file, `Fixed::of` lists every place the
file binds a name: assignments, `const` and `var`, Go's `:=`, `+=`, loop variables, and parameters. A name counts
as fixed text when it has exactly one binding and that binding is fixed text or other fixed names
(`SQL = BASE + " WHERE id = ?"`), or when it is an ALL_CAPS name bound once at the top of the module, whatever it
holds, since a module's constants are written before any request exists. A name bound twice, built with `+=`, used
as a loop variable, or taken as a parameter anywhere in the file is not trusted, because which binding reaches the
call cannot be told without following the code. A table is a name bound once to a dictionary or object whose
every value is fixed; `TABLE[key]` and `TABLE.get(key, <fixed>)` are fixed whatever the key, and a spread
(`**base`) makes it no table. The fixed-text judgment every rule already used (`is_literal`) consults this list, so
the shell and code-execution rules gain it too. It reads Python, JavaScript, TypeScript, and Go; other languages
get no fixed names, which only leaves their rules as they were. A name bound by a form the list does not count
(`with ... as sql`, an import) is the known gap: such a name is never fixed unless the file also binds it once.

**The argument that matters.** `argumentPositions` names, per language, calls whose judged argument is not the
first: Go's `QueryContext(ctx, query)` was judged on `ctx`, a name, and so reported every time.

**Values beside a query.** With `boundParametersLowerConfidence`, a query that is only a name the file does not
settle, handed over with values beside it, is still reported, at low confidence, and says that values beside a
query are how placeholders are used. Text built in the call itself (an f-string, a `+`) keeps the rule's
confidence, values or not.

**A path that stays on the site.** The redirect rule no longer reports a destination that opens with one slash and
then an ordinary path character (`f"/notes/{id}"`, `` `/users/${id}` ``, `"/notes/" + id`): nothing after it can
change the host. `"/" + next`, `` `/${next}` ``, `"//"`, and `"/\t/"` are still reported, since the next character
there is a value or a trick a browser reads as `//`.

Eleven guards broken in turn, each caught by its own witness or test; the table spread only by a second mutation,
since the first left the spread refused for another reason. Not done, and still in the backlog: a path read from
the app's own database, a redirect through the app's own checking function, and family-hub's redirect through a
parameter, which need a judgment about the app's own functions.
