# A page template built from a value (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.3; BACKLOG, item 11, one of its rules). A template is code: in Jinja
or ERB, text a visitor manages to put into one runs on the server. Plain `sv check` had no rule for a template made from
anything but fixed text; only the outside tools' rules (Semgrep's, Bandit's, Brakeman's) found it, and only when they
are installed.

`ast.template-built-from-value`, in `data/ast-rules.json`, finds a template made from text that is not fixed in the code
(an f-string, a joined string, a value passed in): `render_template_string` and `from_string` in Python; `ejs.render`,
`Handlebars.compile`, `pug.render`, lodash's `_.template`, and `nunjucks.renderString` in JavaScript and TypeScript;
`ERB.new` and `Liquid::Template.parse` in Ruby; Twig's `createTemplate` in PHP; and `Template.Parse` and
`Handlebars.Compile` in C#. High severity and medium confidence, citing V1.3.7, and only ever a finding. Fixed text, and
a name the same file sets once to fixed text, is not reported: the engine's `literalArgumentIsSafe` decides, as it does
for `eval`.

Not looked for: Python's bare `Template(...)`, which is also the standard library's harmless `string.Template`; Go's
`Parse`, which cannot be told from `url.Parse` by name; Java's engines, whose template text is the fourth argument or a
reader; and a template read from a file, which is how templates are meant to be kept.

Tests: twenty-three cases in the AST rules' table, each language's built template found and its fixed form left alone,
with `render_template(...)` from a file, `res.render(view)`, `User.new(params[:user])`, `int.Parse`, and
`DateTime.Parse` among the safe ones. Nine guards broken in turn, each caught: Python never matched, `from_string`
missed, fixed text counted, any JavaScript object's `render` counted, TypeScript never matched, any Ruby `new` counted,
Liquid missed, PHP never matched, and any C# `Parse` counted; the last went uncaught until the `DateTime.Parse` case
was added, since `int.Parse` never reached the pattern. The first runs of these breaks passed when they should have
failed: the tests were built in a second checkout sharing the first one's build folder, and ran the first checkout's
code. Run from one checkout, they fail as they should.
