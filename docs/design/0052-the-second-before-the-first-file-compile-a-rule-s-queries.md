# The second before the first file: compile a rule's queries when its language is met (27 September 2026)

Review item 6 said every command loads and compiles everything again, and named the frameworks (234 KB
of JSON), the adapters (371 KB), the rule files, and the tree-sitter queries. Measured before anything
was changed, that list was wrong in an instructive way: `sv init`, which loads nothing, took 3 ms;
`sv scope`, which loads the frameworks, the applicability rules, and the signatures, took 5 ms; `sv
check` on an app holding one empty manifest took 957 ms. Parsing JSON is not where a second goes. A
scratch program timed the loaders one at a time: the credential rules 0.5 ms, the adapters 0.7 ms, the
signatures 0.2 ms, the code rules 960 ms — and inside the code rules, the 248 regular expressions 25 ms
and the 143 tree-sitter queries 873 ms. Fifteen languages, compiled in full for every command: Swift's
ten queries alone 241 ms, Ruby's 113, C#'s 110, Python's 17. A Python app paid for all fifteen and
parsed with one.

**The change.** A rule's query is compiled the first time a file in its language is read, and kept for
the life of the process (`LazyQuery`, a `OnceLock` beside the query's source). Loading the rule file
still reads and checks every query's text — the text-predicate refusal, a pattern for a language the
rule has no query in, a `nothingToFind` beside a query — so the rule file's shape is still checked at
load; what waits is tree-sitter. `AstRules::compile_all` compiles every query in every language, and
the test `every_query_in_the_data_file_compiles` calls it, so a query written wrong still fails in CI
rather than on the first app in that language.

**A query that will not compile is a rule that did not run, and says so.** Before, such a rule was
refused at load and no command ran at all. Now the load succeeds, and the first file in that language
records a `BrokenQuery` (rule, language, tree-sitter's reason) on the scan, once however many files
met it. `sv check` prints it under the unread files; `sv report` adds a gap, "N code rules that could
not run", saying it is a fault in `sv`'s rule file and not in the app; and `clean_rules` refuses to
credit any rule while one stands, exactly as it does for an unread file. A rule that did not run must
not read as a rule that found nothing.

**The MCP server loads once.** `Loaded` (`sv-cli/src/main.rs`) holds the frameworks, the applicability
rules, the signatures, the threat rules, the credential rules, and the code rules; `assemble_report`
takes it, and `Server` builds it when it starts and hands the same one to every call. So the second
call about a Python app compiles no Python query: the first call did, in the rules the server keeps.
`securevibe_explain` reads the server's frameworks instead of loading them per call (that was 5 ms,
and is tidied rather than sped up). A command-line command runs once per process, so for the CLI
"load once" changes nothing and the gain is entirely the queries not compiled.

**Measured**, release builds, seven runs each, median, on this branch's own commit before and after:
`sv check` on an empty app 957 ms → 30 ms; `sv report` on an empty app 960 ms → 39 ms; `sv report` on
the five-file example 967 ms → 58 ms. Loading is now about 30 ms, most of it the regexes, and a
one-language app compiles that language's queries only: 17 ms for Python, 241 ms for Swift, and a
Swift app pays the 241 ms as before, once. On this repository, whose test fixtures hold files in most
of the fifteen languages, `sv check` went from 2.33 s to 1.93 s and `sv report` from 2.73 s to 2.35 s
(five runs, median, the before numbers from the one-walk measurement the same morning): most of the
queries still compile here, because most of the languages are here.

**Broken on purpose, three ways.** A broken query never recorded; the clean-result gate ignoring
broken queries; `compile_all` compiling nothing. On the first run the first two were each caught by
exactly one test, the unit test written with the change — the coverage this document calls
accidental. A second witness went into `clean_coverage.rs`, in the style of its neighbors: it first
asserts the sound rule claims a clean Python app on its own, then that beside a rule whose Python
query will not compile it claims nothing and the broken rule is named once for two files. Rerun, the
breaks are caught by two, two, and three tests.
