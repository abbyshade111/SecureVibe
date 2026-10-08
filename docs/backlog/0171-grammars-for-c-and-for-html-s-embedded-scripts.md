# Grammars for C++, and for HTML's embedded scripts

**Status:** done, as its markers read on 8 October 2026

C++ is the last language the scanner counts and
cannot parse. Assessed on 25 September 2026 against what AI coding tools actually produce: C++ matters
least of the candidates for web apps. Dart, Swift, and shell, which were worth more, are done (above). Since the claim became per rule, a grammar added without queries
no longer turns silence into a clean claim; it moves the silence from the whole app to the rules not
yet taught that language, and the report names them. **Claimed on 27 September 2026 by the v1 builder
("Vibe-coding builder"), at the owner's asking to keep working the backlog.**

**The C++ half is done the same day.** tree-sitter-cpp needed no new query shape: dumping the parse tree
for `fopen`, `system`, `MD5`, and a `printf`-style `Location:` header showed the same `call_expression`,
`argument_list`, `identifier` and `string_literal` nodes tree-sitter-c already produces, so all twelve
rules reuse C's query and function names outright — see DESIGN, "C++". What that does not reach is
written down rather than found by surprise later: a scoped call (`std::system(cmd)`, `::remove(path)`,
`Logger::log(msg)`) parses as a `qualified_identifier`, not the plain `identifier` these queries match,
and is not seen; neither is `std::cout << "Location: " << u`, a chain of `binary_expression` nodes and
never a call at all. Both are real C++ idioms and both are named gaps, not silent ones.
**Both gaps claimed on 6 October 2026 by session securevibe-e9**, at the owner's word ("pick your next backlog
item"), in branch `claude/securevibe-e9-cpp-scoped`: a call named through `std::`, `std::filesystem::`, or the
global `::` is read as the plain call, while a call on a class of the app's own (`Logger::log`) still is not; and
`std::cout << "Location: " << url` is read as the `printf` form is.
**Done the same day** (DESIGN, "C++ calls named through `std::` or `::`, a Location header streamed to `cout`, and
C's SQL calls"): nine rules read the scoped form, `ast.open-redirect` reads the `cout` chain, and, found on the way,
C's and C++'s SQL calls are judged by their query rather than their connection, which had reported every one.

The two "no grammar" tests this item said would break did, and now use Objective-C (`.m`/`.mm`,
recognized by the scanner and deliberately left without a grammar) in C++'s place, continuing the same
device through Ruby, C#, and C++ before it — so the property "an unread language silences every rule"
stays exercised rather than becoming untestable the day the list of examples is empty.

Verified: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and the full workspace test suite
(630 tests in `sv-check` alone) pass; `every_real_rule_is_taught_every_language_it_meets_here` now
includes a `.cpp` file. Broke four things on purpose and watched each fail the test that should catch
it: a rule missing its cpp query, a flipped witness, the grammar arm removed (23 tests fail, since
loading the rules fails), and the Objective-C extension mapping removed (the "nothing can parse
silences everything" test loses its fixture). `docs/COVERAGE.md` needed no regeneration: cpp adds no
ASVS requirement no other language already reaches for these twelve rules.

**HTML's embedded scripts** had been read since 25 September (DESIGN, "A page of markup is not a hole
in the coverage"). The part still named rather than read, which was unquoted values and disguised
schemes, was done on 27 September 2026 under its own entry, "Script in a page written the way a browser
reads it".
