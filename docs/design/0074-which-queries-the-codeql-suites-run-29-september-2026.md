# Which queries the CodeQL suites run (29 September 2026)

Each CodeQL adapter runs one suite, `python-security-extended.qls` or `javascript-security-extended.qls`, and
`data/adapters.json` maps some of CodeQL's queries to requirements. Nothing recorded which queries those suites
select, as `data/semgrep-packs.json` does for semgrep's packs, so a query proposed for a requirement (two were, for
V15.4.2) could not be told from one that never runs, and a mapped query outside its suite would have counted in the
coverage document for nothing.

It was measured with CodeQL itself. The CodeQL 2.27.1 bundle was downloaded, with only the command-line tool and the
Python and JavaScript query packs unpacked, and `codeql resolve queries` listed the files each suite selects; each
file's `@id` is the rule id in the SARIF `sv` reads. The Python suite selects 52 queries and the JavaScript one 105.
Every query the map already counts is among them (32 and 49), so the coverage document was not overstated. Both
proposed queries run:

- `js/file-system-race` (CWE-367): a file's state checked separately before the file is used. That is V15.4.2's own
  example, so it counts the way the other mapped CodeQL queries do, a clean run crediting it for JavaScript.
- `py/insecure-temporary-file` (CWE-377): a temporary file name made with `mktemp`, which another process can take
  before the file is created. It is a race on the file's existence, but finding none says little about races in
  general, so it is found-failing-only for V15.4.2, exactly as bandit's B306 for the same call already was.

`data/codeql-suites.json` holds the two lists, with the date and CodeQL's version; `tools/codeql_suites.py` writes
it, reading the suites from the adapters' own arguments, and needs the bundle but no network. The test
`every_codeql_query_the_map_counts_is_in_the_suite_its_adapter_runs` fails when an adapter runs a suite not recorded
there, or maps a query its suite does not select. Broken both ways (a made-up query mapped, and the Python suite's
record removed), it went red each time with a message naming what was wrong.

**Not done here.** The suites change with CodeQL's releases; the record says which version it is true of, and needs
running again when the version `sv` expects changes. `tools/coverage.py` does not read the file, since the test
already holds the map to it.
