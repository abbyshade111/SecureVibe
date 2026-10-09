# CodeQL for Ruby, and why not Java (9 October 2026)


Backlog 0147, item 7; ADR-078, accepted for Ruby. The owner's decision of 9 October 2026: "let's go ahead with Ruby
and Java once confirmed it stays offline".

**What changed.**

- `data/adapters.json`: `codeql-ruby`, built like `codeql-python`: a database made from the source without a build,
  the bundle's `ruby-security-extended` suite, offline, `credit_loaded_only`. Its map holds 24 of the suite's 50
  queries: 21 cite what the same query cites for JavaScript or Python, and three are Ruby's own (`rb/kernel-open`,
  V1.2.5: input reaching `Kernel.open`, which runs a command when a name starts with a pipe; `rb/regexp-injection`,
  V1.2.9; `rb/insecure-mass-assignment`, V15.3.3). What the other two maps leave unmapped is left unmapped here, and
  so is `rb/csrf-protection-not-enabled`, which raised a false alarm on a controller whose Rails base class protects
  it by default.
- `data/codeql-suites.json`: the Ruby suite as measured with CodeQL 2.27.2. `tools/codeql_suites.py --only` measures
  one adapter's suite and keeps the others as recorded, since the bundle downloaded here carried only Ruby's and
  Java's query packs (the disk had 3.6 GB free).
- Coverage regenerated: the requirements Ruby reaches gain a tool each, and no level count moves.

**Tried before it was trusted** (ADR-032's way, and ADR-078's condition): with the network cut off (`unshare -n`),
Ruby's database and analysis gave the same nine results on a Rails controller as with the network; planted `Gemfile`,
`Rakefile`, `bin/bundle`, and `bin/setup` left no mark; `strace` showed only CodeQL's own programs started and no
connection but local ones; a linked file and a linked folder outside the app put nothing into the database.

**Java, tried the same way, and not added.** CodeQL's build-less mode ran Maven on the app's `pom.xml`, which reached
for Maven Central, and with a `gradlew` planted in the app it ran that too: the planted script left its mark. No
extractor option turns the fetching off, and hiding Maven did not stop CodeQL looking for the app's wrappers. ADR-078
says what was found.

**Tested.** `crates/sv-check/tests/codeql.rs`: a real Ruby report, from the Rails controller, read through the entry
(nine findings, each citing what its map says, the CSRF one citing nothing); the entry offered for Ruby and not for
Go, Java, or Kotlin; and, when CodeQL is installed, the real tool on an app with the planted files and a link (17
seconds here; skipped where CodeQL is not installed, as in CI). `crates/sv-check/tests/adapters.rs` now counts three
CodeQL entries, each query mapped in its suite. Broken in turn and caught: a Ruby query unmapped, a query mapped that
the suite does not run, the CSRF query mapped after all, the entry offered for Java, and the link replaced by a real
copy of the file outside (the real-tool test then found SQL injection in it, and failed).
