# A package list sv cannot read, named beside the answer it changes (10 October 2026)


Backlog 0226, part 1, item 11. Built by session securevibe-e2.

**What was found first.** The item asked for a fixture before anything else, to see whether the wrong answer reaches a
report. It does. An app whose `package.json` names `memjs` and has a lockfile beside it is answered "uses memcache".
With one stray comma in `package.json`, the same app is answered "does not": requirement V1.3.9 is excluded as not
applying, and the claims table says the manifest and the code agree. Without a lockfile the answer was already "can't
tell", because npm then counts as unpinned, so the fault needs a pinned app to show.

**What was built.** Saying so, which the item says is not the owner's. `deps::unread_in` names every package list
found and not read: one that is not text, a `package.json` or `composer.json` that is not valid JSON (with the line
and column), and a `Pipfile` that is not valid TOML. The formats read line by line cannot fail to parse. The scan
carries the list (`ScanReport::unread_manifests`). The report's "What was not examined" names each file, says why, and
says that a technology known only by its package may be answered as not used. `sv scope` prints the same at a
terminal.

**What was not built.** Making such an answer "can't tell" instead of "not used". That changes what counts as
evidence, which is the owner's (backlog 0226, part 3, item H). The tests record the wrong answer as it stands, so a
decision there changes them on purpose.

**Tests.** `crates/sv-scan/tests/unread_manifests.rs` (2) and `crates/sv-cli/tests/unread_package_list.rs` (2,
through the real `sv`). **Broken on purpose, each put back:** the reader naming nothing turned 3 tests red, and the
report leaving the note out turned 1 red.
