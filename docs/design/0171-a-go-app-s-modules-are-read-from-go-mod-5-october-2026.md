# A Go app's modules are read from go.mod (5 October 2026)

A3 of the deep review: the bill of materials took a Go app's modules from go.sum, which keeps a checksum for every
version Go has looked at, older ones included. Each was listed as if the app were built with it, and the advisory
comparison reported versions the app had moved past.

- **go.mod says what is built.** `from_go_mod` reads its `require` lines, one line or a block, and applies its
  `replace` lines: a module swapped for another at a version is listed as that one; a module swapped for a folder of
  the app's own has no published version, is not listed, and is named as not listed, as Python packages installed
  from a folder already are. A `replace` for a different version leaves the required one as it is.
- **Before Go 1.17, go.mod may leave out indirect modules.** For a go.mod with an older `go` line, or none, which
  Go reads as 1.16, a module named only in go.sum is listed at the highest version go.sum holds for it. That is the
  version Go chose whenever go.sum holds the one it chose. From 1.17 on, a module named only in go.sum is not
  listed: it is not in the build.
- **With no go.mod beside it**, go.sum is read as before.

How it is held: `go_mod_names_the_version_built_and_go_sum_s_older_ones_are_not_listed` and
`a_go_app_is_listed_from_go_mod_and_says_what_a_folder_replaced` (`crates/sv-check/src/sbom.rs`). Five guards were
undone in turn and each was caught, the last only after a module named in go.sum alone was added to the fixture.
