# SARIF addresses are addresses, and a rule is described in its own words (5 October 2026)

R14 of the deep review: `findings.sarif` wrote each finding's place straight into `artifactLocation.uri`, so a
finding about the running app had the URI `the running app` (not an address of anything), and a file in a folder
with a space, a `#`, or a letter outside ASCII had a URI that was not valid. Each rule's entry in
`tool.driver.rules` took its title, harm, and fix from whichever of its findings came first, so a probe rule was
described by one page it had asked about, and the same findings in another order gave another description.

- **A file** is a relative reference (RFC 3986, section 4.2) to the path from the app's folder, as before, with
  every byte but letters, digits, `-`, `.`, `_`, `~`, and `/` percent-encoded (UTF-8 for letters outside ASCII), so a
  `:` cannot read as a scheme and a `#` or `?` cannot end the path. A path that starts `//` gains `./`. No
  `uriBaseId`: `sv` never used one. CodeQL writes paths with spaces the same way, and GitHub decodes them.
- **The running app and its output** have no file. SARIF allows a result with no location, but GitHub code
  scanning marks `physicalLocation` required and shows no result without one, so such a finding points at
  `securevibe.toml`, line 1, the manifest whose `[run]` section says how the app was started (`sv report --run`
  needs it), and the location's own message says so: "Seen in the running app, which has no file or line of its
  own." The place is also a `logicalLocation` and the result's `properties.place`; the address the probe asked is
  in the result's message, as it was. `Location::RUNNING_APP`, `RUNNING_APP_OUTPUT`, and `Location::is_file`
  (`crates/sv-check/src/finding.rs`) name these places once; the probes build them with `Location::running_app()`.
  `sv probe`'s findings, which name a host, are only printed and never reach the SARIF.
- **A rule kept as data** (`data/ast-rules.json`, `data/secret-rules.json`, read from the folder the checks read
  them from) is described by its own title, description and harm, and fix. **Any other rule** (a probe, a tool's,
  a settings check) is described by what its findings all say alike: a tool's findings carry the tool's own rule
  text, and a probe's carry its rule's harm and fix. A field they disagree on, such as a probe's title naming the
  page, is taken from none of them and says that each result says it. Tags and requirements are every one the
  rule's findings name, sorted.
- `partialFingerprints["svFingerprint/v1"]` is unchanged, and so is every fingerprint: the places' text is the
  same.

How it is held, in `crates/sv-report/src/sarif.rs`: `a_file_path_is_written_as_a_relative_uri_that_decodes_back_to_it`
(spaces, accents, Japanese, `#?%[]`, a colon, `C:/`, `../`, `//`, each checked against RFC 3986's grammar and decoded
back to the path), `a_finding_about_the_running_app_gets_an_honest_place_github_will_take`,
`a_rule_is_described_the_same_whichever_of_its_findings_comes_first` (a probe rule, a data rule, and a tool's, in
both orders), and `a_secret_rule_is_described_from_its_own_data`. All four failed before the change. Six guards
were undone in turn, and each was caught: no encoding, no `./` before `//`, every place taken for a file, no
catalog, the first finding's text instead of the text all share, and the first finding's tags instead of all of
them.
