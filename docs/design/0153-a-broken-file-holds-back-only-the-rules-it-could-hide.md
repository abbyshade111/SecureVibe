# A broken file holds back only the rules it could hide something from (4 October 2026)

H25 of the deep review: one file the parser could not read in full silenced every code rule for the whole app.
Every rule reads JavaScript, so one vendored script with syntax the grammar does not know took every clean result
for the code out of the report. The rule that a partly read file cannot support a claim that something is absent
stays (`verified.rs`): what changes is which claims it touches. Recorded under ADR-018.

- **The question is whether the rule's call could be in the file.** A rule reports a call only when the call's name
  matches its pattern for that language (`functionPatterns`). So `hold_back` reads every word in a broken file
  (`names_in`: runs of letters, digits, `_`, and `$`, with Ruby's `?` or `!`, and each part of a run joined by `-`),
  and holds a rule back when any word matches. The word can be anywhere in the file, not only where the parser gave
  up: a call whose name was read and whose arguments were not is still a call the rule missed.
- **Only patterns made of words.** `names_only` accepts a pattern built from letters, digits, `_`, alternatives,
  groups, anchors, `?`, `!`, `*`, and `+`. Anything else can match text no word is, such as the shell's quoted
  `"/bin/sh"`, its `.`, `hashlib.pbkdf2_hmac`, or a character class, and holds its rule back whatever the file says.
- **Unchanged:** a file not opened holds back every rule that reads its language; a language with no parser, a page
  whose script did not parse (it is left behind, as before), and a query that would not compile, hold back every
  rule.
- **What a person sees:** the file is still named as partly read. The message says a rule whose call is named in it
  cannot say it found nothing, and a rule whose call is named nowhere in it could not have found it there.

How it is held: `a_file_that_does_not_parse_holds_back_the_rules_whose_call_it_names_and_keeps_its_findings`,
`a_broken_file_holds_back_a_rule_only_when_it_names_that_rules_call`,
`a_file_not_opened_holds_back_every_rule_that_reads_its_language`, and
`a_rule_whose_name_pattern_is_more_than_a_word_is_always_held_back` (`crates/sv-check/tests/clean_coverage.rs`),
and `the_words_in_a_file_rule_out_only_what_a_name_pattern_can_match` (`crates/sv-check/src/ast.rs`).
