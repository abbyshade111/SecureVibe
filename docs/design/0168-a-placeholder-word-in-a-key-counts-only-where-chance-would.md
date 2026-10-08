# A placeholder word in a key counts only where chance would not put it (5 October 2026)

A4 of the deep review: a value was taken for a placeholder, and not reported, when it held any of a list of words
(`example`, `changeme`, `todo`, `xxx`, …) anywhere in it. A real key's random characters spell the short ones by
chance: of 20,000 random JWTs made the way the test makes them, 66 were dropped as placeholders.

- **The short markers, `todo` and `xxx`, count only as words of their own** (`has_word`): not after a letter or
  digit, and not before a letter, so `TODO`, `xxx-xxx`, and `todo1` still count, and `…aXxXb…` inside a key does not.
- **The longer markers count anywhere, as before.** Five or more letters in a row are practically never spelled by
  chance, and the fused form is how real examples are written: AWS's own documentation key is
  `AKIAEXAMPLEEXAMPLE12`-shaped. Making every marker a whole word was tried first and lost exactly that.
- Of the same 20,000 random JWTs, none is now taken for a placeholder.

How it is held: `a_placeholder_word_counts_only_as_a_word_of_its_own` (`crates/sv-check/src/secrets.rs`), which counts
the random JWTs dropped and lists both kinds by hand, and `a_whole_example_env_file_is_silent`, which caught the first
attempt.
