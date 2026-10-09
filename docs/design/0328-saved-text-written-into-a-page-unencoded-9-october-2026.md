# Saved text written into a page unencoded (9 October 2026)

The stored record's half of finding 13(b) of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7
October 2026"). Until now, stored cross-site scripting was asked only in a real browser, and only when stackvet.toml
fills in `[stack.run.users.browser]`, which no trial manifest did. The record marker the other checks save is plain
letters and digits, so a page that writes saved text out as it is went unnoticed.

**The check.** `probe.stored-unencoded` is only ever a finding, at high severity. It cites V1.2.1, as the reflected
check does for text from the address. It runs with the other checks on the `owned` record, once the first user has read
their own record back:

1. The first user saves a second record whose text is `<"'` between the marks the reflection probes use. The runner
   keeps the text around those marks however long the page is.
2. The first user opens that record's own page, the `list` page, and every `private` page.
3. A page said to be HTML, with the `<` as it is between the marks, is named in the finding.

**What it does not claim.** A page that wrote the text escaped credits nothing: one record on a few pages is not every
place an app writes out what it was given. A JSON answer is not judged, because JSON carries a `<` as it is, rightly,
and the page that draws it decides. An answer that does not say it is HTML is not judged either. An app that refuses
the characters has not shown how it writes them out, and the steps say so.

**The scripted app.** Its note pages and its list of notes now escape what they show and say they are HTML. A new
switch writes the text as it is. The switch that let every other note through past the notes limit now moves only past
the limit: before, it moved with every note, so one more note made earlier in a run changed which note a burst saw let
through, which no real limit does.

**Left for later.** The other half of 13(b): the test model's reply carrying an `<img onerror>`, to ask whether the
app draws the model's text as HTML.

**How it is held.** `crates/sv-check/src/signed_in/stored_markup_tests.rs`: found on the record's page, and on the list
when it is named; not found when the pages escape it, with the step saying where it came back escaped; and which answers
are judged. The new switch is in the table of each flaw found by its own rule and in the run with many flaws at once.
Three guards broken in turn, each caught:
- An answer of any type judged: the test of which answers are judged failed.
- Any text between the marks read as raw: 34 tests of the correct app failed.
- The scripted app never escaping: 33 tests failed.
