# The model's reply written into the page as HTML (9 October 2026)

The test model's half of finding 13(b) of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7
October 2026"). The test model's replies never held HTML, so an app that writes its model's reply into the page as it
is went unasked unless stackvet.toml filled in the browser section. Anybody who can steer the model, by what they type
or what they saved for it to read, then chooses what runs in the reader's browser.

**The check.** `probe.ai-reply-html-unencoded` is only ever a finding, at high severity, citing V1.2.1 (output
encoding for HTML), as the reflected and stored checks do. It runs with the AI checks' later questions:

1. A message marked MARKUP has the test model reply with raw HTML: an image tag whose failure to load runs a line of
   script naming the message's tag (`ADR-042`, Later).
2. The app's answer is judged only when it is a page of HTML that carries the reply. A tag opened with a raw `<img` and
   holding the message's marker before it closes is the reply written in unencoded. An escaped `&lt;img` is text,
   whatever its quotes.

**What it does not claim.** A page that escaped the tag credits nothing: one reply on one page is not every place an app
writes one. An answer in JSON is not judged, since JSON carries a `<` as it is, rightly, and the page that draws it
decides, which the browser checks ask. An answer without the reply in it is not judged either. The steps say which.

**The fake AI app.** Its page answer now escapes `<` and `>` as a template would, keeping only the image its markdown
switch makes. A new switch escapes only `&` and `"`, which leaves a tag in the reply a tag.

**How it is held.** `crates/sv-check/src/ai/model_html_tests.rs`: found on a page that writes the reply as it is; said
and not credited on one that escapes it; not judged in JSON; and which tags count. The new switch is also in the table
of faults each found in a page answer too. `crates/sv-run/tests/model_provider.rs` holds the real test model to MARKUP.
Three guards broken in turn, each caught:
- JSON answers judged too: 6 tests failed, the JSON test among them.
- An escaped tag counted as raw: 3 tests failed, the escaped-page test among them.
- The test model's MARKUP case removed: the test model's own test failed.
