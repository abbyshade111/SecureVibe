# The secret rules find what they promise, and grade a test key below a live one (5 October 2026)

A5 of the deep review, three faults in `data/secret-rules.json`:

- **Slack's app-level token (`xapp-`)** was named in `secrets.slack-token`'s own description and not matched by
  its pattern. The pattern now takes `xapp-<digit>-…` beside the `xox?-` tokens.
- **A PGP private key block** (`-----BEGIN PGP PRIVATE KEY BLOCK-----`) was missed; `secrets.private-key-block`
  now finds it beside the PEM and OpenSSH ones. A public PGP block is not reported. The rule's description had lost
  its first sentence, and now says what it found.
- **A Stripe test key was graded critical**, the same as a live one. A test-mode key cannot create a charge or a
  refund; it opens the test-mode data, and is often a sign the live key is kept the same way. It now has a rule of
  its own, `secrets.stripe-test-key`, at medium, and `secrets.stripe-key` is for live keys only. No decision record
  governs the secret rules, so the grading is recorded here. A finding on a test key that someone set aside under the
  old rule's name no longer matches, and is looked at again under the new one.

How it is held: `the_rule_data_finds_what_it_promises_and_grades_a_test_key_below_a_live_one`
(`crates/sv-check/src/secrets.rs`), with every value put together at run time. Each of the three changes was undone in
turn and the test went red.
