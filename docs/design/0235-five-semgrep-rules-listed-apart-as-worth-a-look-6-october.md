# Five Semgrep rules listed apart as "worth a look" (6 October 2026)

Semgrep follow-up 5, decided by the owner on 6 October 2026 (ADR-023, Later). Five rules made 280 findings in the
false-alarm measurement of 4 October, and one was real: `unsafe-dynamic-method`, `prohibit-jquery-html`,
`detect-non-literal-regexp`, `plaintext-http-link`, and `var-in-href`. Mixed in with the rest, they buried the findings
that were usually right.

- **What moves:** a finding whose own rule is one of the five (`finding::WORTH_A_LOOK`, each in every language
  Semgrep's map has it in), when no other tool reported it too and every other problem on its line is one of the five
  as well. `Finding::worth_a_look` decides it from the finding as it stands, as `in_test_code` does from the path, so
  nothing is stored and every report agrees.
- **Where it goes:** after the app's own findings, with test code's and copied libraries' (`Finding::apart`), under a
  heading naming it ("only worth a look"), and in the summary line ("1 of them is only worth a look, listed after the
  app's own.").
- **What is kept:** the whole finding, a note beside it ("Worth a look: the rule that found it was wrong 279 times in
  280…"), its count against its requirements, and its place in SARIF, marked `worthALook`. The MCP server tells the AI
  coding tool to read one before changing anything.

How it is held: `only_a_usually_wrong_rule_alone_on_its_line_is_worth_a_look`, with another tool's report, a different
problem on the line, another Semgrep rule, and the bare rule name as its controls;
`the_rules_only_worth_a_look_were_wrong_279_times_in_280`, which checks the list against the measurement (279 false, 1
true) and against every rule of the five names the adapter maps; and
`a_finding_only_worth_a_look_is_listed_apart_in_full_and_still_counts`, through the Markdown, HTML, summary, and SARIF.
Eight guards were undone in turn, and each was caught.
