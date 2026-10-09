# What an app's own tests cannot show, decided beside the classes it reads (9 October 2026)

The second part of item 12 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture
assessment of 8 October 2026: the four costs worth paying down"). The report lists the tests worth writing first, and
leaves out the requirements an application's own tests cannot show: a requirement classed as documentation or
deployment, Appendix C of AISVS (the development process), and one whose own words ask for documentation. A person
answers each of those. The rule was written inline in the CLI (`requirements_for_tests` in
`crates/sv-cli/src/assemble.rs`), reading the verification classes from `sv-frameworks` but deciding apart from them.

It is now `ApplicabilityConfig::not_for_tests` in `crates/sv-frameworks/src/applicability.rs`, beside
`verification_class_for`, and the CLI calls it. The rule itself did not change, so no report changes.

**Nothing tested it before.** With the rule made to hold for nothing, the whole workspace's tests passed. A report
would then have listed every documentation and deployment requirement as a test to write, and nothing would have
said so. `crates/sv-frameworks/tests/not_for_tests.rs` now reads the real data:

- One requirement for each reason, each one that only that reason covers, with the setup asserted: C3.1.1, classed
  as documentation, whose words do not ask for it; V4.2.1, classed as deployment; AC.1.2, whose class and words would
  not put it there; and V11.1.4 ("a documented plan"), classed as one an AI tool can help with.
- Every Appendix C requirement, whatever its class.
- A control: V6.2.1 and C1.1.1, which an app's tests can show, are not left out.

Each of the four reasons was dropped in turn, and the rule was made to hold for everything. Each break failed
exactly one of the five tests, the one written for it.
