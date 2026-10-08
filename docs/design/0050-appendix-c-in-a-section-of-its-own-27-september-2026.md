# Appendix C in a section of its own (27 September 2026)

Once the coding rules gave OWASP AISVS Appendix C a place at the start of the build, the owner asked
whether it should leave the report. Measured first: on `examples/flask-booking` Appendix C was 44 of
the 284 requirements that applied, and 33 of 163 for a bare manifest, every one *not verified*,
because no check in `sv` reaches any of them. None was on the list of tests to write, since a test
cannot show how an organization runs its AI tooling, and two were among the owner's questions. So
about a sixth of every report's "not verified" said nothing about the app.

Removing them was the wrong answer for three reasons: a report that stops mentioning Appendix C
reads as though it was covered, and the rules are not evidence; two of them are the owner's
decisions and belong with the questions; and some could be reached by a real check later (a static
reading of GitHub Actions workflows is recorded in the backlog). So they move rather than go:

- **Out of the headline numbers.** An Appendix C requirement that applies and that nothing has
  reached (no finding, no evidence of any tier) leaves the app's own list and its counts, and
  `counts.ai_process` holds how many. One with a finding, or any evidence, stays where it is and
  counts as any other requirement does, so a future check that finds something is never hidden in
  a side section. The split happens after the threats, the checklist, and the questions have read
  the full list, so the owner is still asked the two that are theirs.
- **Into one section,** "How the app is built with AI (OWASP AISVS Appendix C)", in `report.html`
  and `compliance.md`, with every one of them listed by what happens to it: *given to your AI coding
  tool as a rule* (it is cited by a coding rule given to this app, the same rules `sv rules` would
  write), *your decision* (it is among the questions, which outranks a rule, since the owner's answer
  is what would settle it), or *nothing in `sv` reaches it*. The paragraph above the list says the
  rules are instructions and following them is not evidence, and counts the Appendix C requirements
  that do not apply or wait on an unanswered question, which stay listed with the others of their
  kind. The headline says a further number are counted apart and where; so do the terminal summary
  and the MCP check's summary. `report.json` carries all of it as `ai_process`.

On the Flask example the headline goes from 284 to 240 requirements that apply, and the section
lists 44: 24 given to the tool as rules, 2 the owner's decisions, and 18 nothing reaches, most of
them pipeline and organization infrastructure. Tested in the report (what moves and what stays, the
counts, each route, a finding keeping one in place, the section and headline in both formats, no
section when there is nothing to put in it), through the binary on the Flask example (including a
problem the owner recorded by hand keeping one in the counts), and in the MCP check's summary. Eleven
breaks were made in turn, and each turned two or more tests red.
