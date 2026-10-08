# Whose "bring in a person" text it is, and two lessons for the AI tool (8 October 2026)

Two findings of the gap analysis (`docs/GAP-ANALYSIS.md`, 4.2 and 4.4) about trust in the build loop.

- **Whose words the report repeats.** The "When to bring in a person" section of `design-decisions.md` is repeated
  where the report lists what was not examined. It came out as "Your design-decisions.md says …" whoever wrote it, so
  a section the AI coding tool wrote, saying no outside review is needed, read as the owner's own judgment. The
  report now says whose it is, from the section's own `Written by:` line (`decisions::section_writer`):
  - "in a section your AI coding tool wrote";
  - "in a section marked as written by you";
  - "in a section that does not say who wrote it, so it counts as your AI coding tool's", as ADR-022 counts any
    unsigned answer.

  The standing line "No tool can make it" stays first.
- **Two lessons from the owner's first build reach the AI coding tool.**
  - "Never rewrite working code just to make a finding go away" joins the rule against weakening a check
    (`never-weaken-a-check` in `data/coding-rules.json`), whose citations (AC.4.3, AC.8.3) are about exactly that
    bypass. If the finding is wrong, the tool says so and the owner records it as a false alarm with `sv review`.
  - "Name a requirement in a test only where the test proves it" now opens the feature brief's "Tests to write". The
    specification already said it.
- **Guards, each broken on purpose.** Each turned its test red and was put back:
  - the AI coding tool's section shown as the owner's (`the_decisions_files_own_words_are_inert_in_security_md`);
  - the first lesson dropped from the rule (`the_ai_tool_is_told_not_to_rewrite_working_code_to_silence_a_finding`);
  - the second dropped from the brief (`a_brief_has_its_five_parts_and_credits_nothing`).
