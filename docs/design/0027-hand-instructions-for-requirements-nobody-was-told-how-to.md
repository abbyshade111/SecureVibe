# Hand instructions for requirements nobody was told how to check (7 October 2026)

The gap analysis (`docs/GAP-ANALYSIS.md`, 6.4) listed requirements that no check settles and that no catalog told
anybody how to check by hand. `data/human-checks.json` now has a line for each, 26 in all, written for somebody who is
not a programmer: what to go and do, and what counts as the wrong answer.

- **ASVS:** V2.2.1 (input checked against what the app expects), V1.3.3, V1.3.5, V1.3.8, V6.5.2, V6.5.3, V8.4.1,
  V11.6.1, V13.3.2, and V16.3.4. An instruction that only applies to some apps says when it does not apply. V1.3.8 is
  for Java only, and V8.4.1 for an app that keeps separate organizations apart. Where `sv check` already finds part of
  the requirement (V6.5.3, V13.3.2), the line says so and covers the rest.
- **AISVS level 1, in C2, C7, C9, and C10:** input normalization, disguised instructions, input that is too long,
  allowed characters, content screening in English and in other languages, sources for answers built from
  documents, limits on the AI's tools, approval before high-impact actions, tools' least access, and the MCP
  server's sources, tokens, and transport.
- **Where they show.** Like every entry in the catalog, they reach the questions the AI coding tool asks the owner
  (`questions_for_you`, `sv mcp`). The report's own "only you can check" list keeps leaving out a requirement a test
  could also settle, as before: those stay on "Tests to write".
- **Held.** The catalog's tests check each new line. It must name a real requirement at level 1 or 2, share words
  with it, say what to do, avoid the jargon list, and not appear in another catalog. A new test,
  `the_requirements_the_gap_analysis_named_have_instructions`, fails if any of the 26 loses its line. Removing C9.2.1
  turned it red.
