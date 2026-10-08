# Smaller report points from the gap analysis (7 October 2026)

The gap analysis (`docs/GAP-ANALYSIS.md`, 6.3) found three small things.

- **"Passed" in the short version.** The next step about unanswered questions said the requirements they would
  place were "neither excluded nor passed today". It now says they "are in none of the numbers above until then".
- **The banned words were held to the headline alone.** `no_part_of_the_short_version_says_pass_or_secure` builds
  a report on which every sentence the short version can print is printed: the headline, the level and run lines,
  every counted row, and every next step with where to look. It holds them all to the list ("pass", "passed",
  "secure", "compliant", "safe", and their forms), matched as whole words so "password" is not caught. Putting the
  old wording back turned it red.
- **CI workflows written by the AI coding tool.** The default exit is 0 with findings (ADR-029), and only people's
  documents said so. The specification and the MCP server's instructions now tell the tool that a workflow step
  running `sv` must pass `--fail-on attention:high`. A test checks both texts name it, and that every value they
  name is one `sv` accepts. A misspelled value turned it red, and so did the flag taken out of the instructions.
