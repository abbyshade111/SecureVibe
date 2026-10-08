# The plan and the check in parts an AI tool takes in whole (5 October 2026)

The loop pilot's builder could not read what `sv` gave it (BACKLOG, "`sv`'s plan is too big for an AI tool to take in
as one answer"). Its transcripts, kept outside the repository, show the two limits Claude Code 2.1.286 put on an MCP
tool's result, and the program the pilot ran says what they are:

- **Over 25,000 tokens, refused.** `securevibe_plan` for the club app: `Error: result (115,618 characters) exceeds
  maximum allowed tokens. Output has been saved to …`, with the model told only the file's name and the shape of its
  JSON. Three builds hit it (115,618 to 116,373 characters). 25,000 is `MAX_MCP_OUTPUT_TOKENS`'s default, the one
  limit of these Claude Code documents.
- **Over 50,000 characters, saved to a file** with a 2 KB preview: `securevibe_check` for Haiku 3, `Output too large
  (50.2KB)`, and a plan of 101.8 KB. A check of 38,146 bytes in the same trials was passed whole. The 50,000 is not in
  Claude Code's documentation; it was read from the program (an MCP tool's limit is the smaller of 100,000 and 50,000
  characters), and the transcripts agree with it.
- **What the model is given is the structured result**, not the text, when a tool sends both: the saved files are
  `structuredContent` as compact JSON, and the error names its schema. So the check's 50.2 KB was mostly
  `undecided` (39 KB), which its text never held.

**The budget.** `crate::parts::ANSWER_BUDGET` is 40,000 bytes, for the text and for the structured result as compact
JSON, each measured on its own: a fifth under the 50,000 characters, and about 10,000 to 13,000 tokens. No other
client's limit was found on record. A server can raise Claude Code's 50,000 for a tool through
`_meta["anthropic/maxResultSizeChars"]` (read in the same program); that was not used, because it is one vendor's
extension, the 25,000-token limit would still refuse the plan, and an answer that size is not one a model reads well
whole.

**What the tool answers** (`crates/sv-cli/src/parts.rs`):

- **Short: whole, as before.** With no `section`, an answer within the budget is the same text and the same
  structured result as before, so a small app sees no change.
- **Long: in parts.** The answer is cut into its sections (the plan's six: `summary`, `requirements`, `decide`,
  `tests`, `run`, `threats`; the check's eleven, its text's nine and the two lists only its structured result held,
  `claims` and `undecided`), each in pages of at most 15,000 bytes, cut at the end of a line. The first answer holds
  as many pages as fit in 30,000 bytes, in the order a builder acts on them: for a plan, its opening, what to decide,
  and what `sv run` needs, then the threats, the tests, and the requirements; for a check, the counts, what was not
  examined, the questions, the contradictions, what was set aside or not counted, and then the findings. It ends with
  a list of every section, its pages, which are shown, and the argument that asks for each.
- **`section` and `page`** ask for a page, and the answer holds the pages after it in that section while they fit.
  `"section": "all"` gives the whole answer, whatever its size, for a client that takes it.
- **The structured result is cut the same way, not sent whole.** Claude Code reads the structured result, so a whole
  one in every part would have kept every part over its limit. Each item of a list belongs to the line of text that
  shows it, so a page's structured result holds the items of its lines. A list a part holds none of is left out, never
  sent empty, so a missing list cannot be read as "none"; an empty list is sent where it would be. `part` says which
  pages an answer holds and lists every section. The fields every answer needs (the app, its level, the counts,
  `creditsNothing`) are in every part.
- **The app's text stays fenced in every part.** Each answer is made through `fence::fenced`, so its tags are named for
  that answer and appear nowhere in it, and it says first what they mean. Pages are measured with tags of the same
  length as any answer's, so a page is the same in every answer.
- **The whole is unchanged.** `plan::markdown_with` and the check's text are now the sections joined; before the old
  code was removed, both were compared to the byte with the old answers for the five examples, the club app's brief,
  and a club app with 121 findings.

**What it does to the examples.** The club app's plan: 99,962 bytes of text and 115,619 of structured result whole,
26,990 and 27,754 in the first answer. Its check with no code: 18,271 and 56,860 whole, 19,998 and 28,597 first. Every
example's plan is over the budget (64 KB to 127 KB) and now comes in parts; so do the checks of four of the five
examples, by their structured result (83 KB to 116 KB), all but `flask-booking`'s. A brief for an app with no sign-in
and nothing on the internet gives a plan of 21 KB, answered whole.

**Not done here.** An item longer than a page (one finding with a fix of 15,000 characters) has a page of its own and
can take that answer over the budget; nothing `sv` writes comes near it. The other tools were not cut: in the pilot
the longest were `securevibe_questions` (33 KB), `securevibe_before` (29 KB), and `securevibe_spec` (27 KB), all
under the budget. No build was run through a real AI tool with this server: the pilot's own setup would show whether
a builder reads the parts, and it spends the owner's API credit.

How it is held: `the_club_apps_plan_comes_in_parts_under_the_budget_with_what_to_decide_first` and
`a_long_check_comes_in_parts_under_the_budget_with_what_was_not_examined_first` ask for every page of every section of
the club app's plan and of a check with 20 files of weak hashes named with words aimed at the tool, each page on its
own and each section read through as a tool would; every answer is under the budget in both forms, has the shape the
tool declares, and keeps the app's text between its own tags; the pages joined are the whole answer's text, the lists
joined are its lists, and the first answer starts where it should. `a_short_plan_and_check_are_answered_whole_as_before`,
`a_section_or_page_that_is_not_there_is_refused_and_named`, and `the_sections_offered_are_the_sections_answered`
(`crates/sv-cli/src/mcp.rs`); `a_list_a_page_holds_none_of_is_left_out_and_an_empty_one_is_sent_empty`,
`an_item_larger_than_a_page_has_a_page_of_its_own`, and
`what_is_asked_for_is_read_and_a_section_that_is_not_there_refused` (`crates/sv-cli/src/parts.rs`).

Eleven guards were broken in turn, each caught: answering whole whatever the size (the two walks); a page cut that
drops the item at its edge (the two walks and both page unit tests); the parts made without the fence (the two walks
and `the_apps_text_is_fenced_in_every_tools_result`); the whole structured result in every part (the two walks and
the list unit test); pages of 45,000 bytes (the two walks and the list unit test); no page cut at all (four); a page's
opening lines left out (five); the plan's requirements put first (the plan's walk); what was not examined put after
the findings (the check's walk and `the_check_says_what_was_not_examined_before_what_was_found`). Sending a list a
page holds none of as empty, and never sending an empty list, were each caught only by the unit test written for
them, since no section of the club app's answers holds two lists across pages; that is why that test exists.
