# Two MCP tools folded into others: the questions into the check, the notes file into the answers (9 October 2026)


Backlog 0187, part 10 (the architecture assessment of 8 October 2026); ADR-066, "Later, 9 October 2026". The owner's
decision of 9 October 2026: "yes to part 10's tool fold, as recommended", with the old names still answering, unlisted,
for a few weeks.

**The problem.** The server listed thirteen tools, and two of them were halves of others. `stackvet_questions` gave
the questions from the same report as `stackvet_check`, which already had a section named `questions` holding only a
pointer to the other tool. `stackvet_notes_file` made the file `stackvet_record_answer` writes into, and makes itself
when it is missing. Two more names for an AI coding tool to choose between, and two more for the guide to explain.

**What is done.**

1. **`stackvet_check`'s section `questions` holds the questions.** The interview's text (`sv_report::interview`) is
   split into one item per question, and before each group's heading, so a page never ends inside a question; each
   question's item carries it in the structured result's `questions` (`check_text::question_items`). Asked for by
   name, the section comes a page at a time like the others. The check's output shape gains `questions`, with the
   item shape `stackvet_questions` declared.
2. **The default answer does not grow by them.** Seventy questions in full are about 38,000 characters:
   `flask-booking`'s check is about 19,000 with them counted and about 57,000 with them in full. So a check asked for
   with no section comes whole with the questions in full only when that fits the budget; when it would come whole
   without them and not with them, it comes whole with the questions counted and the way to ask for them, as before
   (`Server::check`). Asked for as `all`, the whole check holds them, so the parts joined are still the whole, as
   the parts' own test requires. In a check that comes in parts, the questions are no longer among the first
   sections: in full they would push the findings off the first answer, so they come after them, while room lasts.
   `stackvet_write_report`'s summary keeps the count.
3. **`stackvet_record_answer` with no id and no answer makes the notes file.** It is what `stackvet_notes_file` did,
   word for word, refused links and all. With only one of the two it is refused, and nothing is written. Its
   structured result names the file always, and either what was recorded or what the file holds.
4. **The old names answer, unlisted.** `stackvet_questions` and `stackvet_notes_file` give what they gave, ending with
   one line outside the fence naming the tool to call instead (`protocol::folded`). Neither is in `tools/list`.
5. **What the AI coding tool and the person read follows.** The server's instructions, the check's pointer, the
   notes file's answer, the error for a question that does not apply, the guide's pasted prompt (step 5 now names
   `stackvet_check` with section `questions`, and `stackvet_record_answer`), the guide's tool counts, the README's
   list (with a note on the two old names), `ARCHITECTURE.md`, and the image smoke test.

**Tried.** `crates/sv-cli/src/mcp/fold_tests.rs`, three tests: the old names give what the new forms give, on every
page of the questions, and say so, and are not listed; a half answer is refused and writes nothing; and
`flask-booking`'s check comes whole with its questions counted while `all` holds every one. The tests that list the
tools, check every structured result against its declared shape, walk a long check page by page, and hold a short
check whole, moved to the new forms. Broken five ways, each caught: the old name's line left off (1 test), the notes
branch taken away (6), the questions never counted (4), always counted (3), and their structured items dropped (4).

**Not done.** No date is set for taking the old names away; that is a change to ADR-066 when it comes. The loop trials'
records in `docs/prompts/loop-*/loop-measures.json` name the old tools, as they were called then, and are left as
written.
