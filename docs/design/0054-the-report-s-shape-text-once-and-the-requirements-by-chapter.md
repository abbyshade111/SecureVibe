# The report's shape: text once, and the requirements by chapter (28 September 2026)

Review item 9 said the reports were large for what they said, "because each of about six hundred
requirements carries its full text in every rendering, applicable or not", and left the reading
experience to the owner. The owner decided three things on 28 September 2026: in `report.json`, each
requirement's text once, in a table by id; in `compliance.md`, the requirements that apply grouped by
chapter, each chapter's count in bold, with how many in the same chapter do not apply beside it, and
the full text in an appendix; and a requirement that does not apply shown by its id and its reason,
without its text. The HTML page keeps the full text.

**Measured before the change, the premise was half right.** On the five-file Flask example the
requirements that apply were 108 KB of the 367 KB `report.json`, the ones that do not apply 62 KB, and
half of each was the requirement's own sentence. But only one list repeated another: the tests worth
writing carried again 153 sentences the list of requirements already had. The owner's questions and
the checks only a person can make carry their own plain-language instructions, not the standard's
words. And `compliance.md` already showed a requirement that does not apply by its id and reason
alone, so the third decision was true of it before this change and changes only the JSON.

**`report.json`** (`sv_report::json`). Every list whose rows carried a requirement's text (the
requirements that apply, the tests worth writing, the ones that do not apply, the ones nobody has
placed, the checklist controls above the target level, and Appendix C) keeps its rows and their ids
and loses the text, which goes once into `requirement_text`, keyed by id. Every id a list names is a
key there, and the table holds no id that no list names. A row whose text differs from the one
already filed under its id keeps its own: no two lists build their text differently today, and if
one ever does, the difference must survive rather than be replaced by the first list's words. The
file went from 367 KB to 334 KB on the example, 9%, of which the duplicated sentences were most.
The MCP server's answers are built separately and did not change.

**`compliance.md`** (`sv_report::chapters`). "Requirements that apply" opens on one table: each chapter
of the standards, in their own order (ASVS by number, then the Secure by Design checklist, then
AISVS by number, then Appendix C), with how many of its requirements apply in bold, and then how many
had a problem found, were checked, are the owner's word or the AI tool's word (each column drawn only
when some requirement has that status, and never added to *checked*), are not verified, do not apply,
and are not placed yet. Below it, each chapter where anything applies lists its requirements by id,
status, and level, with the level 1 ones first. The text of every requirement that applies is in
"Appendix: what each requirement asks for", at the end. Each column is counted from the same lists
as the report's headline counts, so it adds up to them. Appendix C is one row, named for the
appendix; the first version named it for whichever of its sections came first, which the table
showed at once. The Appendix C requirements nothing has reached (44 on the example) are still
counted apart, as everywhere else in the report, and the page says so under the table.

On the Flask example the table shows what the owner asked it to: of AISVS's chapters about AI
models, ten have nothing that applies and between 5 and 26 requirements each that do not, and
ASVS's WebRTC chapter has seven that do not apply and none that do. The part a person reads before
the appendix went from 63 KB to 14 KB. The file as a whole grew, from 160 KB to 169 KB: the text is
there once, as before, and the chapter headings and their small tables are new. Making the page
shorter to read and the file smaller were different aims, and the decision was about the first.
The level split the page used before (level 1, level 2, design review) remains on the HTML page.

**The checks only a person can make, named once** (the owner's decision the same day, after the
above). `only_you_can_check` in `report.json` was, entry for entry and word for word, a subset of
`questions_for_you`: 50 of 62 on the Flask example, 27 KB written twice. It is now
`only_you_can_check_ids`, the ids in the list's own order, each of which is a question in
`questions_for_you`. The name changed with the shape, so a tool that read full entries under the old
name finds no list rather than a list of a different kind. If an entry ever differs from the question
of the same id, or has no question, the full list is kept, as a differing requirement text is. The
file went from 334 KB to 306 KB on the example. Broken on purpose four ways: the step never called,
caught by two tests; the list dropped without its ids, three; the ids in the questions' order rather
than the list's, two unit tests (on the real catalogs the two orders happen to agree); and entries
converted without checking each is a question, one, the unit test written for it, since no real
report reaches that case.

**Broken on purpose, eleven ways**, each restored from the bytes read before it, never from git,
with cargo told to run every test file even after one fails. The first pass did not, and stopped
at the first failing file: the wrong-key break looked caught by one test, and is caught by three. Text not filed: four tests. Rows keeping their text: three. A differing text
replaced by the filed one: one, the unit test written for it, because no real report reaches that
case. What does not apply, what is not placed, or what was checked counted in the wrong column: two
each, after a second witness went into `report.rs`, a report small enough that every count in every
chapter is known; the first pass had one each, the end-to-end sum, which a swap between two chapters
would pass. The AI tool's word counted as the owner's: two, after the witness was given an answer
from the tool. Chapters merged by a wrong key: three. A chapter with one requirement left unlisted:
six. No appendix: two. Text left in the chapter lists: two.
