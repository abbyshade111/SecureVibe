# The design questions, and the weakest tier there is

Sixteen requirements at level 1 and 2 ask for a property of how the app is built rather than a fact
in the code: is input validation enforced at a trusted service layer, are calls between the app's own
backend components authenticated, can a load balancer's header fields be faked by a browser. A
scanner sees a fragment of one at most. The owner knows the answer.

They answer in the `[design]` section of securevibe.toml, one of three words per requirement, with
`where` naming the file that does it:

```toml
[design]
"V8.3.1" = { answer = "yes", where = "server/auth.py" }
"V2.2.2" = { answer = "no" }
"V15.3.1" = { answer = "not-sure" }
```

### Why this ranks below the security notes

The notes credit requirements that ask for a *document*, and writing the document is the thing ASVS
asks for, so writing it partly satisfies the requirement. Nothing of the kind holds here. V8.3.1 asks
that authorization be enforced at a trusted service layer; an owner typing `yes` has enforced
nothing. The answer is worth recording — it is a decision, and `where` points somebody at the code —
but it is the owner's word about the app rather than the app.

So *attested by the owner* ranks below *documented by the owner*, and two consequences keep the tier
honest:

- **An attested requirement stays on the list of tests to write.** Every other non-checked tier does,
  and this one must, because an attestation is precisely the claim a test would settle. Letting the
  word retire the test is how *attested* would quietly become *checked* with nobody deciding to make
  it so. Breaking this fails `an_attested_requirement_is_still_a_test_to_write`.
- **An attestation settles no threat**, for the reason a document does not and more strongly: the
  threat model could otherwise be cleared by answering yes sixteen times.

### The two answers that are findings

This is what makes the section worth having rather than a way to feel better about a report:

- **`no`** is the owner saying the control is not there, which is the requirement failing on the best
  authority available. It is reported as *needs attention*, not as a silent nothing.
- **A `where` naming a file the app does not have** is a pointer that has gone stale — worse than no
  pointer, because it reads as evidence and leads nowhere. The attestation is withheld and the
  staleness reported. A rename is all it takes.

`not-sure` and silence come to the same thing, and a fourth word (`true`, `y`) is reported as
unreadable rather than folded into silence: a question the owner believes they answered, dropped
without a word, is the quiet failure this section could most easily have.

### What the guards caught

The same three as the security notes — the id exists, the question shares vocabulary with its
requirement, and it fits its own requirement better than any other — and the third earned its place
twice over:

- Four questions were written in such plain language that they shared two or three words with their
  requirement and fitted a neighbor as well. They are rewritten to use ASVS's own terms (*trusted
  service layer*, *backend service*) and explain them, which is better for the reader anyway, since
  the report prints the requirement's wording beside the question.
- **V13.2.2 was simply wrong.** It was written as "traffic between the app's own parts is encrypted";
  V13.2.2 is about the accounts used between those parts having the least privilege necessary. The
  question tied with V13.2.1 on vocabulary, which is what surfaced it. Nothing else in the suite
  would have: a wrong question is answerable, and the owner would have answered it and had the answer
  credited against a requirement about something else.

### The AI coding tool's answers, a tier lower still

The owner is not a programmer, and the tool that wrote the app knows its code better than they do.
So the questions go to the tool as well, and the plan (asked for by the owner on 26 September 2026)
is that the tool interviews the owner, one question at a time, with what it knows about the code as
a tip. That leaves two kinds of answer, and they are not worth the same:

- **The owner's answer**, given in that conversation, recorded with `by = "owner"`: *attested by the
  owner*, as before.
- **The tool's answer**, when the owner does not know and the tool answers from the code, recorded
  with `by = "ai-tool"`: *stated by the AI coding tool*, its own tier below the owner's, at the
  owner's decision the same day. It is the author grading its own work.

Everything that keeps *attested* honest holds for *stated*: it stays on the list of tests to write,
settles no threat, and a `no` is still a finding, now saying who said it. Where both answered, the
owner's word is the one shown.

**An answer that does not say who gave it counts as the tool's.** The file is usually written by the
tool, so crediting the owner on nobody's say-so is the direction that overstates; the owner writing
by hand adds `by = "owner"`. A `by` that is neither word is named as unreadable, like a fourth
answer, rather than guessed at.

Each guard was broken in turn and caught: silence read as the owner's, an unknown `by` read as the
owner's, *stated* dropped from the tests to write, *stated* shown as *attested*, and the two tiers'
order swapped.

### The interview: the tool asks, the owner answers

The three lists (design questions, security notes, checks by hand) reached the owner only as a
section of the report, and the walk-through of `sv mcp` on 26 September 2026 showed they did not
reach the AI coding tool at all: the check named the design questions by id alone and told the tool
to run `sv notes`, which it has no way to do. The owner's idea the same day was the fix: give the
questions to the tool, and have it interview the owner.

- **`securevibe_questions`** (and `sv questions`, to paste into a tool without MCP) lists what is
  still open for this app: design questions nobody has answered or only the tool has, security notes
  not yet written, and the checks by hand. Each has the question in plain words and where to look.
  The instructions ahead of them say how to ask: one at a time, with what the code shows as a tip,
  "not sure" as a good answer, and `by = "owner"` only for an answer the person gave. It is wider
  than the report's checklist, which leaves out what a test could also settle; a question the owner
  can answer is worth asking even when a test could settle it later.
- **A design question only the tool has answered is asked again**, to be confirmed or corrected,
  since the owner's word outranks the tool's. One the owner has answered is not asked again.
- **The security notes have no lower tier**, so the tool is told to write a decision only once the
  owner agrees with it. A written decision nobody made is not one.
- **`securevibe_notes_file`** makes or refreshes `security-notes.md`, keeping what is written, and
  refuses to write through a link out of the app, like `securevibe_write_report`'s folder.
- **The checks by hand record nothing yet.** The tool walks the owner through them.

Asking credits nothing: a test holds that every requirement on the list is still not verified. Two
smaller things from the walk-through went in beside it: the check now points the tool at the
questions, and a contradicted claim says what in the code contradicted it ("What the code shows:
`stripe` is declared in requirements.txt"), which `sv scope` always said and the report did not.

Six guards were broken in turn, each caught: an owner-answered question asked again, a tool-answered
one not asked, the "confirm this" line dropped, the `by = "owner"` rule dropped from the
instructions, the link check off, and the contradiction's evidence dropped.

### Checks made by hand, and what was seen

The interview walks the owner through twenty checks no tool can make: the certificate on the live
site, whether being away signs you out, whether two people can book the same slot. What they saw was
then lost. It is now recorded in securevibe.toml, in a design the owner agreed to on 26 September
2026:

```toml
[checked-by-hand]
"V12.2.2" = { result = "done", on = "2026-09-26", by = "owner",
              how = "Opened the live site; the padlock shows a trusted certificate." }
```

- **`done` by the owner is *checked by hand by the owner***, its own tier just above *attested*: the
  owner watched the app behave, which is more than describing how it is built, and it is still their
  word, which nothing here repeats. So it is never *checked*, stays a test to write where a test
  could show it, and settles no threat. An automated check or a finding outranks it.
- **`done` by the AI coding tool, or by nobody named, is *stated by the AI coding tool*.**
- **`problem` is a finding from anyone**, and `not-yet` adds nothing.
- **`how` is required**, because one sentence of what was done and seen is the whole of the evidence,
  and the report prints it. A bare `done` is unreadable and named as such.
- **`on` is required, and a check counts for 90 days.** Certificates expire and apps change, so an old
  check is reported as needing to be made again and counts for nothing; one dated in the future is
  unreadable. One number for all twenty, at the owner's choice.
- **Only the twenty are read.** Any other id is named as unreadable rather than ignored or credited.

A current check made by the owner is not asked again in the interview; an out-of-date one is.

Nine guards were broken in turn, each caught: a blank `how` counted, no expiry, a future date
accepted, silence read as the owner's, a problem not reported, the tier never shown, the tier dropped
from the tests to write, its rank swapped with *documented*, and the CLI not passing the checks on.

### Every requirement only a person can settle is explained somewhere

`manualOnly` lists the requirements no tool may ever settle, so for each of them a person is the
only way to an answer, and the checklist and the interview are the only places that tell them how.
Ten were in none of the three catalogs when this was found (26 September 2026), nine of them AISVS,
added as the framework grew. Twelve entries went into `human-checks.json` (the ten, and two AISVS
appendix C requirements at levels 1 and 2 that the finding had set aside as unleveled), each an
instruction for somebody who is not a programmer: look up the model's safety documentation, try the
well-known attacks yourself, check that a person who did not ask the AI for the code reviews it.

The guards so far all ran one way: every entry names a real requirement, fits it, and says what to
do. None ran the other way, so a requirement could be added to `manualOnly` and reach the reader as a
row with nothing beside it. `every_requirement_only_a_person_can_settle_is_explained_somewhere` is
that direction, at levels 1 and 2 like the checklist.

### Who wrote each section of the security notes (27 September 2026)

The owner's first run in VS Code showed the notes had the hole the design answers had closed a day
earlier. The AI coding tool wrote nine of thirteen sections from the code and, to its credit, marked
each with a line of its own: *Written by the AI coding tool from the code; review before relying on
it.* `sv` never saw it. The reader dropped every line wrapped in `*` as one of `sv`'s own italic
lines, so the disclaimer went and the section under it was reported as *documented by the owner*,
"you answered this", the highest tier short of *checked*. The same rule would have dropped the
owner's own `**Decided by the owner (2026-09-26):**` lines the next time `sv notes` rewrote the file.

Now each answer says who wrote it, on one line:

```markdown
Written by: owner
```

- **`owner`** is the owner's decision, or one the tool wrote that the owner read and agrees with. It is
  *documented by the owner*, as before.
- **`AI coding tool`** is what the tool wrote from the code and the owner has not agreed to. It is
  *stated by the AI coding tool*, the tier its design answers have, and the interview asks it again.
- **No line counts as the tool's**, at the owner's decision the same day, for the reason a design
  answer without `by` does: the file is usually the tool's writing, and crediting the owner on
  nobody's say-so is the direction that overstates. Every notes file written before this is
  unmarked, so its sections read as the tool's until somebody adds the line; the interview asks.
- **Anything else is unreadable**, a name or two lines that disagree, and named in the report rather
  than guessed at. Only this line is read: "Decided by the owner" in prose, or a disclaimer, is not.
- **Bold or italic around the line is ignored**, since tools and people both add it.
- **The line is who, not what.** It does not count toward the forty characters that make a section
  an answer.
- **The reader drops only the two italic lines `sv` writes** (the requirement's wording and "What
  `sv` found"), each matched exactly, so a person's or the tool's own emphasis survives a rewrite.

Eight guards were broken in turn and each was caught: an unmarked section read as the owner's (three
tests), every italic line dropped again (three), the line counted toward the answer's length (one,
after its first version passed with the break in: its sample was too short to reach the floor either
way), a name read as the owner (two), two lines that disagree resolved by the first (one), the tool's
sections left out of the report (one, the end-to-end test), the unreadable line not named (one), and
every answered section documented regardless of who (four). The end-to-end test,
`the_report_credits_only_what_the_owner_wrote_to_the_owner`, builds a report with one section of each
kind and reads the status the owner would see.

**A byline alone is not an answer** (added the same day by session securevibe-e9). The tool's own
line, *Written by the AI coding tool from the code; review before relying on it.*, has no colon, so it
is not a `Written by:` line, and at seventy-odd characters it passes the floor an answer must reach.
A section holding nothing else read as the tool's answer, *stated by the AI coding tool*, when
nothing had been answered. A line entirely in italics or bold that begins "Written by" now says who
and not what, as the `Written by:` line does, and is left out when the answer is measured; it is
still never read for who. A sentence of an answer that merely begins "Written by" is not in emphasis
from end to end, and stays the answer. Breaking the fix, the emphasis requirement, and the
underscore form of emphasis each turns two tests red, one of them through the binary with `sv notes`
and `sv report`.

### A person confirming what the AI coding tool said (27 September 2026)

Asked for by the owner after the VS Code run: when the owner does not know an answer, the tool answers
from the code and it is *stated by the AI coding tool*, and the owner had no honest way to record
that they then looked. Writing `by = "owner"` would say they gave the answer; they checked somebody
else's. So a confirmation sits beside the tool's answer (`sv_check::confirm`):

```toml
"V8.3.1" = { answer = "yes", where = "src/app.js", by = "ai-tool",
             confirmed = { by = "owner", on = "2026-09-27", answer = "yes", where = "src/app.js",
                           how = "Sent a POST to the site and got 405; only GET and HEAD work." } }
```

The owner's four decisions, the same day:

- **It ranks level with the owner's own record of the same kind**: a confirmed design answer with
  *attested by the owner*, a confirmed check made by hand with *checked by hand by the owner*. Once a
  person has looked and put their name to it, it is their word, and a sentence of what they saw is at
  least as good as a bare yes. **It is shown as confirmed**, never as theirs: "stated by the AI coding
  tool, confirmed by a person", then the tool's words, then the person's.
- **The owner or anyone named may confirm**, at the same rank, the name printed. `sv` cannot tell who
  anyone is, so a named reviewer does not outrank the owner.
- **Never *checked***: it stays on the tests to write and settles no threat, as the tiers it joins do.
- The nine tool-written notes sections of the owner's run were reviewed and agreed to. For the notes,
  agreeing is `Written by: owner` (above), because a written decision the owner adopts is theirs.

What keeps it honest. A confirmation failing any of these does not count, the tool's answer stays
*stated*, and the report names the confirmation and why:

- `how` is required, `on` is required and not in the future, and it lasts 90 days.
- It repeats the answer it confirms (`answer` and `where`, or `result`), so an answer changed later is
  not carried by a confirmation of the old one.
- The `where` file must not have changed after `on`, judged by its modification day. A fresh copy of
  the project looks new throughout and so asks again, which is the safe direction; a change made the
  same day as the confirmation is not seen, because `on` is a day.
- The AI coding tool cannot confirm its own answer.
- Disagreeing needs nothing new: the owner answers `no` themselves, or records a check as a `problem`.

It is applied after the answers are read, to the *stated* evidence only, and what it moves leaves
*stated*, so nothing counts twice and an owner's own answer is never touched. The interview tells the
tool to suggest something the person can see for themselves rather than ask a yes-or-no, and never
to write a confirmation the person did not make.

Fourteen guards were broken in turn and each was caught: a missing `how`, no expiry, a changed
answer, a changed `where`, a file changed afterwards, the tool confirming itself, a future date, a
changed `result`, a moved item left *stated* as well, confirmed design answers and confirmed checks
each left out of the report, a confirmation that does not count left unnamed, a confirmed answer
kept below the owner's rank, and a confirmation shown as the owner's own word. The end-to-end test,
`the_report_shows_each_confirmation_for_what_it_is`, reads the status of each kind in the report; the
two guards that mattered most and were first caught by one test only (the tool confirming itself,
and a missing `how`) were given a second witness there.

### Three things the owner's first build tripped on (27 September 2026)

Items 6, 7, and 8 of "What the owner's first build found", each a place where somebody who is not
technical was left to work something out.

**The command it told them to run did not exist.** The MCP server said "run `sv report --run --tools`
in a terminal", and `sv` had never been put on the terminal's search path: `command not found`. Now
the command names the program answering, by its full path (`std::env::current_exe`, canonical), and
quotes it when it holds a space, so it works as typed whether or not `sv` is on the path. In the
container the image sets `SV_IN_CONTAINER`, and the command is for `sv` installed on the computer
instead, since starting the app cannot work from inside it; the container's own path would mean
nothing outside. Guards broken and caught: the bare `sv` again (three tests, one of them driving the
server over stdio), the container's path given (one here, and `tools/image_smoke.py` in CI), a path
with a space left unquoted (one).

**Nothing said to put the app in git.** Whether a secrets file was ever committed is *not assessed*
outside git, honestly, and a beginner's app usually starts there. The message now says to put it in
git, and in which order: a `.gitignore` that leaves out `.env` before the first commit, or the first
commit saves the very file the check looks for. A repository git cannot read gets its own message,
not that advice, because it is in git already. The two were one message before; breaking them back
into one is caught.

**One question led a tool to count a web search as a vector database.** `rag` asked "does it search a
document store or vector database?", and the owner's app, which asks Claude to search vendor
websites, answered yes, bringing in the vector-database requirements (C8) for an app with no
database. Narrowing the question would have been wrong the other way: four of the seven requirements
`rag` switches on fit a web search too, C7.4.1 to C7.4.3 (answers cite what was retrieved, from the
retrieval itself) and C12.1.4 (each retrieval logged). So a separate answer, `web-search`, brings in
those four and not the rest. The trap in writing it: `rules_for` takes the most specific scope that
has rules, so a `web-search` rule at C7.4.1 alone would have hidden the `rag` rule written for all of
C7.4, and an app with a document store would have lost C7.4.1. Each of the three is written with both
conditions. Breaking that, dropping C12.1.4's rule, reading `web-search` as `rag`, and not reading the
answer at all are each caught.

### `planned`: decisions held to the code (5 October 2026)

A brief written before the code (ADR-028) could answer a design question only as `yes`, which claims code that does not
exist, or `not-sure`, which loses the decision. So a fourth answer, `planned`, with `where` naming the file the work
will be in. The owner chose it over reading `design-decisions.md`, which is a backlog item of its own.

`planned` credits nothing, whoever gives it, and is never evidence: a plan is not the app. What it is worth depends on
whether the app has code, which `sv` decides the way the technology answers already do: the scan read a source file or
a dependency manifest. Reading neither is an app not written yet.

| The app | `where` | What the report says |
|---|---|---|
| no code yet | anything | planned, not built yet (a gap: nothing to check) |
| has code | names a file that is not there | **decided, never built**: `design.planned-never-built`, low |
| has code | names a file that is there | planned, and the file is there now: change the answer to yes or no |
| has code | none | planned, with no file named: `sv` cannot tell whether it was built |

The finding is low, like the stale pointer it resembles, and of medium confidence rather than high: the file named is
certainly missing, but the work may have been built in another one, which the fix says. A planned file that is there
is not credited, because a file existing is not the decision held to; the owner or the tool looks and changes the
answer, and `yes` then goes through the tiers as before (ADR-022).

Tested at both ends: `sv-check`'s unit tests take each row of the table for the owner, the tool, and an answer that
names nobody, and `crates/sv-cli/tests/planned_decisions.rs` runs `sv report` on an app with no code, one with a
source file, and one with only a dependency list. Nine guards broken in turn, each caught: the code test forced true,
forced false, and blind to dependency lists; the no-code row removed; the finding not raised; the two
nothing-credited rows swapped; `planned` read as unreadable; the report's lines dropped; and the finding raised as
medium. The design-time prompts do not yet ask for `planned`: the third trial tested their present wording, and
changing it would leave the results describing words no longer there.


### `design-decisions.md`: two sections as written answers, and a review repeated (5 October 2026)

Four design-time prompts write their decisions into `design-decisions.md`, each under a heading of its own words, and
until now `sv` read none of it (backlog, design-time item 9). The owner chose, on a proposal, what each section is
worth:

| Section the prompt writes | What `sv` makes of it |
|---|---|
| "What we do if something goes wrong" | a written answer toward SBD-MT-06 (an incident plan, a critical control) |
| "Rules that might apply" | a written answer toward SBD-AC-06 (the regulatory controls identified) |
| "When to bring in a person" | repeated in the report where what was not examined is listed; credits nothing |
| "Safe defaults" | held to the code in a later change |

**Read as the notes are.** The two controls had no ASVS counterpart, so nothing could ever move them from *not
verified*. Their sections are now read by the security notes' own reader, with a second catalog,
`data/design-decisions.json`: an answer of forty characters or more makes the control *documented* when it is the
owner's and `sv review` sealed it, and *stated by the AI coding tool* otherwise, by the rules of ADR-022; never
*checked*. The catalog's sections name the heading they go by (`heading`), since the prompts write no id, matched as
the whole heading in any case with a trailing colon or full stop ignored; a section without one is found by its id, as
before, so the notes read exactly as they did. Each says what a written section cannot show (`notCovered`), and the
report says it beside the credit: that the plan was rehearsed, or that the design follows the rules. `sv review`
offers the owner's sections of both files, and seals each under its own heading (`with_seal_in`). SBD-MT-05 (records
kept current) is not credited: whether a decision was re-read before a change is not something a file shows.

**The review, repeated.** No tool can make a person's review, and the prompt asks the tool to say whether one is
needed. What the section says is repeated, cut at six hundred characters, as a row of "What was not examined", near the
top of the report. Its words are not read for a yes or a no.

**Held to what they stand on.** `crates/sv-check/tests/decisions.rs` holds each section of the catalog to a real
checklist control, to the one prompt that writes its heading into the file, and to that prompt naming the control; and
the reminder's heading to the prompt that writes it. The prompts' own notes in `design-prompts.json` and
`docs/prompts/design-time.md` say what `sv` now does with each section.

**Tested.** Twelve guards broken in turn, each caught: sections found by id only (five tests), headings compared as
written, the not-covered sentence left off either tier, either tier left out of the report, the reminder not given,
who wrote a section repeated in the reminder, a section running past the next heading, `sv review` reading only the
notes or placing the seal as in the notes, and a heading other than the prompt's. The two report tiers are caught
only by the end-to-end test, which is where they are joined.

**Later the same day: safe defaults, held to the running app.** The second part of the owner's choice. The
safe-defaults prompt now starts its section with three lines, `- debug mode: off`, `- cross-site access: own site
only`, and `- default accounts: none`, a value changed only where the owner decided otherwise. `sv` reads those three
(`decisions::safe_defaults`), each to one check of the running app that sees it:

| Line | Held to | Why that check and no other |
|---|---|---|
| debug mode | `probe.development-console-open` | a development console answers only with debug on; an error page with a stack trace can have other causes |
| cross-site access | `probe.cors-any-origin` | the app answering any site's request for its data is the opposite of "own site only" |
| default accounts | `probe.default-account` | a default name and password signing in is the opposite of "none" |

A switch decided the safe way whose check found otherwise is a finding of its own, *decided, not held to*
(`decisions.not-held-to`): low, at the check's confidence, citing the check's own requirements, on its line of the
decisions file, beside the check's finding, which stays the thing to fix. It is made after the findings a person set
aside are taken out, so a false alarm set aside is not held against a decision either. A switch decided the other way
(`on`, `any site`, `some`) is the owner's call and is not held against the code; a line with any other value is named
as unreadable, not guessed at; the rest of the section is for a person. Nothing is credited for a decision kept: the
check's own credit already says what it saw. All three checks need the app running, so without `--run` the report
says how many safe defaults were decided and not looked at, and `examined` gives the `decisions.` family as partly
run. `decisions.` joins `sv`'s own families, and its findings are never taken for a line of code.

Twelve guards broken in turn, each caught: the owner's other value held against the code, any finding counted against
any switch, debug mode held to the cross-site check, a switch read past its section, every line about a switch
counted, backticks kept, another value taken as the other, the "not looked at" and "unreadable" lines not given,
`examined` saying ran without the app, and the family taken for a line of code or for a tool's. A test holds the
prompt's three lines to the switches `sv` reads. **Not tested here:** the line that adds the finding to the report
runs only with the app running, and this environment has no Docker; the finding itself is tested directly.
