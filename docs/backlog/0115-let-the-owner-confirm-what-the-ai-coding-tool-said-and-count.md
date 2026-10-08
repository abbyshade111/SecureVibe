# Let the owner confirm what the AI coding tool said, and count it for more

**Status:** partly done: 1 of 7 parts done, 0 claimed, 6 open, as its markers read on 8 October 2026

Asked for by the owner on
27 September 2026, after trying the interview in VS Code: "give an option for a human to validate
information supplied by the AI system to strengthen the evidence on human review." **Claimed on 27
September 2026 by session securevibe-e8**, at the owner's asking, in two steps: first who wrote each
notes section (the finding below), then the confirmation itself.

**The owner's decisions, 27 September 2026** (on the four questions below, each as recommended):
1. The nine tool-written sections in the owner's run were reviewed and agreed to by the owner; once a
   marker exists, they are the owner's.
2. **A notes section that does not say who wrote it counts as the AI tool's**, as a design answer
   without `by` does. `sv` defines one marker line per section and reads nothing else (no guessing at
   "Decided by the owner"). Existing files are re-asked in the next interview.
3. **A confirmation ranks level with the owner's own record of the same kind** (attested, checked by
   hand, documented), shown as confirmed with the owner's `how`, and never *checked*.
4. **The owner or anyone named may confirm**, at the same rank, the name printed; `sv` cannot verify
   who anyone is, so a named reviewer does not rank higher.

**Today:** when the owner does not know an answer and the tool answers from the code, it is recorded
`by = "ai-tool"` and shown as *stated by the AI coding tool*, the lowest tier that counts for anything
(DESIGN.md, "The AI coding tool's answers, a tier lower still"). The same holds for a hand check the tool says it made. The owner's only way
up is to write `by = "owner"`, and that would say something untrue: the owner did not give the answer,
they checked someone else's. So a careful owner who looked has nowhere honest to record it.

**The idea:** a third kind of record, *stated by the AI coding tool, confirmed by the owner*, kept beside
the tool's answer rather than replacing it, so the report still says who said it first. A sketch:
`"V8.3.1" = { answer = "yes", where = "auth.py", by = "ai-tool", confirmed = { by = "owner", on =
"2026-09-27", how = "Signed in as Sam, changed the address to Kim's note, and got 'not allowed'." } }`.
The interview would offer it: the tool shows what it claimed and where, and suggests something the owner
can see for themselves (a page to open, a thing to try), not a yes-or-no.

**What keeps it honest** (each to be broken and watched, as for the other tiers):
- **`how` is required**, and it says what the owner saw, not "looks right". A bare confirmation is
  unreadable, as a bare `done` is for hand checks.
- **It is tied to the answer it confirmed.** If the tool changes its answer, or the file in `where`
  changes, the confirmation stops counting and the question is asked again: the owner confirmed that
  answer about that code, not whatever it says later.
- **It dates.** Probably the same 90 days as a hand check, so an old confirmation is asked again.
- **It is never *checked*.** It stays on the tests to write and settles no threat; an automated check or
  a finding outranks it. A confirmation cannot turn a finding into a pass.
- **The owner can also disagree.** "I tried it and it did not work" is a finding, as a `problem` hand
  check is.
- **Rubber-stamping is the risk.** An interview that asks "is this right?" gets "yes". The tool has to
  ask the owner to look at something, and the report prints the owner's `how`, so a reader can judge it.

**For the owner to decide before it is built:**
1. **Where it ranks.** Above *stated* for certain. Level with *attested by the owner*, or just below it
   (the owner checked a claim rather than knowing the answer), or just below *checked by hand by the
   owner* when the owner watched the app behave?
2. **Whether it covers hand checks as well as design answers**, and the written security notes.
3. **Whether "owner" is the only confirmer**, or a named reviewer (a colleague, a security person) can
   confirm too, with their name in the report. A second person is stronger evidence than the owner, and
   the manifest already has a `by` field to carry it.

**Step 1 done the same day** (DESIGN.md, "Who wrote each section of the security notes"): each notes
answer starts with `Written by: owner` or `Written by: AI coding tool`; no line counts as the tool's;
the tool's sections are *stated by the AI coding tool* and asked again; anything else is unreadable
and named; only `sv`'s own two italic lines are dropped. Eight guards broken, each caught. **Step 2
done the same day** (DESIGN.md, "A person confirming what the AI coding tool said"): `confirmed = {
by, on, how, answer, where }` beside a design answer, or `{ by, on, how, result }` beside a check made
by hand; it ranks with the owner's own record, shown as confirmed; it lapses after 90 days, when the
answer changes, or when the `where` file changes after `on`; the tool cannot confirm itself; one that
does not count is named. Fourteen guards broken, each caught. **Done.**

**Found the same day, from the owner's own files, and the first thing to fix:** the security notes
have no way to say who wrote a section, and `sv` credits every written section as *documented by the
owner* ("you answered this in security-notes.md"). In the owner's VS Code run, the tool wrote 9 of the
13 sections itself, from the code, and marked each with its own line, *Written by the AI coding tool
from the code; review before relying on it.* `sv` never sees that line: `notes::read_answers` drops
every line wrapped in `*` as one of its own italic lines, so the tool's disclaimer is thrown away and
the section under it reported as the owner's, the highest tier short of *checked*. Reproduced with a
copy of the owner's files: V8.1.1, written by the tool, reads *documented by the owner*. The same rule
drops a bold line such as `**Decided by the owner (2026-09-26):**`, since bold is also wrapped in `*`.
The interview tells the tool to write a decision only once the owner agrees; this tool wrote the
sections and said so, which is more honest than the report it fed. What to settle: a marker `sv`
defines and reads (the counterpart of `by` in `[design]`), which tier a tool-written section gets
(the natural answer is *stated by the AI coding tool*, as for design answers), what an unmarked
section counts as (the design answers chose the tool's, because crediting the owner on nobody's say-so
is the direction that overstates, but every notes file written so far is unmarked), and a narrower
test for `sv`'s own italic lines than "starts and ends with `*`". Confirming, above, then applies to
notes sections as it does to design answers. In the same run, `[design]` held nine answers, all
`by = "ai-tool"`, under the tool's comment "The owner has not reviewed these yet": the case this item
is for.

Related but separate: a second AI model checking the first one's claims. That is still the author's side
of the table, so it would be its own lower tier and is not this item.
