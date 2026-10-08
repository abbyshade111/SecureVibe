# What only you can check

On a real app, 98 of the applicable requirements can be settled by nobody but the owner. They sat in
the report as *not verified*, indistinguishable from the ones nothing had got around to, with no hint
of what doing something about them would even involve.

The section that fixes that is mostly a gathering job, because two of the three sources already
existed:

| source | what it covers | what the reader is told to do |
|---|---|---|
| `security-notes.json` | 19 requirements that ask for a written decision | write it in `security-notes.md` |
| `design-questions.json` | 16 that ask how the app is built | answer it in `[design]` |
| `human-checks.json` | the 20 ASVS requirements left over | go and look, and here is what at |

Measured before any of it was written, because two earlier estimates were wrong: 40 ASVS (7 at level
1, 33 at level 2), 21 Secure by Design, and 37 AISVS. The first estimate counted only ASVS levels and
said 7; the second counted `sv`'s inferred levels and said 37. Both were answers to questions nobody
had asked.

### The 58 are counted, not listed

The Secure by Design and AISVS controls get one sentence rather than 58 rows. Those standards are
checklists already, and reproducing them is the wall of text this whole piece of work exists to
remove. Counting them rather than dropping them is the part that matters: silently omitting them
would make a list of 40 look like the whole job when it covers 40 of 98.

### It credits nothing, and that needed a test that could see it

Every requirement here stays *not verified*. An instruction for how to check something is not the
check, and the section would be worse than useless if reading it moved a number.

The first version of that guard compared a report built with the catalogs against one built without,
and asserted the statuses matched. A mutation that credited every requirement on the list **passed
it** — the crediting happens in code that runs whether or not the catalogs were supplied, so both
sides moved together and the comparison stayed equal. Four unrelated tests caught the mutation and
the one written for it did not. It now asserts the property directly: every row on the list names a
requirement that reads *not verified* and carries no evidence of any kind.

That is the second time in this work a guard could only see a difference when the fault was a change
applied to everything, and it is worth remembering as a shape: a test that compares two outputs is
blind to anything that moves both.

### Where to look, beside what to answer

Every row on the checklist also says where to go and find the answer, not only what the answer should
be. The `human-checks.json` entries were instructions already; the rows that come from the security
notes and the design questions were not. "Write down the session inactivity timeout and the absolute
maximum session lifetime" is the right sentence for the notes file and no help at all to somebody who
does not know where those numbers are configured — so each of those carries a `howToFindOut` line,
and a guard refuses one without.

The owner asked for the level 2 ones. Writing them left the level 1 entries as the only rows with
nothing but a question, which is backwards, since level 1 is where somebody starts. So the rule is
every catalog entry that could reach the checklist.

And a third instance of the shape above: the guard that says the catalogs carry the line said nothing
about whether it reaches the reader. Dropping it on the way into the row was caught by nothing, and
so was never printing it. **A guard on the input is not a guard on the output**, and both ends now
have one.
