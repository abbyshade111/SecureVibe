# Test the weekly decision-record review from end to end

**Status:** open

Asked for by the owner on 9 October 2026, for after the roadmap: the weekly review of the decision records is a
routine with a stored prompt (updated 8 October 2026 for one file per backlog item, ADR-061), and it has not yet
been watched running from start to finish. Fire it once by hand, or wait for its next firing, and follow it: that it
reads every record in `docs/adr/`, compares each against the files it governs, finds a record that is owed a Later
entry or a correction when one is planted for it, writes the pull request it is meant to write, and says what it
found in plain words. Fix the prompt where it falls short, and record the result in a design entry. A review that
finds nothing on a clean tree is not a pass until it has been seen to find a planted gap.

**Claimed 9 October 2026 by session securevibe-e9**, in branch `claude/stackvet-e9-adr-review-test`. The owner chose,
the same day, to follow the routine's next scheduled run (Monday 12 October 2026, 8:45 New York time) rather than
fire it by hand, so this week's review is not used up early and the routine's own scheduling is part of the test.
Before Monday, one gap is planted on `main` for the review to find: a record made to say something the code it
governs does not do, in a pull request of its own. Where it is and what it says are written here only after the run,
so that the review is not reading its own answer; the plant is then taken out whether or not the review finds it.
