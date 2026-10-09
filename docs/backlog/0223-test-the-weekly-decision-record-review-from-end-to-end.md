# Test the weekly decision-record review from end to end

**Status:** open

Asked for by the owner on 9 October 2026, for after the roadmap: the weekly review of the decision records is a
routine with a stored prompt (updated 8 October 2026 for one file per backlog item, ADR-061), and it has not yet
been watched running from start to finish. Fire it once by hand, or wait for its next firing, and follow it: that it
reads every record in `docs/adr/`, compares each against the files it governs, finds a record that is owed a Later
entry or a correction when one is planted for it, writes the pull request it is meant to write, and says what it
found in plain words. Fix the prompt where it falls short, and record the result in a design entry. A review that
finds nothing on a clean tree is not a pass until it has been seen to find a planted gap.
