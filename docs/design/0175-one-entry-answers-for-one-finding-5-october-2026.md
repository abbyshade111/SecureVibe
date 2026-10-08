# One entry answers for one finding (5 October 2026)

R11 of the deep review: `[[finding-review]]` entries were applied one after another, each to the first finding it
matched, and an accepted risk leaves its finding on the list. So two entries for one finding were both applied, the
same answer counted twice, and a false alarm and an accepted risk for the same finding were both taken as said.
Recorded under ADR-023.

- **Each entry that counts takes one finding**: the first it matches that no earlier entry has taken. Two identical
  lines with an entry each are still both answered.
- **An entry left with nothing to take** repeats an earlier one or contradicts it. Repeating, it does not count,
  and says it adds nothing and can be removed. Contradicting, neither counts: the finding stands, and both are
  listed, until one is removed.
- **An entry that does not count takes nothing**, so it cannot keep a sealed entry after it from answering.

How it is held: `one_entry_answers_for_one_finding_and_a_pair_that_disagree_leaves_it_standing`
(`crates/sv-check/src/review.rs`), with a repeat, a contradiction in both orders, two identical lines, and an unsealed
entry before a sealed one. Three guards were undone in turn and each was caught.
