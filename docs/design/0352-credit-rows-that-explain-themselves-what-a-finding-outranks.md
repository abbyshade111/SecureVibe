# Credit rows that explain themselves: what a finding outranks, a false alarm that withheld a credit, and whose word (10 October 2026)

Backlog 226 (the observability review), part 2, item 17, its report half, built by session stackvet-e9. Rendering
and JSON only: no status changes. `sv explain` follows in a pull request of its own.

**A row that needs attention.** It showed only its findings. The checks and tests that passed for the same
requirement were in `checked_by` and `tested_by` but on no page, and the rule that a finding outranks every credit
was only a comment above `status_of`. The row now says "these passed as well and do not count, since a finding
outranks every credit: …", on `compliance.md` and `report.html` alike (`RequirementLine::credit_note`).

**A false alarm that kept a check from counting.** A finding set aside as a false alarm turns a requirement it
names from *checked* into a bare *not verified* (`status_of`). The row now carries `withheld_by`, the rule ids of
the set-aside findings that did so, filled only when a check or a test passed and was kept from counting. The
pages say "config.something passed and does not count: ast.sql was set aside here as a false alarm, and a person's
word that a rule was wrong does not show the protection is in place".

**Whose word, in `report.json`.** A row resting on somebody's word now says whose in `whose_word`: the owner, the AI
coding tool, or somebody confirming the tool's answer through `sv review`. `attested_by` held the owner's yes and the
AI coding tool's alike. Each credit from a person's word now carries `whose`, from its tier and check id
(`credit_from_whom`, which follows `confirmed_only_by`). The status already names the tier. All fields are added and
none changes, so `report_format` stays 1.

**Tests.** Three in `crates/sv-report/tests/report.rs`: a row that needs attention names what passed and the rule,
on the page too; a set-aside false alarm names itself on the row it withheld and on no other, in `report.json` too;
and `whose_word` and `whose` for the owner's yes and the AI tool's. With the changes undone, all three fail.
