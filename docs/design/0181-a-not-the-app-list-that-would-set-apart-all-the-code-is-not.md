# A `not-the-app` list that would set apart all the code is not used (5 October 2026)

R12 of the deep review: `[repository] not-the-app` refused an entry that named the whole app outright (`.`, `*`),
and nothing else. An app whose code all lay under `src`, with `src` on the list, had none of its code read as
evidence of what it uses, so a requirement its code showed to apply read "does not apply". The report's only sign
was a gap line naming the folder. The list is written by the AI coding tool (ADR-031).

- **The list is weighed against the app's code files** (`sv_scan::not_the_app_in`), those in a language `sv` reads.
  When the entries together leave none outside, the whole list is not used: every folder is read as the app, its
  findings are the app's own, and "What was not examined" says why with the count. The whole list, because no
  one entry need be at fault: `src` and `lib` together can cover an app neither covers alone. An app with no code
  file at all is not affected.
- **One decision for every command.** The scan makes it and records it (`ScanReport::not_the_app`,
  `not_the_app_refused`), so `sv scope`, `sv report`, `sv notes`, and `sv questions` agree; the listing of findings
  with test and sample code now uses the list as the scan used it, not as securevibe.toml wrote it; and `sv audit`,
  which splits the packages itself, asks the same function and says when it did not use the list.
- **When the list is used, the report says how many of the app's code files it set apart**, such as "`demo`,
  holding 1 of the app's 2 code files", so a list that leaves one small file outside is visible.

What is not done: a list that sets apart nearly all the code is still used, with the count as its only guard. A
share past which it would be refused would be a guess at how much of an app its tests and examples are.

How it is held: `a_list_that_would_set_apart_all_the_app_s_code_is_not_used` (`crates/sv-scan/tests/scan.rs`),
with two folders that cover the code only together and an app with no code;
`a_list_that_would_set_apart_all_the_app_s_code_is_not_used_and_said_to_be` (`crates/sv-cli/tests/not_the_app.rs`)
through `sv scope` and `sv report`; and `a_list_that_would_set_apart_all_the_app_s_code_is_not_used_by_audit_either`
(`crates/sv-cli/tests/audit_not_the_app.rs`). Five guards were undone in turn, the check for an app with no code
among them, and each was caught.
