# Since the cut-off

The rest of this appendix stops at the cut-off, `main` at `157ddc3` (11:37 on 4 October 2026, Eastern time), and its
numbers are true there. This file records what changed in `sv` after it, up to `main` at `4c3c5e0` (16:30 the same
day). The other files keep their cut-off figures and point here. Nothing below was measured the way the cut-off's
analyses were; it is a record of what was built, from the merges, `docs/BACKLOG.md`, and `docs/DESIGN.md`.

## In numbers

| | at the cut-off, `157ddc3` | at `4c3c5e0` |
|---|---|---|
| Pull requests merged after the cut-off | | 41, numbered between #558 and #606 |
| Tests (`#[test]` attributes in `crates/`) | 1,655 | 1,761 |
| Commands | 14 | 15 (`sv review` added) |
| MCP tools | 10 | 10 (`sv review` is deliberately not one) |
| Rules that read the code (tree-sitter) | 19 | 20 (a shell command run with `shell=True`, #587) |
| Deep-review findings fixed, of 58 | 1 (S1) | 14, and one in part |
| Decision records for `sv` | 11 (ADR-015 to ADR-025) | 12 (ADR-026 added) |

## The deep review

`REVIEW.md` lists 58 findings and what had been done by the cut-off: S1 fixed, and S2 to S5 and S12 being worked on.
By 16:30 these were fixed, each with tests, and each recorded as done in `docs/BACKLOG.md`:

| finding | what was wrong | fixed by | merged |
|---|---|---|---|
| S3, S4, S5 | `sv`'s own files written through a link, or over the app's own | #562 | 11:40 |
| S12 | a named pipe in the app read as a file | #566 | 11:56 |
| S2 | the network fence let the app reach the host through its gateway | #558 | 12:10 |
| R2 | "Nothing here found a problem" over findings set aside | #570 | 12:36 |
| S6 | outside tools' reports read from a fixed name, whatever the tool's exit | #574 | 13:01 |
| R1 | an AI coding tool could clear its own findings | #578, #588, #598 | 13:09 to 15:39 |
| H8, H10, H11 | advisories missed under Python names and nested npm copies; V15.2.1 credited from an incomplete list | #584 | 14:17 |
| H12, H13 | an HTTPS redirect and HSTS credited without holding | #595 | 15:16 |

**H4** is fixed in part (#572, 12:45): workflows started by `issue_comment` and `discussion_comment` are now treated as
privileged; `pull_request_review_comment` and `pull_request_review` are still open. **H3, H14, and H15** were claimed
and not yet done. The other 40 findings were open.

So of the 56 review findings `TESTS-AND-FAULTS.md` counts, 14 are fixed rather than 1. Six of the fail-open findings
it counts as open are now fixed (R1, H8, H10, H11, H12, H13). All six real findings of `sv`'s self-assessment on the
cut-off's source (`SELF-ASSESSMENT-V2.md`) are fixed: S3 and S4 by #562, S6 by #574, and S12 by #566.

## The owner's word now needs `sv review`

The largest change is to the evidence model `HOW-SV-WORKS.md` describes, and it is recorded as ADR-026. Until the
cut-off, an entry counted as the owner's when the file said so: `by = "owner"` in `securevibe.toml`, or
`Written by: owner` in `security-notes.md`. The review showed that an AI coding tool could write that line as easily
(R1). Now:

- **`sv review`** is a new command that runs only in a terminal a person is typing in. It shows each entry that does not
  count yet and asks for the person's name, or `owner`, and it seals what they record with a key kept outside the app's
  folder (`~/.config/securevibe/review-key`).
- **What needs the seal:** a finding set aside, a confirmation of the AI coding tool's answer, and the owner's own
  answers, so the tiers *documented by the owner*, *attested by the owner*, and *checked by hand by the owner*.
- **Without a seal that holds**, a finding set aside or a confirmation is a proposal and counts for nothing, and an
  owner's own answer counts as *stated by the AI coding tool*. A `no` or a `problem` is still a finding.
- **On a computer with no key**, such as CI, a sealed entry counts and the report says its seal could not be checked
  there.
- **The reports say what securevibe.toml says**, not that "a person" decided: the section is "Set aside in
  securevibe.toml", and confirmed answers read "confirmed through sv review".

The order of the tiers is unchanged. One more change to how they combine: a finding that says it leaves a requirement's
credit alone, such as a warning about a test's name, no longer outranks that credit (#581).

**What this means for the comparison study.** `STUDY.md`'s variant C was checked by `sv` at `45b6d71` and recorded 18
findings set aside and 26 answers at the owner's tiers. On `sv` at `4c3c5e0`, none of those entries is sealed, so the
findings would count again and the answers would be the AI coding tool's word until the owner recorded them through
`sv review`. The advisory comparison would also differ (H8, H10, H11). The study's results reproduce on its own
commit, not on current `main`.

## Other changes to `sv`

- **The fence** has no gateway address, and a throwaway container checks the gateway before the app starts (#558,
  recorded under ADR-019).
- **Files `sv` writes** go through one shared way of writing, never through a link and never over the app's own (#562).
- **Reports:** the headline counts findings set aside (#570); one run at a time writes to a report folder, and an older
  report never replaces a newer one (#589).
- **Checks:**
  - `sv probe` credits an HTTPS redirect and HSTS only when they hold (#595);
  - the signed-in checks ask for an authenticator code where an administrator must give one (#600);
  - the log checks no longer fail an app that keeps personal data out of its log (#601);
  - a credential name over a sentence is reported low (#597);
  - the starter example listens on all addresses, and a run names an app listening only on 127.0.0.1 as the likely
    cause (#586);
  - a fresh sign-in after the `--slow` wait (#580);
  - a rich-text editor with no lockfile, and a shell the call asked for (#587).
- **The prompt library:** design-time prompts are in `sv prompts`, with a second test app (#567, #603).

## In the appendix itself

- **The friend's health app is anonymous in the paper** (#591, 14:52; and #606, 16:26, for the study figure's short
  label). Its first word was left in `figure-study.html` by the first pass. It remains in the history of the files
  that held it.
- **Errors found at the cut-off were corrected in place**, each saying it was. A review of the appendix against `sv` at
  `12dbdaf8` found them, and the same change added this file.
