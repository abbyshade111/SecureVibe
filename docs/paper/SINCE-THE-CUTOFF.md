# Since the cut-off

The rest of this appendix stops at the cut-off, `main` at `157ddc3` (11:37 on 4 October 2026, Eastern time), and its
numbers are true there. This file records what changed in `sv` after it: first up to `main` at `4c3c5e0` (16:30 the
same day), as it was written that evening, and then, added on 8 October 2026, up to `main` at `01b10f60` (05:07 on 8
October). The other files keep their cut-off figures and point here; the trials of 5 to 8 October are in `TRIALS.md`. Nothing below was measured the way the cut-off's
analyses were; it is a record of what was built, from the merges, `docs/BACKLOG.md`, and `docs/DESIGN.md`.

## In numbers

| | at the cut-off, `157ddc3` | at `4c3c5e0` | at `01b10f60`, 8 October |
|---|---|---|---|
| Pull requests merged after the cut-off | | 41, numbered between #558 and #606 | 378 more after `4c3c5e0`, numbered between #602 and #990 |
| Tests (`#[test]` attributes in `crates/`) | 1,655 | 1,761 | 2,366 |
| Commands | 14 | 15 (`sv review` added) | 18 (`plan`, `preflight`, `brief`) |
| MCP tools | 10 | 10 (`sv review` is deliberately not one) | 13 (`securevibe_plan`, `securevibe_preflight`, `securevibe_before`) |
| Rules that read the code (tree-sitter) | 19 | 20 (a shell command run with `shell=True`, #587) | 27 |
| ASVS 5.0 requirements a check can settle, of 345 | 163 | 163 | 169, of which 119 can be credited |
| Deep-review findings done, of 58 | 1 (S1) | 14, and one in part | 58, six with a part deliberately left out |
| Decision records for `sv` | 11 (ADR-015 to ADR-025) | 11 (see the correction below) | 42 (ADR-015 to ADR-056) |

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

- **The health-tracking app built for a friend is anonymous in the paper** (#591, 14:52; and #606, 16:26, for the
  study figure's short label). Its first word was left in `figure-study.html` by the first pass, and an abbreviation
  of its name in `figure-top10.html`, replaced on 8 October 2026 (#978). It remains in the history of the files that
  held it.
- **Errors found at the cut-off were corrected in place**, each saying it was. A review of the appendix against `sv` at
  `12dbdaf8` found them, and the same change added this file.

## From `4c3c5e0` to 8 October 2026

Added on 8 October 2026, from the merges, `docs/BACKLOG.md`, `docs/DESIGN.md`, and the decision records; the numbers
in the table above were counted on `01b10f60` that day. As before, nothing here was measured the way the cut-off's
analyses were.

**A correction to this file.** As first written, the table gave 12 decision records at `4c3c5e0`. ADR-026 was written
by the change that added this file (`45bbf188`), merged a few minutes after `4c3c5e0`, so there were 11 there.

**The deep review is done.** All 58 findings are marked done in `docs/BACKLOG.md`, the last on 6 October (H9). Six
were done with a part deliberately left out, each with its reason: S7 (Brakeman is still given the whole folder), S9
(the app is not run as a separate user, ADR-019), H2 (Vue templates in another language), H3 (a passphrase with
spaces in JSON), H4 (the dispatch events), and R6 (the owner chose other exit codes, ADR-029). Two later reviews, of
the code merged 1 to 4 October and 5 to 6 October, found faults in some of those fixes, and every item of both is
done. `REVIEW.md` keeps the status as it stood at the cut-off.

**What a report says changed.** The order of the tiers `HOW-SV-WORKS.md` describes has two additions, both below
*checked*: *tested by the app's own tests* (ADR-050), for a passing test of the app's that names a requirement, and
*checked in part* (ADR-053), for a check that tried only part of what its requirement asks. There are nine statuses
in all. A seal is now a signature any computer can check against keys the owner chose to trust (ADR-043), replacing
`~/.config/securevibe/review-key` above. A threat is still moved only by a check that ran.

**What a run can reach changed.** With `install = true`, an app's packages are installed before the run, in a
container that sees only the dependency files and runs none of their code, so apps that use packages can be tested
at all (ADR-052). The signed-in checks gained, among others, another user's records listed, changed and deleted
(ADR-053), compressed uploads to the owner's limits (ADR-046), the sign-in token checks (ADR-039), a read-only SQL
injection probe on `sv`'s own copy of the app (ADR-038), and another site's Origin on the signed-in pages (ADR-055).
Notebooks and templates are read for what they can hold (ADR-054).

**Before any code.** `sv plan`, `sv brief` and `sv preflight` (ADR-030, ADR-035) say what to decide, what each feature
brings, and whether the run settings look right, and credit nothing. The coding prompts shown to work are given to
the AI coding tool at the start of every build (ADR-044); the trials that decided which are in `TRIALS.md`.

**How the project is run.** Every pull request must pass the tests before it merges into `main`, and every commit on
`main` is tested (ADR-051); a pull request that changes what a decision record governs must change the record or say
why not (`tools/adr_check.py`).

**What this means for the comparison study.** Beyond what is said above for `4c3c5e0`: the study's apps would now meet
the install step, the new statuses, and the larger set of checks, so re-running it on current `main` would answer a
different question. Its results reproduce on its own commit.
