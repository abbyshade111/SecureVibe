# An observability dashboard, once the observability review's findings are built

**Status:** open

Asked for by the owner on 9 October 2026, after the observability review (0226): "please add to the backlog an item
to work on an observability dashboard once this work is complete". **Not to be taken before 0226's findings are
built**: parts 1 and 2, and the owner's decisions A (ADR-082), C (ADR-083), and D (ADR-084). It reads the records
those make, and before them there is little to show.

A page, private to the owner and written to their own computer like the dashboard of ADR-057 (`sv dashboard`), that
shows what `sv` did and why, across runs and apps, from `sv`'s own records only. Among what it could show, to be
settled with the owner, with a mock-up first:

- **Each run:** when it ran, with which `sv` and which data, how long each part took, which outside tools ran and their
  versions, what could not run and why, and whether it finished, failed, or was stopped.
- **Each requirement over time:** its status run by run, and what moved it (a check, a finding, a note, a setting).
- **The running app:** for a run with the app, the probes' exchanges and the stand-in services' records (ADR-082),
  beside the credits and findings that rest on them.
- **The build loop:** the AI coding tool's calls, their outcomes, the prompts and report files it was given, and the
  findings fixed, set aside, and new between its checks (ADR-084).
- **`sv`'s own health:** crashes, data files that did not load, records it could not read.

Whether it extends `sv dashboard` or is a page of its own is part of the plan. It opens no network connection, keeps
everything on the owner's computer, and adds no record of its own beyond what ADR-057, 082, 083, and 084 decide; a page
that would need more is the owner's decision.
