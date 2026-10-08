# An error page is searched whole before it is cut (5 October 2026)

H17 of the deep review: `sv` keeps only the first 4,000 characters of each answer from the app, enough to recognize
a stack trace and not enough to copy a page out of somebody's app. The error-page check (V13.4.2, V16.5.1) read only
what was kept, so a page whose trace began below a long stretch of markup was credited as saying nothing it should
not.

- **The whole answer is searched first.** `kept_body` looks through all of it for each sign of a trace
  (`sv_check::probes::TRACE_MARKERS`, now public), and for the first of each found past the cut keeps the text
  around it, as it already did for the reflection probes' value. The check then reads it like any other.
- **What is kept stays small:** the start, plus at most one short stretch per kind of trace.

How it is held: `a_stack_trace_below_the_cut_is_kept_and_found` (`crates/sv-run/src/docker.rs`) puts every marker past
the cut, checks the setup really did, and runs the real check on what was kept; its control, a long page with no
trace, is still credited. Taking the new search out turned it red.
