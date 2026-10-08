# The tests' scratch folders, one per run and per call (5 October 2026)

The same fault in `sv`'s own tests. Twelve helpers made their scratch folder at a fixed name in the computer's
shared temporary folder (`sv-clean-<test>` and the like), emptying it first. Two `cargo test --workspace` runs at
once, from two sessions or a session and the owner, used the same folder, and one run's emptying deleted the
other's files in the middle of a test. On 5 October 2026 two `clean_coverage` tests failed so, their second scan
finding nothing, while another session's full run was going; with `TMPDIR` pointed at a folder of their own they
passed. A failure of that kind says something false about `sv`.

- **The name carries the process id and a count**: `sv-clean-<test>-<process id>-<n>`. No two processes running at
  once share an id, and the count keeps two calls with one name in one run apart.
- **The folder goes when the test lets go of it.** A fixed name was emptied by the next run; a name of the run's own
  never would be, so the helpers return a `Scratch` that removes its folder when dropped. One whose test panicked is
  kept, so the files it failed on can be looked at.
- One copy serves `sv-check`'s test files (`crates/sv-check/tests/scratch/mod.rs`); `sv-scan`'s single test file
  has its own. The unit-test helper in `sv-check/src/config.rs` already removed its folders, and gained the
  process id only. Helpers that already named their folder by process id were left as they were.

How it is held: `a_scratch_folder_is_this_calls_alone_and_goes_when_the_test_lets_go`, in `clean_coverage.rs` and
in `sv-scan`'s `scan.rs`. With the count taken out, the process id taken out, or the removal taken out, it failed
each time, on the assertion written for that guard.
