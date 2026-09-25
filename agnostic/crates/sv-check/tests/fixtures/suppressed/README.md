# Suppressed findings

Real reports from four tools, each run over the small app beside it, in which some finding has been
marked to be ignored. `crates/sv-check/tests/suppressed.rs` checks that such a run is never credited
as clean, and that what the tool reports as suppressed is shown.

- `bandit-1.9.4-nosec.sarif`: `bandit --recursive --format sarif --quiet blanket.py targeted.py`
  inside `bandit-app/`. No results; `_totals` counts one `# nosec` line and one skipped test.
- `bandit-1.9.4-ignore-nosec.sarif`: the same with `--ini /dev/null --ignore-nosec`, as `sv` runs it.
  Both injections are reported.
- `gosec-2.29.0-tracked.sarif`: `gosec -fmt sarif -quiet -track-suppressions ./...` inside
  `gosec-app/`. Three results marked `inSource`, one not.
- `semgrep-1.178.0-nosemgrep.sarif`: `semgrep scan --config semgrep-rule.yml --sarif --metrics off
  app.py` over `semgrep-app/app.py`, copied out of this folder first: semgrep skips anything under a
  folder called `tests/` by default, so run here it reports nothing at all.
- `brakeman-8.0.6-ignored.sarif`: `brakeman --format sarif --no-progress --quiet --force .` inside
  `brakeman-app/`, whose `config/brakeman.ignore` lists the SQL injection. Both warnings are reported;
  the ignored one is marked `external` and names the ignore file.
