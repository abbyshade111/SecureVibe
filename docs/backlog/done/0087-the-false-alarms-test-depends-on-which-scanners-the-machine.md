# The false-alarms test depends on which scanners the machine has installed

**Status:** done, as its markers read on 8 October 2026

**Done the same day.** Found on 27 September 2026
by session securevibe-e8 running the full suite on the owner's Mac. **Claimed the same day by session
securevibe-e8**, at the owner's asking. `one_weakness_on_one_line_from_two_tools_is_listed_once_naming_both`
in `crates/sv-cli/tests/false_alarms.rs` runs `sv report --tools` with a stand-in `bandit` put in front of
the user's own PATH, so a real `semgrep` (or any other adapter's tool) on that PATH runs too. On the owner's
Mac it failed twice that way: once at the control, once finding the SQL line twice. CI has none of them
installed, so it passes there. Fix: shadow every other adapter's command with a stand-in that will not
start, read from `data/adapters.json`, and show in the report that each was kept out. **Done:** that is the fix; it
is the only test in `crates/sv-cli/tests/` that passes `--tools`. Broken on purpose on the owner's Mac,
with `semgrep` at `/opt/homebrew/bin`: without the shadowing, the new kept-out check fails, and without
both, the old failure (the SQL line found twice) comes back.
