# Before going live: what only the live site can answer (6 October 2026)

The `sv probe` item's leftover (BACKLOG, "A production check"): "the rest of deployment becomes a 'before going live'
list in the report", never written. A report for an app on the internet showed V12.2.1, V12.2.2, V12.1.1, V3.4.1,
V3.3.3, and V4.1.2 as "not verified", with nothing saying that one command against the live site asks them.

- **For an app securevibe.toml says will be on the internet** (`deployment = "internet"`; `sv probe` asks only public
  addresses, so no other deployment can use it), `compliance.md` and `report.html` have a "Before going live" section
  after "What only you can check", and `report.json` carries it as `before_going_live`.
- **What it lists** (`sv_report::live::LIVE_SITE`): each requirement `sv probe`'s checks cite, with what it asks in plain
  words and the command (`sv probe https://your-address`, with `--api` for V4.1.2 and `--hsts-preload` for V3.7.4), and
  V12.1.2, which the owner decided on 6 October 2026 to leave to a scanner. Only those that apply at the app's level,
  and only while nothing has settled them: a check that ran here, or one the owner recorded by hand, takes a line off.
- **It credits nothing.** `sv probe` prints its answers where it runs and never adds them to a report; the section
  says so, and the requirements stay "not verified".

How it is held: `an_app_on_the_internet_is_told_what_only_its_live_site_can_answer` (`crates/sv-report/tests/report.rs`),
with a requirement not about the live site, one settled by a check, and an app not on the internet as its controls;
`every_requirement_sv_probe_answers_is_listed`, which reads `production.rs` and `live_tls.rs` and holds the list to
the requirements they cite; and `an_app_on_the_internet_has_a_before_going_live_list_and_one_kept_local_does_not`
(`crates/sv-cli/tests/before_going_live.rs`), through `sv report`. Eight guards were undone in turn, and each was
caught.
