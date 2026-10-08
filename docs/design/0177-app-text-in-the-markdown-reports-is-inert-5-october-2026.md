# App text in the Markdown reports is inert (5 October 2026)

R13 of the deep review: security.md and compliance.md wrote the app's name, file paths, and what tools or the app
said as they were, so `[click](…)`, `![](…)`, or `<img …>` in any of them was live wherever the Markdown was shown,
and a backtick in a file name let the rest of it out of the code span it was put in. report.html already escaped
them.

- **`inert`** makes text from the app or a tool inert: outside code spans, `\`, `[`, `]` escaped and `<` written as
  `&lt;`, so no link, image, or HTML of its own; inside code spans, nothing, since a renderer reads nothing there as
  Markdown. Code spans are found as CommonMark finds them, a run of backticks closed by the next run of the same
  length, and a run with no partner is escaped, so it cannot pair with a later one. `sv`'s own backticks, such as
  `` `[[finding-review]]` ``, still read as code.
- **Where it is applied:** every table cell (`cell` now calls it), the app's name in both titles, and each finding's
  title, description, impact, fix, accepted-risk note, and notes. `sv`'s own `<details>` and its one link are
  written outside these, and unchanged.
- **`code`** shows a file path as code in a span opened with more backticks than any run inside it.
- **`sv`'s redaction marker** is escaped like everything else, `\[redacted: Qv7r… (16 more characters)\]`, and reads
  as `[redacted: …]` when shown. The credential scan's check for the marker (S8, which lets `sv bundle` read its own
  report back) now takes the escaped form too; without that, the bundle refused every report holding a redaction.

How it is held: `app_text_is_inert_outside_code_and_left_as_it_is_inside` and
`a_value_shown_as_code_cannot_close_its_span` (`crates/sv-report/src/markdown.rs`);
`text_from_the_app_cannot_put_a_link_an_image_or_html_into_the_markdown_reports` (`crates/sv-report/tests/report.rs`),
end to end with a file name and an app name built to escape; and `sv_s_own_redaction_marker_is_read_as_one_escaped_or_not`
(`crates/sv-check/src/secrets.rs`). The S8 test `a_password_a_tool_quotes_reaches_no_report_bundle_reply_or_screen`
now looks for the escaped marker in the Markdown. Four guards were undone in turn and each was caught.
