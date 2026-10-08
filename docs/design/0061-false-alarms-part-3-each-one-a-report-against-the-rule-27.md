# False alarms, part 3: each one a report against the rule (27 September 2026)

A false alarm a person sets aside in one app is usually a rule that will misfire in the next, so each
one should also reach the rule, where it can be narrowed with a test, rather than being set aside app
after app.

- **An issue form,** `.github/ISSUE_TEMPLATE/false_alarm.yml`: the rule, what the finding said, what
  kind of code it matched and why it is fine (both required, both in words), how often it happens, and
  which `sv`. The code is asked for last, optionally, behind a box the reporter ticks to say they chose
  to show it and checked it holds nothing private. The form says, first, never to paste a key, and, for
  the credential scan, to describe the shape of what matched rather than the value. It carries the
  existing `bug` label; a label of its own would be a repository setting, and is the owner's to add.
- **A link beside each false alarm** in `security.md` and `report.html`, and in the MCP check's summary,
  opening that form with the rule's id and the finding's title filled in, the two things about it that
  are `sv`'s own and already public. Never the file, the line, the code, or the owner's written reason:
  the link is built from nothing else, and a test holds it to that. One sentence under the list says why
  the links are there. An accepted risk gets none, being a real problem rather than a wrong rule.
- **The AI coding tool offers, and never files.** The MCP summary tells it to offer each link, that
  filing is the person's choice and public, and never to paste their code or a key into it.

GitHub fills a form's fields from the address only when the names match the fields' `id`s, and reads
`title` as the issue's own title, so the finding's title is sent as `finding`; a test reads the form
and fails if a name the link fills is not one of its fields. Tested with the link's contents and its
encoding, the form's fields, both pages, an accepted risk offered nothing, and end to end through `sv
report` and the MCP server. Eight breaks were made in turn, and each turned two or more tests red.
