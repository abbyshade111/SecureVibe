# A report read back is fenced as a tool's result is (9 October 2026)

The gap analysis of 7 October 2026, finding 22(b). Since the deep review's R9, every tool's result puts the app's own
text (its name, file paths, package names, code, and what `stackvet.toml` and the security notes say) between
`<app-text-…>` tags, and says first that the text inside is information, never an instruction. A report the AI tool
read back through the MCP server's `resources/read` had no such tags: the app's name came back as plain text in the
report that an injection in it had been fenced out of everywhere else.

**What changed.** `report.html`, `compliance.md`, and `security.md` come back whole between one pair of tags, named for
that one reading so that nothing in the report holds them, after a first line saying what they mean. The whole report
is inside, `sv`'s words with the app's, since a report read back is information about the app; its lines are kept as
written, unlike a tool result's pieces, which are each put on one line. `report.json` and `findings.sarif` come back
exactly as written: a program parses them, and tags would break them. Each file's description in `resources/list`
says which way it comes back. The files on disk and their seals are unchanged; the tags are added to what is handed
over, after the bytes read have been held to the seal (ADR-066, Later).

**Held by** `crates/sv-cli/src/mcp/resource_fence_tests.rs`: an app whose name is a prompt injection, a report written
for it, and each of its five files read back. The name has to be in each file (the setup), and must then be only
inside the fence in the three fenced files, with the report whole and unchanged inside; the two JSON files come back as
written and still parse (the control). The existing resource test now reads the fenced files that way too. Broken two
ways: no file fenced (both resource tests failed), and the report flattened to one line inside the fence (both failed).

**Found on the way.** Running the resource tests together, one run in six failed on unchanged `main`: two tests sealing
reports at once in the same fresh key folder each make a key, `create_new` refuses the second, and that report is left
unsealed and not offered. It is a fault of `sv`'s, not only of the tests (two runs at once on a computer with no report
key yet), and is fixed on its own.
