# The written reports, offered as resources (3 October 2026)

A report `sv` wrote was a set of files on disk that the AI tool had to be told to go and open. The MCP server now
offers them as resources, which a client lists and reads through the protocol itself (BACKLOG, "Improving the MCP
server", item 5): `resources/list` names each report below the folder the server was started for, and
`resources/read` gives back one of its files.

**What is offered, and what is not.** Only a folder that carries `sv`'s marker (`.securevibe-report`, a file and not
a link to one) counts as a report, and only the five files `sv` writes there are offered: `report.html`,
`compliance.md`, `security.md`, `findings.sarif`, and `report.json`. A test holds that list to the names the report
writer really writes. Nothing else of the person's can be listed or read this way, whatever URI is sent. The search
for reports does not follow links, goes at most six folders below the root, does not enter installed packages, build
output, or version control (the folders every walk of the app leaves out), and lists at most 100 reports. Searching
this whole repository takes 0.07 seconds.

**A read is checked again, not trusted.** A URI can be written by hand, so `resources/read` checks everything the list
did: the file is below the root once its folder's links are resolved, its folder carries the marker, its name is one
of the five, it is a file and not a link, and it is at most 16 MiB and is text. The file opened is then held to the one
looked at (the same file on the same disk), so a link put in its place in between is not read. Each refusal says why,
and none says what the file held.

**A report is old the moment it is written.** Each resource says that it describes the app as it was when written,
not necessarily as it is now, and the server's instructions tell the AI tool to check again before relying on one.
Folder names come from the app's folder, so they reach the tool on one line, as file names already do (DESIGN,
"Writing nothing through a link, and saying nothing on the app's behalf"). URIs are `file://` with every byte that is
not plain written as `%XX`, and a path that is not text is left out rather than offered under a name that means
something else.

**In each protocol version.** A client that opened with `initialize` is told the server has resources (with
`listChanged: false`), and a resource that is not there is answered with "resource not found" (-32002). The stateless
version (2026-07-28) retires -32002 and answers it with "invalid params" (-32602), and both results may be kept by
the one client only, and not at all (`ttlMs` 0), since a report can be written at any time.

Six tests: two reports, one under a name that must be escaped, listed and read back exactly as written; the offered
names against the writer's; URIs that name exactly the path they were made from, and strings that are not one;
ten reads refused (a folder not marked, another file in a marked one, a link to a file, a link to a folder outside, a
marker that is a link, a `..` path out, a file too large, one not text, one whose folder is a file, and one whose
folder is not there) with the refused file's text never in the answer; a folder named to break a line; where reports are and are
not looked for; and the stateless answers. Nineteen ways broken, each caught: the root, the marker, the name, a link
read, the size, text, a marker that is a link, folders left out, the depth (and one deeper), links followed in the
search and in the list, a name on two lines, a URI unescaped, a relative URI, the -32002 and -32602 codes each in the
other version, the stateless results kept an hour, and a resource that does not say when it is from.

**Not tested.** The check that the file opened is the one looked at: the race it guards against is not set up by any
test. Nor is the limit of 100 reports.

**Not done here.** A tool's result does not link to the report it wrote (`resource_link`), since the 2025-03-26 and
2024-11-05 versions have no such thing and the server does not keep which version a client chose. Nor does the server
tell the client when a report is written (`listChanged`, subscriptions).
