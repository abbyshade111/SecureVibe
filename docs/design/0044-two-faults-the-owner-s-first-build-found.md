# Two faults the owner's first build found

**`sv`'s own report was read as the app.** `sv report` writes into the app's folder by default, and
nothing skipped that folder, so the next check read `report.html` as code. While a page no code rule
could fully read was present, no code rule claimed anything, and the requirements checked fell from 9
to 1. Every folder the report is written to now carries `.securevibe-report`, and every walk of the
app leaves such a folder out; a folder name alone would not do, since `--out` takes any name. The two
lists of folders to skip, which had drifted, are one (`sv_scan::ecosystems::skip_dir`); the credential
scan keeps reading editor settings, since a token can sit there.

**Two false alarms rated high changed correct code.** With an AI tool in the loop a false alarm is not
noise: the tool rewrites working code until the warning stops. `RegExp.prototype.exec` was read as a
shell command and a test client's `.query({...})` as SQL, because both JavaScript rules matched any call
with the name. The shell rule now needs the call to be made on `child_process` or one of its usual
names (a bare `exec` still counts); the SQL rule only matches a call made on a name or a property, not
on another call's result. The price of the second is `getDb().query(sql)`, which is no longer found.

Six guards were broken in turn, each caught: the marker ignored, the default folder name dropped, the
credential scan skipping editor folders, the report left unmarked, the shell rule taking any receiver,
and the SQL rule taking a call's result.
