# A zip of the whole result, for the owner to keep or hand on

**Status:** claimed by a session not named, as its markers read on 8 October 2026

Asked for by the owner on
26 September 2026: the application, its scans and its report in one download, at the end of a build
or on request. **Claimed on 27 September 2026 by the v1 builder ("Vibe-coding builder"), when the owner asked
that an item be picked; the owner is watching it and can stop it.** Plan: a `sv bundle` command first, with the
secret rules deciding what stays out and a listing that says what was left out and why; the MCP tool and the
"offer it once the report is written" step after that, as their own pieces.
**First piece done on 27 September 2026:** `sv bundle` (`crates/sv-cli/src/bundle.rs`, tests in
`crates/sv-cli/tests/bundle.rs`). It writes the zip beside the app, with the app's files, the report, the bill of
materials, a `BUNDLE.json` of SHA-256s and a plain-words `README.txt`; nothing the credential scan flagged, no
environment file, key store, database, link, editor folder or unreadable file goes in, and each is listed with its
reason. Written with no new dependency (SHA-256, CRC and a stored zip are in the crate). Reproduced on the way: a `--out`
reaching the app folder through a link (`/var` and `/private/var` on a Mac) slipped past the check, and a test caught it.
**Second piece done the same day:** `securevibe_bundle` over MCP (beside the app, never inside it, only where the
server may write, a link to somewhere else refused before anything is written), offered by `securevibe_write_report`
and the server's instructions "only if the person wants one", so nothing makes a zip on every run; the commit `sv` was
built from in `BUNDLE.json` (`unknown` outside a checkout, as in the Docker image); and the data categories from
`securevibe.toml` named in the listing, the README and on screen, and not acted on, since `sv` cannot tell which files
hold them. The image smoke test asks the container for a bundle and looks for the committed `.env` in it.
**Left:** each outside tool's own SARIF (only `findings.sarif` is in), and a real decision about what a category could
leave out, if anything can be said deterministically about it.
**The owner's decision, 6 October 2026, on the outside tools' own SARIF:** leave it out, and keep `sv`'s own
`findings.sarif`, which never carries a secret, since another tool's file can quote the value it found
("I agree with all your recommendations", 6 October 2026).

What goes in: the app's own files (without `node_modules`, build output, or anything in `SKIP_DIRS`),
`securevibe.toml`, `security-notes.md`, the report (`report.html`, `compliance.md`, `security.md`,
`findings.sarif`, `report.json`), the bill of materials, each outside tool's own SARIF, and a small
file saying which `sv` made it (version and commit), when, with which command, and a SHA-256 for
every file, so what was checked can be matched to what is in the zip.

Three things decide the design:
- **It must never carry a secret.** "The application's files" includes `.env` for most beginners,
  and this owner's app runs on an Anthropic API key. `sv` already finds credentials; the zip should
  leave out every file its secret rules flag, and say in the zip's own listing that it did. The same
  for data the app holds about people (`[data]` categories): leave it out unless asked.
- **It goes outside the app folder.** Finding 1 in the entry above is what happens when `sv`'s
  output lands inside the app. The MCP server writes only below the app today, deliberately, so a
  zip written from MCP needs its own place to go, or has to be skipped like the report.
- **When.** `sv` cannot tell when a build is finished; only the AI tool and the owner can. So
  "at the end" means the tool offers it once the report is written, and "on request" means a
  command (`sv bundle`, say) and an MCP tool. The two are the same feature; nothing should make one
  on every run.
