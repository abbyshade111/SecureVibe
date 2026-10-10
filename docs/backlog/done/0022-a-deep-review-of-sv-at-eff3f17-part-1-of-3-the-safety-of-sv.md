# A deep review of `sv` at `eff3f17`, part 1 of 3: the safety of `sv` itself, and AI reviews

**Status:** done, as its markers read on 8 October 2026

Sent on 4 October
2026 by the cato-pipeline session at the owner's asking: six reviewers, findings reproduced with harmless fixtures
on a build of `eff3f17` or on the 45b6d71 image. Labels: *Reproduced* (a reviewer ran it), *Read* (confirmed from
the code), *Plausible*. Parts 2 and 3 (honesty, accuracy, reports) follow as their own entries. The sender's order
of fixes: S1; S2; S3 to S6; R1 and R2; then part 2's. **Each item can be claimed on its own.**
- **S1. Critical, Reproduced. A backslash in a file name makes `sv bundle` read and zip files outside the app.**
  `bundle.rs` walk (about line 306) rebuilds each path from its text with `\` turned into `/`, so a file named
  `..\outside\key.txt`, an ordinary name on macOS and Linux, is read as `../outside/key.txt` (enough `..\` parts
  reached `/etc/hosts`), and the zip entry is a zip-slip. The same mapping feeds Semgrep's file list
  (`adapters.rs`), the compose reader (`sv-scan/src/lib.rs`), and `jvm.rs`. Fix: carry the walked path, never
  rebuild one from its text; leave out and list a name with `\`, a `..` part, or bytes that are not UTF-8; check
  every zip entry name part is ordinary.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking through the cato-pipeline session,
  in branch `claude/securevibe-e9-backslash-paths`.
  **Done the same day** (DESIGN, "A backslash in a file name"), held three ways: relative paths are built from
  their parts (`sv_scan::files::relative`, so every check reading through the listing has it), the bundle leaves
  such names out and lists them, and `zip` refuses any entry name that is not a plain path inside the bundle.
  Tested with the review's own fixture; each layer broken on its own was caught, and all three broken reproduced
  the fault.
- **S2. High, Reproduced on Colima. The fence lets the app reach the host through the bridge's gateway.**
  `docker network create --internal` blocks the internet but not the gateway: a fenced container reached the
  Colima VM's sshd at 172.20.0.1:22. On Linux with Docker itself, the gateway is the developer's own machine.
  `verify_fenced` only checks the network is internal, and `tests/fence.rs` only tries the internet. Fix: create
  the network with `com.docker.network.bridge.inhibit_ipv4=true` or block the gateway another way, refuse to run
  when a fenced container can reach the gateway, and test the gateway with a positive control.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking through the cato-pipeline session,
  in branch `claude/securevibe-e9-fence-gateway`.
  **Done the same day** (DESIGN, "The fence's gateway"): the fenced network is made without a gateway address
  (`inhibit_ipv4`), and before the app starts a throwaway container knocks on the gateway; any answer stops the run,
  with a control on the container's own loopback. The fence test asks the runner's check of a plain `--internal`
  network (refused, the positive control) and of the runner's own (passes); its real run is CI's.
- **S3. High, Reproduced. `sv notes` and `sv rules` write through a link to a file outside the app**
  (`main.rs`, AGENTS.md and security-notes.md, plain `fs::write`). The MCP route refuses a link; the command
  line does not.
- **S4. High, Reproduced. `sv bundle` writes its zip through a link in the app's parent folder**
  (`main.rs`, `bundle.rs`): an existing `app-securevibe-bundle.zip` link to another file had that file
  overwritten. Fix: refuse a link there; write a new file under a temporary name, then rename.
- **S5. High, Reproduced. A report written with `out` "." overwrites the app's own files** (`mcp.rs`,
  `main.rs`): on a case-insensitive volume `security.md` replaced the app's `SECURITY.md`. Fix: refuse an
  existing folder that holds other files and no marker of `sv`'s, comparing names case-insensitively.
  **S3 to S5 claimed on 4 October 2026 by session securevibe-e2**, at the owner's asking to continue with the
  backlog, in branch `claude/securevibe-e2-safe-writes`: one way of writing a file `sv` makes, used by every
  command.
  **S3 to S5 done the same day** (DESIGN, "Files `sv` writes, never through a link and never over the app's
  own"): `sv rules`, `sv notes`, and `sv bundle` refuse a link where they write and write under a new name then
  rename; `bundle::resolve_for_writing` no longer resolves the zip's own name, which had hidden the link from any
  check; and a report is refused in a folder holding files `sv` did not write unless `sv` marked it, and in any
  folder holding a name that differs from one of `sv`'s only in capitals. Eleven guards broken in turn; ten caught,
  and the eleventh (the rename after the check) closes a race no test can stage, held by its own unit test.
- **S6. High, Reproduced. Tool reports go to fixed names in the shared temporary folder, and a planted file is
  taken as a real run** (`adapters.rs`: `temp_dir()`, `sv-<id>.sarif`, any readable file accepted, exit status
  ignored). A planted unwritable `/tmp/sv-bandit.sarif` recorded Bandit as run with nothing found; two runs at
  once read each other's. Fix: a private folder per run (0700, unpredictable name), each tool's exit codes, and
  only a report created after the tool started.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking through the cato-pipeline session,
  in branch `claude/securevibe-e9-tool-reports`.
  **Done the same day** (DESIGN, "Tools' reports in a folder of the run's own"): each run makes a new folder,
  mode 700 with a random name, for the tools' reports and removes it afterwards; each adapter lists the exit codes
  that mean it finished, from its own source, and any other ending is not run; and only a plain file the tool
  wrote in this run is read. Seven guards undone in turn, each caught by its own test. Gosec ends with 1 both on
  finding and on failing, so for it the report still decides.
- **S7. High, Reproduced. Bandit follows links `sv` refuses**, so a linked file's text from outside the app
  reaches the report. Bandit and Brakeman are given `{dir}`. Fix: give Bandit `sv`'s own file list, as Semgrep
  gets; until then drop findings on linked files and mark the run partial.
  **The same `{dir}` brings in folders `sv` leaves out** (added on 4 October 2026 by the cato-pipeline session,
  usability analysis for `docs/paper`): in family-hub on 3 October, 139 of Bandit's findings (145 in the last
  report of the day) were in `vendor/`, Flask's own code, which `sv`'s reading and Semgrep's file list both leave
  out (`SKIP_DIRS`, `crates/sv-scan/src/ecosystems.rs` line 573; `data/adapters.json` line 26). Bandit's rules
  are Bandit's; handing it the folder is `sv`'s choice. S7's fix, `sv`'s own file list, takes these out too.
  **Claimed on 4 October 2026 by session securevibe-e10**, with H7, at the owner's asking to work through the
  review's open items, in branch `claude/s7-h7-bandit`.
  **Done the same day** (DESIGN, "Bandit handed the app's own Python files, and a run that did not finish"):
  Bandit is handed `sv`'s listing of the app's Python files by name, so links out of the app and `vendor/` are not
  read; `{files}` gives a tool that reads one language only that language's files. Brakeman still takes the folder,
  since it reads a Rails app as a whole. Tested with stand-in programs; Bandit itself is not installed where this
  was written, so its first real run is CI's or the owner's.
- **S8. High, Reproduced. A bundle leaves out a file for holding a secret, but carries the secret in its
  report**: Bandit's B105 message quotes the password, and adapter messages are not redacted. Fix: redact every
  adapter finding's text, and scan the report files for secrets before zipping.
  **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/s8-bundle-tool-messages`.
  **Done the same day** (DESIGN, "What an outside tool says is redacted, and a bundle's report is scanned before
  it is zipped"): every tool finding's title, description, impact, and fix, and every line of a tool's stderr a
  reason quotes, go through `redact_text` as they are read, redacted before being cut to length; a quoted value
  now runs on past an apostrophe (B105 quoting "You've…" left the rest showing); and `sv bundle` scans its report
  files and refuses to zip one holding a credential, naming file and line, never the value, with `sv`'s own
  redaction marker no longer read as one. Tested end to end with a stand-in Bandit quoting a password and stand-in
  tools quoting it on stderr: after the search is shown to find a planted copy, the password is in no report file,
  bundle entry, MCP reply, or printed line; and a key in the app's name stops the bundle. Seven guards broken in
  turn, each caught; cutting before redacting only by its unit test, whose lines are long enough to be cut.
- **S9. Medium, Read. No resource limits on the app, and its output read without a cap** (`docker.rs`: no
  `--memory`, `--pids-limit`, `--cpus`, or `--user`; unsized tmpfs; `sv-run/src/lib.rs` reads to the end).
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-s9`.
  **Done the same day** (DESIGN, "Limits on what the app may use"; ADR-019, Later): every container a run starts
  gets 2 GB of memory with no swap beyond it, 512 processes, and up to two processors, added where every `docker
  run` is labeled, so none is missed; the browser's and mail server's in-memory folders have a size; `sv` keeps at
  most 32 MB of what any command prints, reads and drops the rest, and never hands a cut answer to a check.
  `--user` was weighed and left out, with the reason in ADR-019. Five guards broken in turn, each caught.
- **S10. Medium, Read. Run names come from the process id alone, and teardown removes containers by name**, so
  two jobs on one Docker daemon can remove each other's containers. Fix: randomness in the run id; tear down only
  what this run made.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-s10`.
  **Done the same day** (DESIGN, "Each run removes only its own"; ADR-019, Later): a run's name ends in four
  random bytes, everything it creates carries the label `org.securevibe.run` with that name, and its teardown
  removes what Docker lists under the label, by id, falling back to the run's own names only when Docker will not
  list them. Four guards broken in turn, each caught.
- **S11. Medium, Plausible. The browser's DevTools port may be reachable from the app, and the driver evaluates
  in the page's own world**, so an app could hide storage from the sign-out check. Fix: DevTools on loopback,
  an isolated world, storage read through DevTools' storage domains.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-s11`.
  **Done the same day** (DESIGN, "The browser's DevTools on loopback, and the driver in a world of its own";
  ADR-019, Later): reproduced, the image's script forwarded DevTools on every address; Chromium now starts with
  DevTools on loopback alone, and the driver runs every expression in an isolated world of its own.
- **S12. Medium, Reproduced. A named pipe in the app hangs `sv`** (`files.rs` lists pipes as files and blocks
  reading them). Fix: list only regular files; say the rest were not read.
  **Claimed on 4 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
  branch `claude/securevibe-e2-pipes`.
  **Done the same day** (DESIGN, "A named pipe is named, never opened"): the walk lists only regular files, and
  anything else (a named pipe, a socket, a device) is named apart and never opened; `sv check` prints it, the report
  lists it as a gap, the checks that read the app's files say they read part of it, and `sv bundle` lists it as left
  out. Five guards broken in turn, each caught; undoing the walk's own guard hung all three commands again.
- **S13. Low, Reproduced. `sv probe` takes internal addresses, and curl's globbing turns one address into
  several requests** (`production.rs`). Fix: `--globoff`, and refuse private, loopback, link-local, and
  unspecified addresses, names that resolve to them included.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-s13`.
  **Done the same day** (DESIGN, "`sv probe` asks only public addresses"; ADR-027): private, shared, link-local,
  loopback, unspecified, and other non-public addresses are refused, typed or looked up; the name is looked up
  once and curl is held to the checked addresses with `--resolve`; every curl starts `--disable --globoff --proto
  =http,https`. Found while building it: `--disable` had been ignored, because curl reads it only as the first
  argument. Seven guards broken in turn, each caught.
- **R1. High, Reproduced. An AI tool can mark its own findings as reviewed by a person** (`review.rs`,
  `confirm.rs`): only an empty `by`, "ai-tool", and "AI coding tool" are refused, so `by = "owner"` cleared a
  finding, shown as "SET ASIDE BY A PERSON"; `confirmed.by` has the same gap. Fix: at least say what is known
  ("marked by = owner in securevibe.toml; sv cannot tell who wrote it"); better, record reviews only through an
  interactive `sv review` that refuses input that is not a terminal and keeps its record outside the app folder,
  entries without one counting as proposals; show the entry's git author.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking through the cato-pipeline session,
  in branch `claude/securevibe-e9-who-set-aside`, for the first fix only: say what is known wherever a report
  says "by a person". The interactive `sv review` stays open, for the owner to decide.
  **First fix done the same day** (DESIGN, "Who set a finding aside: what securevibe.toml says, not "a person""):
  the section is "Set aside in securevibe.toml", each entry reads "securevibe.toml says (name) set it aside", a
  confirmed answer is "confirmed in securevibe.toml", and each says `sv` cannot tell who wrote the entry; the MCP
  output tells the AI coding tool never to name the person in `by` itself. Twelve wordings put back in turn, each
  caught. **Still open, for the owner to decide:** the interactive `sv review` with its record outside the app's
  folder. The git author was considered and left out: an AI coding tool commits under the owner's git name.
  **The owner decided on 4 October 2026**: build `sv review`, a command that runs only in a terminal and seals each
  entry it records with a key kept outside the app's folder; the entries stay in securevibe.toml, and an entry
  without a valid seal counts only as a proposal. A seal that cannot be checked where `sv` runs (CI, another
  computer) still counts, saying it could not be checked there. **Claimed the same day by session securevibe-e9**,
  in branch `claude/securevibe-e9-sv-review`.
  **Done the same day** (DESIGN, "`sv review`: what a person records is sealed"): `sv review [PATH]` runs only in a
  terminal, shows each entry that does not count on this computer, and writes the person's name, the date, and an
  HMAC seal back into securevibe.toml, keyed by `~/.config/securevibe/review-key`. Unsealed entries, `by = "owner"`
  included, are proposals; on the computer holding the key a changed entry or another key's seal is too; with no key
  (CI) a sealed entry counts and says it was not checked. Twenty-one guards undone in turn, each caught.
  **Still open, the same gap one step over:** an answer under `[design]` or `[checked-by-hand]` written with
  `by = "owner"` still counts as the owner's own word ("attested by the owner", "checked by hand by the owner")
  without a seal. `sv review` could record those too; it changes how the owner answers every question, so it is the
  owner's decision.
  **The owner decided on 4 October 2026 to close it, and it was claimed the same day by session securevibe-e9**,
  in branch `claude/securevibe-e9-owner-answers`: `[design]` answers and `[checked-by-hand]` results written
  `by = "owner"`, and security-notes.md sections marked `Written by: owner`, count as the owner's word only when
  recorded through `sv review`; otherwise they count as the AI coding tool's.
  **Done the same day** (DESIGN, "The owner's own answers are recorded through `sv review` too"): all three now
  count as the owner's only when sealed by `sv review`, which offers each of them; without a seal they drop to
  *stated by the AI coding tool*, and the report says why.
- **R2. High, with R1, Reproduced. "Nothing here found a problem" when a check found something and it was set
  aside** (`bluf.rs`, `markdown.rs`). Fix: name set-aside findings in the headline.
  **Claimed on 4 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
  branch `claude/securevibe-e2-set-aside-headline`.
  **Done the same day** (DESIGN, "The headline counts what was set aside"): the headline counts false alarms set
  aside in securevibe.toml, says so when nothing else is open, and says where they are listed; it says "in
  securevibe.toml", not "by a person", since who wrote the entry is R1's question. Three guards broken in turn, each
  caught.
