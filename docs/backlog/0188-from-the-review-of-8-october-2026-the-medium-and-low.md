# From the review of 8 October 2026: the medium and low findings, for any session to pick up

**Status:** done, 9 October 2026

The four rated
high were built the same day (the entry above this one's predecessor). Each of these can be claimed on its own.
1. Ctrl-C during `--tools` leaves the tool running with no limit: tools get their own process group
   (`adapters.rs`, `process_group(0)`) and that path installs no handler, so SIGINT kills `sv` alone and the
   30-minute limit, the private folder, and the lock's `Drop` are gone. The handler `sv-run` uses, killing the
   recorded group.
   **Claimed 8 October 2026 by session securevibe-e9**, from the roadmap (Phase 1, item 1, third in its order, the
   second being claimed by securevibe-e2), in branch `claude/securevibe-e9-tools-interrupt`: while an outside tool
   runs, Ctrl-C (or a polite `kill`) stops the tool's whole process group and lets `sv` end through its own cleanup,
   with the private folder removed and the lock let go, and the report not written as if the tools had run.
   Confirmed on `main` just before this claim: `adapters::finish` installs no handler, and `sv_run::catch_interrupts`
   is called only by the Docker backend.
   **Done the same day** (`docs/design/0306-ctrl-c-while-an-outside-tool-runs-8-october-2026.md`): Ctrl-C while a
   tool runs stops the tool's whole group, starts no other, removes the private folder, lets go of the report folder,
   and ends `sv` with 130 and nothing written.
2. npm lockfile `resolved` URLs are not held to the registry (`install.rs`), so the install container fetches
   wherever the lockfile says; refuse unless every entry is `https://registry.npmjs.org/` with `integrity`, as
   pip's `unpinned` refuses. And a dependency file that is a symlink is followed into the networked container
   (`symlink_metadata`, refuse a link).
   **Claimed 8 October 2026 by session securevibe-e2**, from the roadmap (Phase 1, item 1, second in its order), in
   branch `claude/securevibe-e2-npm-sources`: `install = true` refuses a `package-lock.json` any of whose packages is
   downloaded from anywhere but `https://registry.npmjs.org/` or carries no `integrity`, and a dependency file that
   is a link, each in plain words before anything runs. Changes what `sv` lets the networked install fetch: a Later
   entry on ADR-052. Confirmed on `main` just before this claim: `install::plan` reads neither, and no other session
   had claimed this part.
   **Done the same day** (`docs/design/0305-the-install-step-downloads-npm-packages-only-from-the-npm.md`; ADR-052, Later): every package in
   `package-lock.json` must come from `https://registry.npmjs.org/` with a SHA-256 or stronger `integrity`, a local
   folder or a lockfile `sv` cannot read is refused, and a `requirements.txt`, `package.json`, or `package-lock.json`
   that is a link is refused before it is read. Not done: a package's address is not compared with its name and
   version.
3. gosec fetches modules and runs the C toolchain, undeclared: `GOPROXY=off` and `CGO_ENABLED=0` in its `env`, or
   mark it `network: true` and say so in the README. CodeQL's extractors may run the app's package manager or
   `sitecustomize.py`: test it the ADR-032 way with a planted `preinstall` and `sitecustomize.py`. gosec,
   Brakeman, and CodeQL walk the folder themselves and follow links `sv` refuses: skip them when `listing.links`
   is non-empty, or list the links in `looked_away`.
   **Claimed 8 October 2026 by session securevibe-review**, from the roadmap (Phase 1, item 1, fourth in its order;
   the first three are done or claimed), in branch `claude/securevibe-review-tools-fence`: gosec is started with
   `GOPROXY=off` and `CGO_ENABLED=0`, so it neither downloads the app's modules nor runs a C compiler, and a run that
   could not load the app's packages for want of them is said to be one; the three tools given the folder rather
   than the files (gosec, Brakeman, CodeQL) are not run while the app holds a link, with the links named, since
   each would follow it out of the app; and CodeQL's extractors are tried against a planted `preinstall` and
   `sitecustomize.py` the ADR-032 way where `codeql` is installed. Changes what the tools may run and fetch, and when
   they run: a Later entry on ADR-032. Confirmed on `main` just before this claim: gosec's `env` is empty,
   `adapters.rs` reads `listing.links` nowhere, and no other session had claimed this part.
   **Done the same day** (`docs/design/0305-gosec-is-fenced-like-the-rest-and-the-tools-that-walk-the.md`;
   ADR-032 and ADR-018, Later): gosec starts with `GOPROXY=off` and `CGO_ENABLED=0`, shown to have downloaded 46 MB
   of modules and started `gcc` 32 times without them; its `-quiet` is gone so its log says which files it read and a
   clean run writes a report at all (none ever was credited before), with a file it did not read, or an analyzer run
   that failed for want of the modules, said in the report; gosec and Brakeman, each shown to read a linked file,
   are not run over an app that holds a link, with the links named. CodeQL 2.27.2, tried with planted `preinstall`,
   `postinstall`, `prepare`, `sitecustomize.py`, `usercustomize.py`, and `setup.py` and a linked file, ran none and
   read through nothing, so it carries no guard and the planted test stays. Not done: an SSA failure withholds the
   whole clean gosec run rather than only the analyzers' rules, and a linked folder, which neither tool entered, is
   refused with the files.
4. A planted `.securevibe-report` marker lets `securevibe_write_report` replace five named files in any app
   subfolder (`main.rs`, `refuse_someone_elses_folder`: a marker alone counts for writing). Require
   `is_sv_output` or a proven seal, else "give an empty folder".
   **Claimed 8 October 2026 by session securevibe-e2**, from the roadmap (Phase 1, item 1, first in its order), in
   branch `claude/securevibe-e2-report-marker`: a folder with the marker counts as `sv`'s own only when what is in it
   shows it is (`is_sv_output`), so a marker alone no longer lets a report replace files there. Confirmed on `main`
   just before this claim: `refuse_someone_elses_folder` lets any marked folder through, and no other session had
   claimed this part.
   **Done the same day** (`docs/design/0304-a-copied-report-marker-no-longer-lets-a-report-replace-the.md`; ADR-034,
   Later): a marked folder holding files `sv` did not write takes a report only when this computer can show, by the
   marker's seal, that `sv` wrote the report there, rather than only when the folder holds nothing else as the claim
   said, so a file the owner puts in a folder `sv` sealed is still kept. Not done: a folder holding only files under
   `sv`'s names, with no marker, is still written to as an old report folder (the deep review's S5 decided that).
5. Honesty gaps: an unreadable lockfile or unparseable manifest silently drops the manifest-versus-lockfile
   comparison (`sbom.rs:281, 437`; `manifest_lock.rs` returning `None`), so an unsaid comparison reads as
   agreement: an `unread` entry naming the file. The credit census (`tools/coverage.py`, `check_credits`) checks
   per check, not per requirement: a check citing two ids whose tests only ever credit one passes; also fail on
   `ids - got`, and mirror a findings log. `model_provider.rs` passes silently without `node`: honor
   `SV_REQUIRE_BACKEND` there.
   **Claimed 8 October 2026 by session securevibe-e2**, from the roadmap (Phase 1, item 1, the next unclaimed in its
   order), in branch `claude/securevibe-e2-honesty-gaps`: all three parts. A manifest-versus-lockfile comparison that
   could not be made is named as not made, with the file; the credit census fails a requirement a check cites and
   was never seen crediting, beside the per-check test it has (a Later entry on ADR-059); and the model-provider
   test fails without `node` when `SV_REQUIRE_BACKEND` is set. Confirmed on `main` just before this claim: none of
   the three is done, and no other session had claimed this part.
   **Done the same day** (`docs/design/0306-three-honesty-gaps-from-the-review-of-8-october-8-october.md`; ADR-059,
   Later): a manifest that cannot be read or understood is said not compared, on screen, in the report, and in the
   CycloneDX document, the bill of materials still complete; the census fails a cited requirement never seen
   credited; and the test model's tests fail without `node` when `SV_REQUIRE_BACKEND=1`. The findings log the review
   also asked for is the census of what checks withhold (ADR-059).
6. Low: a FIFO named `securevibe.toml` hangs the MCP server's serving thread (`app_dir` refuses links only);
   `Secret::redact` keeps four characters whatever the length, so a 4-character URL password is shown whole (show
   `min(4, len/3)`); `redact_text` masks only listed names, and `authorization`, `bearer`, `cookie`, `session`,
   `otp`, `pin` are missing, so a token a failing test prints reaches the report; a newline in a file name or a
   tool's finding title starts a fake terminal line (`main.rs`, the findings loop: use `one_line`); header values
   are quoted into findings uncapped (`production.rs`, `probes.rs`); an IDN host is not refused by `sv probe`, and
   curl's `--resolve` key would not match its punycode form; the no-sidecar fallback bypasses `prepared`, so those
   containers get no limits or run label (`docker.rs`, `inside_fence_with_input`); `image` is not validated
   against Docker's reference grammar; the typed passphrase `String` is not zeroized (`review.rs`); the DNS
   transaction id is predictable (`live_tls.rs`); a broken `adapters.json` is exit 3 with `--tools` and silent
   without; `main.rs` exits 130 in one place without the flush `exit_with` does; the bundle's scratch folder in the
   system temp dir is a write outside the root no document records; `report.html` has no Content-Security-Policy
   meta tag; the install volume's cache key is FNV-1a (use SHA-256).
   **Its first four parts claimed 8 October 2026 by session securevibe-e2**, from the roadmap (Phase 1, item 1, next
   in its order), in branch `claude/securevibe-e2-low-findings`: a FIFO (or anything but a plain file) named
   `securevibe.toml` refused before it is read; `Secret::redact` shows at most a third of a short value; `redact_text`
   masks values under `authorization`, `bearer`, `cookie`, `session`, `otp`, and `pin` too; and a line break in a file
   name or a tool's finding title is kept from starting a line of its own on screen. Confirmed on `main` just before
   this claim: none of the four is done, and no other session had claimed any part of item 6. The rest of item 6
   stays open.
   **Those four done the same day** (`docs/design/0307-four-low-findings-from-the-review-of-8-october-8-october.md`): a short value shows at most a
   third of itself; the names a program prints a credential under, and the token after `Bearer` or `Basic`, are
   masked; a pipe under a name the MCP server reads is refused before it is read; and `sv check` writes a finding's
   file and title on one line. The rest of item 6 is open.
   **Three more of its parts claimed 8 October 2026 by session securevibe-e9**, from the roadmap (Phase 1, item 1, the
   next unclaimed in its order), in branch `claude/securevibe-e9-low-three`: a header value quoted into a finding is
   cut to a length a person can read (`production.rs`, `probes.rs`); `sv probe` refuses a host name with letters
   outside ASCII and says to give its `xn--` form, since curl's `--resolve` key would not match it; and both places
   `main.rs` ends with 130 after Ctrl-C go through `exit::exit_with`, so what was printed is out first (one of them
   added by this session's own Ctrl-C fix). Confirmed on `main` just before this claim: none of the three is done,
   and no other session had claimed them. The rest of item 6 stays open.
   **Those three done the same day** (`docs/design/0308-three-low-findings-header-values-a-host-outside-ascii-and.md`;
   ADR-027, Later): a header value or redirect address is quoted on one line and cut at 200 characters, and still read
   whole; a host name outside ASCII is refused with a sentence asking for its `xn--` form; and every exit goes through
   `exit::exit_with`, which a test now holds. The rest of item 6 is open.
   **One more of its parts claimed 8 October 2026 by session securevibe-e2**, with item 7's `Adapters::load` and tool
   list below, whose code it shares, in branch `claude/securevibe-e2-adapters-once`: a broken `adapters.json` said in
   the report without `--tools` too, rather than silently listing no outside tools. Confirmed on `main` just before
   this claim: not done, and no other session had claimed it. The rest of item 6 stays open.
   **The rest of item 6 claimed 8 October 2026 by session securevibe-review**, from the roadmap (Phase 1, item 1, the
   next unclaimed in its order), in branch `claude/securevibe-review-low-rest`, as one pull request of small fixes:
   `image` in `[stack.run]` held to Docker's reference grammar before it is put on a command line, so a value that
   is a flag (`--privileged`) or carries a space is refused with its reason; the typed passphrase zeroized once used
   (`review.rs`); the DNS transaction id drawn from the operating system's randomness rather than the process id
   (`live_tls.rs`); the bundle's scratch folder recorded (ADR-017, Later) or moved beside what the bundle writes;
   a Content-Security-Policy meta tag on `report.html` and the dashboard; and the install volume's name made with
   SHA-256. The no-sidecar fallback is done already: since `d77f82dc` (8 October, "The hardening in one place")
   `fence_args` and `prepared` give it the same flags, labels, and limits as the sidecar, so it gets a done note
   and no build. Confirmed on `main` just before this claim: none of the six is done (`live_tls.rs` still forms
   the id from `std::process::id()`, `volume_name` still uses FNV-1a, no `Content-Security-Policy` in `sv-report`,
   no `zeroize` in `sv-cli`, no image grammar check in `sv-run`), and the only other claims on item 6 are the parts
   above and the broken `adapters.json` in #1104.
   **Those six done the same day** (`docs/design/0309-six-low-findings-from-the-review-of-8-october-an-image-name.md`;
   ADR-017, ADR-019, ADR-027, ADR-043, ADR-052, and ADR-057, Later): `image` held to Docker's grammar and refused with
   its reason; the typed passphrase zeroed; the DNS id from the operating system's randomness; the bundle's report in
   a private folder; a Content-Security-Policy tag on both pages; the volume's name a SHA-256. With the no-sidecar
   fallback's done note, item 6 is closed, apart from the broken `adapters.json` claimed in #1104.
   **That one done the same day** (`docs/design/0309-the-outside-tools-read-once-and-named-from-their-file-8.md`): without
   `--tools`, a broken `adapters.json` is said in the report, with why it could not be read. The rest of item 6 is open.
7. Housekeeping: fourteen British spellings against the American standard ("cancelled" in `rust.yml`, ADR-051,
   GAP-ANALYSIS, this file, `fake_app.rs`; "honoured" in `codeql.yml`; "licence" in ADR-018 and this file;
   "labelled" here; "recognise" in `docs/prompts/trial-4`); a home path with the owner's first name in
   `docs/prompts/library-trial/recipe-summaries.txt`; `assemble_report_saying` is 1,585 lines and
   `Adapters::load` runs three times per report; `main.rs` hard-codes the tool list and omits semgrep.
   **The spellings and the home path claimed 8 October 2026 by session securevibe-e2**, from the roadmap (Phase 1,
   item 1, last in its order), in branch `claude/securevibe-e2-housekeeping`: the British spellings in files a person
   reads made American, and the home path in `recipe-summaries.txt` replaced by `~`. History is not rewritten, so
   the path stays in earlier commits. `assemble_report_saying`, `Adapters::load`, and the tool list stay open.
   **Those two done the same day**: fifteen British spellings made American in workflows, a code comment, the gap
   analysis, two decision records, four backlog items, and a trial protocol; and the home path in
   `recipe-summaries.txt` replaced by `~`. Left as they are, saying why: the OWASP standards' own text in
   `data/frameworks` (and `docs/REQUIREMENTS.md`, made from it), quoted word for word; `common-passwords.txt`, a list
   of data; "cancellation", which is American too; identifiers such as test names; this item's own quotation of the
   words; and `docs/prompts/trial-4/recipe-brief.md`, which is the brief the trial gave its builders as given, so its
   "recognise" stays, as a record of what they read.
   **`Adapters::load` and the tool list claimed 8 October 2026 by session securevibe-e2**, from the roadmap (Phase 1,
   item 1, last in its order), in branch `claude/securevibe-e2-adapters-once`: the tools' file read once per report
   and handed to what needs it, and the sentence naming the outside tools made from that file, so Semgrep is named.
   Confirmed on `main` just before this claim: neither is done, and no other session had claimed either.
   `assemble_report_saying`'s length stays open.
   **Those two done the same day** (the same design entry): `adapters.json` read once, with the rest of `sv`'s data, and
   that copy handed to the run, the list of tools not run, and the exit status; and the sentence naming the outside
   tools made from the file, so it reads "Bandit, gosec, Brakeman, Semgrep, and CodeQL". `assemble_report_saying`'s
   length is open.
   **`assemble_report_saying`'s length claimed 8 October 2026 by session securevibe-review**, from the roadmap (Phase
   1, item 1, the last part of its last sub-item), in branch `claude/securevibe-review-assemble`: the 1,576-line
   function (`main.rs` lines 3909 to 5485 on `main` at `a49d856a`) split along the stages it already names
   (`STAGES`, which the MCP server reports) into a module of its own, one function per stage with the state they
   pass between them in one struct, and nothing else changed: the same report, the same stage names in the same
   order, and the same words. Held by the verdict snapshots (`crates/sv-cli/tests/verdicts.rs`), which fail on any
   change to what the example apps' reports say, and by the existing MCP tests of the stage names. Confirmed on
   `main` just before this claim: the function is still one body, and no other session had claimed it (#1108
   touches `main.rs` elsewhere; this build starts once it has merged, so the two do not meet).
   **Done the same day** (`docs/design/0311-the-report-s-assembly-in-stages-one-function-each-8-october.md`): the
   function moved to `crates/sv-cli/src/assemble.rs` and became eight functions along its own sections, with what
   every stage reads in one struct (`Scene`) and what each produces returned; the report, the stage names, and their
   order unchanged, held by the verdict snapshots and the rest of `sv-cli`'s suite. With it, every part of item 7 is
   done. `main.rs` is 5,063 lines after it, and its size stays with the architecture assessment's item.
