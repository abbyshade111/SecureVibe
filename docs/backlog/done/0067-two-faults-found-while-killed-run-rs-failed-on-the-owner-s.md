# Two faults found while `killed_run.rs` failed on the owner's Mac

**Status:** done, as its markers read on 8 October 2026

Found on 28 September 2026 by the
session working in branch `claude/killed-run-colima-mount`. The test itself was fixed in #361: it wrote its
app to the system's temporary folder, which on a Mac is under `/var/folders`, and Colima does not share that
folder with its machine, so the app's folder arrived empty and the app never answered. Each item can be
claimed on its own.
1. **A run that removes leftovers and then fails does not say it removed them.** `DockerBackend::run`
   (`crates/sv-run/src/docker.rs`) removes what an ended run left before it starts anything, but the list
   travels back only in a successful `RunOutcome`. When the app then never answers, or Docker refuses,
   `sv run` and `sv report --run` say only why the run failed, and containers and a network were removed
   from the owner's computer without a word. Seen on the owner's Mac: after the failing test, nothing
   labeled `org.securevibe.owner` was left, and nothing had said so. Fix: a failed run carries what it
   removed, and its explanation names it, so both commands say it.
   **Claimed on 28 September 2026 by that session**, at the owner's asking, in branch
   `claude/failed-run-says-removed`.
   **Done the same day:** a failed run is a `RunFailed`, the reason and what was removed first, and its
   explanation gives both. `a_run_that_fails_after_removing_leftovers_still_says_what_it_removed` in
   `crates/sv-run/tests/leftovers.rs` fails when the failure drops the list and when the explanation
   leaves it out. See DESIGN, "A run has an end, and Ctrl-C cleans up", the part headed "Later still".
   **Part status:** done, 28 September 2026
2. **On a Mac with Colima, an app folder outside the home folder reaches the app empty, and `sv` says only
   that the app never answered.** Colima shares the home folder with its machine by default and nothing
   else; Docker mounts any other folder as a new, empty one without complaint. Checked on the owner's
   Colima (Docker 29.5.2): a folder under `/var/folders` appeared empty inside a container, and one under
   the home folder appeared with its file. The run is still correctly not assessed, but the reason given
   ("never answered on its health path") sends the owner looking at their app rather than at where it is.
   Fix, as a suggestion: after the app's container starts, list `/app` inside it; when it is empty and the
   folder on this computer is not, stop the run as not assessed and say the container backend could not
   see the folder, naming Colima's shared-folder setting. A test: an app folder the backend cannot see
   (on Linux, where every folder is shared, this needs a stand-in, such as a folder the check is told is
   empty inside). **Claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to continue
   with the backlog.
   **Done the same day:** when the app never answers, the run lists `/app` from a throwaway container of the
   probes' own busybox image with the same mount (no network, read-only, no capabilities). Empty there while
   the folder has files on this computer is `CannotRun::AppFolderUnseen`, which names the folder and Colima's
   and Docker Desktop's sharing settings instead of blaming the app. Asked only on failure, so a run that
   works pays nothing. `unseen_folder` in `crates/sv-run/src/lib.rs` is tested with the inside as a stand-in
   (Linux shares every folder), with three controls; the existing never-starts test in
   `crates/sv-run/tests/fence.rs` is the control that runs for real in CI, where the listing must see the
   fixture's files and the reason must stay "never answered". Not tried on a Mac with Colima.
   **Part status:** done, 28 September 2026
