# An app in a subfolder of a git repository is reported as not in git

**Status:** done, as its markers read on 8 October 2026

Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
--tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). `tracked_files` in
`crates/sv-check/src/config.rs` looks for `.git` in the app folder itself, which exists only at a repository's
root, so `config.secrets-file-committed` says "This folder is not a git repository" and advises putting it in git.
Fix: ask git (`git -C <app> rev-parse --is-inside-work-tree`, then `ls-files`, which lists the subfolder's tracked
files relative to it). **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
**Done the same day,** by looking for `.git` in the app's folder and every folder above it rather than asking
`rev-parse`, so a `.git` git cannot read is still told from none: git is asked from inside the app's folder, so
only its own files count, and a secrets file committed elsewhere in the repository is not reported. An app in a
subfolder with no `.gitignore` of its own is not assessed rather than failed. See DESIGN, "A check reports one
of three things".
