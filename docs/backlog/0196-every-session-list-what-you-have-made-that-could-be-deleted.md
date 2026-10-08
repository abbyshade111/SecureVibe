# Every session: list what you have made that could be deleted, and ask the owner

**Status:** open

Asked by the owner on
7 October 2026, after the disk reached 152 MB free during the revision trial (17 GB was freed by deleting one session's
own `cargo` build folders, with the owner's yes). Each session, the cloud ones included where they keep files on this
Mac, looks through what it made: `cargo` target folders, worktrees under `/tmp/claude-502` and elsewhere, trial
folders under `~` (such as `~/sv-loop`, `~/sv-prompts`) whose results are committed, and logs. It writes the list
under this item, one line each, with the size, whether it can be made again, and which session made it, then asks
the owner. Nothing is deleted without the owner's yes; a folder another session made is that session's to list.
The standing rule is in `CLAUDE.md` ("Keep the disk tidy").
- Session securevibe-e2 (7 October 2026): a cloud session, so nothing of its own is on the Mac. Its build folder
  and scratch files are in its own cloud container, which is removed when the session ends.
