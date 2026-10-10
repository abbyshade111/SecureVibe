# Found by the documentation review (6 October 2026), in `sv` itself

**Status:** done, 8 October 2026

Each was found reading a document against
the code and confirmed in the code; each is **not claimed** and can be claimed on its own. Most important first.
1. **A clean run credits V15.2.4 on a check that cannot show it.** `ast.download-piped-to-shell` cites V15.2.4
   (components and their dependencies come from the expected repository, no dependency confusion; level 3) and is
   not `findingsOnly`, so a shell script with no `curl … | sh` credits V15.2.4 as checked. Not finding a download
   piped to a shell says nothing about where the app's dependencies come from. Fix: make the rule finding-only for
   V15.2.4 (a finding is evidence against it; nothing found credits nothing). A change to what counts as evidence:
   ADR-018 changes with it.
   **Part status:** done, with the item
2. **The starter `securevibe.toml` leaves `[stack.run.users]` in force with every key commented out.** It parses as
   an empty section, not an absent one, so a run reports "[stack.run.users] … cannot be used: `login` is not set…"
   where the spec says leaving it out reports the signed-in checks as not assessed (`crates/sv-manifest/src/spec.rs`,
   the starter; `signed_in/mod.rs`). Fix: comment the header out, as the other optional sections are. **Done**, in
   part 2 of the documentation review.
   **Part status:** done, date not recorded
3. **`admin-actions` needs `admin` too.** An admin account is made only when `admin` pages are listed, so with
   `admin-actions` and no `admin`, V8.3.1 is not assessed with the reason "an admin is made by `seed`", which misleads
   when `seed` is set. Fix: make the admin when `admin-actions` is listed, or say in the spec that it needs both.
   **Part status:** done, with the item
4. **`sv run` exits 0 when the app could not start,** after printing "Not assessed". ADR-029's codes cover `sv check`,
   `sv report`, and `sv audit` only; `sv run`'s are not decided. For the owner: should `sv run` exit 2 there?
   **Part status:** done, with the item
5. **`securevibe_bundle` with no `path` is always refused** (the zip goes beside the app, and the server's own folder
   has no "beside" it can write to), though the tool's description says `path` defaults to that folder. Fix the
   description, or the default.
   **Part status:** done, with the item
6. **`tools/coverage.py` writes three things wrong into `docs/REQUIREMENTS.md`:** a Rust `\\u{2014}` escape printed
   as `u{2014}` (V2.2.2's row); "semgrep, N rules" counting distinct descriptions rather than rules (V1.2.4 says 1,
   where 74 rules cite it); and a phrase repeated where a rule's own description joins two with "; ". The escape
   is **done**, in part 2 of the documentation review; the count and the repeated phrase are still open.
   **Part status:** done, with the item
7. **`[data]` category names are not checked.** Only an exact match to the sensitive list raises the level, so a
   misspelled `"Health"` quietly allows level 1. Fix: warn on a name not in the list.
   **Part status:** done, with the item
8. **For the owner, about the prompt library:** the "settings file first" prompt, shown to work, says to "delete the
   line instead of writing false" when unsure, where `sv init`'s own instructions say "if you are unsure whether a
   capability is present, say true"; and it says `sv init` creates the file, where it prints it. Changing a shown
   prompt's words may take its result away, so the owner decides which wording stands.
   **Part status:** done, with the item
**Items 1, 3, 5, 6 (the count and the repeated phrase), and 7 claimed on 6 October 2026 by session securevibe-e9**, at
the owner's word ("Please continue to work off the backlog"), in branch `claude/securevibe-e9-doc-review-fixes`.
Item 1 changes what counts as evidence, so its record goes with it: **`Status: proposed`**, a "Later" entry on
ADR-018 saying `ast.download-piped-to-shell` is only ever a finding, since finding no download piped to a shell says
nothing about where the app's dependencies come from. Items 4 and 8 stay the owner's.
**Done the same day** (DESIGN, "Five findings of the documentation review"; ADR-018 and ADR-024, Later, 6 October
2026). 1: the rule is findings-only. 3: `admin-actions` make an admin as `admin` pages do. 5: the bundle tool's
`path` is required and says why. 6: the tool rules are counted by rule, and each phrase is said once. 7: a category
not on the list holds the app to level 2, and the report names it; capitals and spaces are read through.
**The owner's decisions, 6 October 2026, on items 4 and 8**, as session securevibe-e9 recommended ("1 yes, 2 go with your recommendation, 3 the firmer sentence, 4 agree yes, 5 no for now agree, 6 yes agree with your
recommendation, 7 leave it unchecked and update report to give that information yes").
4: `sv run` exits 2 when the app could not start, as `sv check` and `sv report` do when a check could not run
(ADR-029). 8: only "`sv init` creates the file" becomes "prints"; the shown prompt's advice to delete the line when
unsure stays, since both it and `sv init`'s "say true" leave nothing excluded.
**Both claimed the same day by session securevibe-e9**, in branch `claude/securevibe-e9-owner-small`. Item 4 changes
what an exit code says, so its record goes with it: **`Status: proposed`**, a "Later" entry on ADR-029: `sv run`
exits 2 when the app never answered or could not be started, 3 when `sv` itself failed, and 0 otherwise.
**Both done the same day** (DESIGN, "Four of the owner's decisions of 6 October 2026"; ADR-029, Later, 6 October
2026): `sv run` exits 2 when the app could not be run, held against real containers; the prompt says "it prints",
and `docs/PROMPTS.md` says that one word changed after its trial.
**Every part done, checked on `main` on 8 October 2026 by session securevibe-e2** from the roadmap (Phase 1, item 2):
the status line read "2 of 8 parts done" because the notes above mark several parts at once ("Items 1, 3, 5, 6 …
claimed", "Both done"), which the board does not read part by part. Checked in the code: `ast.download-piped-to-shell`
is `findingsOnly`, and `admin-actions` make an admin (`signed_in/admin.rs`).
