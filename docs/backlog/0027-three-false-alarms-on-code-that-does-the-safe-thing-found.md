# Three false alarms on code that does the safe thing, found testing the prompt library, 3 October 2026

**Status:** partly done: parts 2 (backlog 0228's conversion read them as not done)

Found
by session securevibe-e10 in the prompt test builds (Python and Flask, written by helper agents; see
`docs/PROMPTS.md`). Each kept a prompt from being shown to work, because the build that followed the prompt was
flagged. **Each can be claimed on its own.**
1. **`ast.sql-built-by-hand` (V1.2.4) on a query taken whole from the code.** Flagged:
   `db().executescript(SCHEMA)` with `SCHEMA` a module-level text constant, and `db().execute(sql, params)` with
   `sql = SORT_ORDERS.get(key, SORT_ORDERS["newest"])`, a dictionary of fixed queries, and the values passed as
   parameters. Neither joins text. Witnesses needed both ways: a constant and a lookup in a constant dictionary
   stay quiet; a constant joined with a request value still fires.
   **Done on 4 October 2026 with A1** (DESIGN, "Names that stand for fixed text"): both are quiet, and the
   constant joined with a request value still fires.
   **Part status:** done, 4 October 2026
2. **`ast.file-path-from-value` (V5.3.2) on a path built from the app's own database.**
   `send_file(os.path.join(UPLOAD_DIR, row["id"]), ...)`, where `row` came from a query on the signed-in user's
   attachments and the id was made by the app (`uuid4().hex`) when the file was saved. Telling a database value
   from a request value is the hard part; at the least the finding could say `"confidence": "low"` here, as the
   rule already does for a question it cannot settle.
   **Part status:** claimed by securevibe-e9, 5 October 2026
3. **`ast.open-redirect` (V3.7.2) on a destination already checked.** `redirect(safe_next(next_url))`, and
   `next_url = safe_next(...)` then `redirect(next_url)`, where `safe_next` sends anything but a same-site path to
   the home page. Both the build with the prompt and the one without were flagged, so the rule cannot currently
   tell a checked redirect from an unchecked one. Recognizing every checking function is not possible; one
   honest step is to lower the confidence when the value passed through a function of the app's own whose
   name or body speaks of the destination, and say so in the finding.
   **Items 2 and 3 claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
   `claude/securevibe-e9-a1-rest`: each finding stays, with its confidence lowered and the reason said, when the
   path is built only from fixed text and a value read back from the app's database, or the destination passed
   through a function whose name says it checks it.
   **Done the same day** (DESIGN, "A path the app stored, and a destination a function checked, say so"): both
   rules already report at low confidence, so the finding says why instead: a path built from fixed text and a
   value read back from the app's database says so, and a destination that passed through `safe_next` and the
   like names it. Neither is dropped.
   **The owner's decision, 5 October 2026:** keep the finding, and when the destination passes through a function
   of the app's own, name that function in it as the thing to check. **Claimed the same day by session
   securevibe-e2**, at the owner's word, in branch `claude/securevibe-e2-redirect-checked`.
   **Withdrawn the same day:** session securevibe-e9's claim above landed within minutes of this one, and its
   work (#738) merged first and already does what the owner decided. This session's version, which named any
   function the same file defines rather than one whose name says it checks, was closed unmerged (#744); its
   branch is kept.
   **Part status:** done, 5 October 2026
**Every part done, checked on `main` on 8 October 2026 by session securevibe-e9** from the roadmap (Phase 1, item 3):
the status line read "2 of 3 parts done" because parts 2 and 3 were marked together ("Items 2 and 3 claimed", "Done
the same day"), which the board does not read part by part. The withdrawn second claim above changes nothing.
