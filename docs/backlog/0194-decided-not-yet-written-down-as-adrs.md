# Decided, not yet written down as ADRs

**Status:** open

**All three written down on 27 September 2026 by session securevibe-e8**, in a `docs/adr/` of `sv`'s
own, numbered after v1's so that a number always means one decision (`docs/adr/README.md`). Each one was
checked against the code and the history before it was written, and two were not quite true as stated here:

- ~~Corroboration only ever moves toward more requirements applying, never fewer.~~ **ADR-015.** True for
  every question the owner is asked. The derived conditions, which nobody is asked, are the exception: a
  scan that finds no XML or GraphQL library answers "no", and those requirements stop applying. The record
  says so rather than repeat the rule without it.
- ~~The OWASP data files are shared with v1, not copied.~~ **ADR-016.** True until 26 September 2026.
  Since the move there are two copies, `main`'s and the `v1` branch's, and a correction to one does not reach
  the other. Eight of the eleven files in `data/knowledge` are v1's alone, and editing them changes nothing
  `sv` does.
- ~~`sv` never writes application code.~~ **ADR-017.** True. It lists what `sv` does write into an app's
  folder (`security-notes.md`, its section of `AGENTS.md`, the reports), none of which the app runs.

The nine references to ADR-012, in `DESIGN.md` and in four files of three crates, now say it is v1's, and the
index says where it lives. **Not settled, and named in the index:** ADR-012 also ruled out SecureVibe writing
its own static-analysis rules for other languages. `sv` has since written them for fourteen, and no record
revisits that ruling. Whether one should is the owner's question.

**The owner answered on 27 September 2026:** the ruling needs updating. A superseding record covering
the decision that `sv` checks apps in many languages, with its own rules among the checks, is **claimed
the same day by session securevibe-e8** and drafted as ADR-018. **Accepted by the owner the same day**, and
done: `docs/adr/ADR-018.md`.
