# One file per design entry, so two pull requests stop colliding in `docs/DESIGN.md`

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on
8 October 2026 ("can you implement your recommended action of one file per design entry"), after auto-merge kept
stalling: every session adds its section to the end of `docs/DESIGN.md`, so any two open pull requests edit the same
lines, and each merge leaves the others in conflict. A `.gitattributes` rule to keep both sides was considered and
does not help, since GitHub ignores it when it decides whether a pull request conflicts. To build: each of
`DESIGN.md`'s sections becomes its own file under `docs/design/`, numbered in their order and named by their
heading, unchanged, so every `DESIGN, "Section title"` reference still finds its section; `DESIGN.md` becomes a
short, fixed introduction saying where the entries are and how to add one, with no index in it (a committed index
would bring the same conflict back); a script that writes a new entry, and moves the sections a branch added to the
old file into entries of their own after it merges `main`; the documentation pages (`tools/docs_page.py`) list the
entries apart; and `CLAUDE.md`, `README.md`, and `ARCHITECTURE.md` say where design entries now go. Record:
ADR-060, proposed with this claim.
**Claimed 8 October 2026 by session securevibe-e9**, at the owner's word, in branch
`claude/securevibe-e9-design-entries`.
**Done the same day** (`docs/design/0297-one-file-per-design-entry-8-october-2026.md`; ADR-060 accepted).
