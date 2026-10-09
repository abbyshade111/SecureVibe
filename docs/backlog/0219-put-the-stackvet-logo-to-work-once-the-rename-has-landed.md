# Put the StackVet logo to work once the rename has landed

**Status:** open

Asked for by the owner on 8 October 2026, the day they chose the name StackVet and its logo: "a backlog item for after
the change is complete to deploy the logo and all that." **Waits for the rename** (ADR-062, and the backlog item the rename's
session claimed): do not start it until the rename has merged, since every part below names files the rename
changes. Written the same day by session securevibe-e2.

The logo is the code bracket in terracotta: a check mark inside square brackets, and the name in JetBrains Mono Bold
with "vet" in the accent color. Every file is in `docs/brand/`, whose README says what each is for, the colors, and
how to make them again; the owner's choice is ADR-063. Each part below can be claimed on its own.

1. **The README.** The logo at the top, the light or dark one to match the reader's GitHub theme, with the
   `<picture>` snippet in `docs/brand/README.md`. The same at the top of `docs/GETTING-STARTED.md` if it reads well
   there.
2. **The repository's preview image.** `docs/brand/social-preview.png` uploaded in the repository's Settings, under
   Social preview. **The owner's to do**: it is a repository setting, which sessions do not change. Check its line
   ("A security check for apps built with AI. It says plainly what it checked, and what it didn't.") still says what
   StackVet is when this is taken up; change it in `docs/brand/source/make_logo.py` and make the files again if not.
3. **The two sites.** stackvet.dev and stackvet.app are the owner's (bought 8 October 2026) and serve nothing yet.
   What they show, where they are hosted, and whether one sends visitors to the other are the owner's to decide,
   and hosting may cost money, so ask first. When a page exists, it uses `favicon.svg`, `favicon-32.png`, and
   `apple-touch-icon.png` from `docs/brand/`.
4. **The container image.** The `org.opencontainers.image.title`, `description`, `url`, and `source` labels in the
   `Dockerfile`, if the rename has not already set them, so the image's page on GitHub's package registry shows the
   new name and links back to the repository. Check what the rename did first.
5. **The reports, only if the owner wants it.** `report.html` and the dashboard could carry the mark in their
   heading and as the browser tab's icon. That changes what `sv` writes into someone's folder, which is a decision
   (CLAUDE.md), so it needs the owner's yes and a record, and the icon has to be inside the page (an inline SVG),
   since a report opens no network connection. Ask before building it.

**Parts 1 and 4 claimed 9 October 2026 by session securevibe-e2**, the rename having merged, in branch
`claude/securevibe-e2-logo`: the logo at the top of `README.md` (and of `docs/GETTING-STARTED.md` if it reads well
there), and the image's `org.opencontainers.image` labels in the `Dockerfile`. Confirmed on `main` just before this
claim: neither file carries the logo or any label, and no other session holds this item. Parts 2, 3, and 5 stay the
owner's.
