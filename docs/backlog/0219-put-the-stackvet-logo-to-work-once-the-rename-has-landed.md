# Put the StackVet logo to work once the rename has landed

**Status:** partly done: parts 2 (the repository's preview image, a setting), 3 (the two sites), and 5 (the mark in the reports), each the owner's to decide

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
**Parts 1 and 4 done the same day:** the logo, light or dark to match the reader's GitHub theme, at the top of
`README.md` and `docs/GETTING-STARTED.md`; and the `Dockerfile`'s `org.opencontainers.image` labels (title,
description, url, source, licenses), so the package page on GitHub's registry shows StackVet and links back to the
repository. `tools/docs_page.py` leaves a `<picture>` block out, since it shows no images and would otherwise print the
markup at the top of the README's page; its self-test holds that, and removing the skip failed it. Not checked by
hand: how the image's package page shows the labels, which needs the next push to `main` to publish the image. Parts
2, 3, and 5 remain the owner's.

**The owner's decision, 9 October 2026**, asked by session securevibe-e2 with a recommendation for each open choice: **yes to part 5**, the mark in `report.html` and the dashboard, as an inline SVG so a report still opens no network connection; it changes what `sv` writes into someone's folder, so it is built with a record. Part 2, the repository's preview image, stays the owner's to upload in Settings. Part 3, what the two sites show, waits for the website mock-ups (0224). Not claimed yet.
