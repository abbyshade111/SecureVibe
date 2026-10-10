# A review of the code merged on 5 and 6 October 2026, for faults

**Status:** done, by its own batch notes, read again on 8 October 2026 after a reviewer's comment on the split
Asked for by the owner on 6 October 2026,
once every item an agent could take without the owner's word was done or claimed. About 120 pull requests,
23,600 lines in `crates/` and `data/`: among them the booking check sent as two users, the decisions file held to
the code, the safe-defaults switches, the sign-in limit, and the other sessions' work. Each fault that is
reproduced goes here as its own item, with how it was seen; those in this session's own work it fixes, and the rest
it leaves for their owners to claim. **Claimed on 6 October 2026 by session securevibe-e2**, at the owner's word, in
branch `claude/securevibe-e2-review-6oct`.
**What it found, 6 October 2026.** Four reviewers read the changes in four parts. Each fault below was then
reproduced by running `sv` on a small app made for it, or confirmed by reading where noted; nothing here is a
reviewer's word alone. Numbered so each can be claimed on its own. Items 1 to 9 are in this session's own work and
are **claimed by session securevibe-e2** in this branch; items 10 onward came from other sessions' work and are
**not claimed**.
1. **The MCP server reads a `securevibe.toml` that is a link to a file outside its root, and quotes it to the AI
   tool.** Reproduced: `app/securevibe.toml` linked to a file outside the root holding `API_KEY="…"`;
   `securevibe_preflight`, `securevibe_check`, and `securevibe_plan` each answered with the parse error, whose
   snippet shows the whole line, value included. Reports, notes, and bundles already refuse a link; the manifest,
   `security-notes.md`, and `design-decisions.md` are read through one.
   **Part status:** done, with the item
2. **A text file whose first bytes spell an image or font signature is skipped, and the secrets scan is still
   credited** (H22's signatures). Reproduced: a `.env` starting `IMG_FMT=WEBP` with a key on the next line;
   `secrets.scan` credited, the file listed as "images, fonts, or other files that hold no text". `WEBP` is
   accepted at byte 8 without `RIFF` at byte 0, and `OTTO`, `wOFF`, `wOF2` are plain letters.
   **Part status:** done, with the item
3. **`manifest-version = 0` is read as version 1**, and a newer version with a field only it has is told to move
   the field rather than that the version is unknown (improvement 6). Confirmed by reading `sv-manifest/src/lib.rs`.
   **Part status:** done, with the item
4. **`security.md` prints the decisions file's "When to bring in a person" text, and other app text, unescaped.**
   The gaps, the false-alarm lines, and the reviews not counted are written raw, so a Markdown image or HTML in them
   renders; the decisions-file gap is a new path for it. compliance.md and report.html already escape these.
   Confirmed by reading `sv-report/src/markdown.rs`.
   **Part status:** done, with the item
5. **`probe.action-done-twice` credits V2.3.4 when one user's copies went through more than once and the other's
   were refused for a reason of its own.** Ten "Booked" answers to the first user are taken as repeats of one
   booking; nothing shows the second user could have taken it. Confirmed by reading `signed_in/once.rs`.
   **Part status:** done, with the item
6. **A sign-in the limit refused, other than the first user's, cites the first user's requirements as not run.**
   When nothing was credited, the gap names V8.2.1 and the rest, whose checks ran on a session the limit did not
   refuse. Confirmed by reading `signed_in/mod.rs`.
   **Part status:** done, with the item
7. **A sealed review of a `decisions.not-held-to` finding can never apply**, and the report says nothing looked for
   its kind: the finding is made after the reviews are applied. Confirmed by reading `sv-cli/src/main.rs`.
   **Part status:** done, with the item
8. **A safe-defaults line written another way (`- **debug mode**: off`) is skipped without a word**, neither held to
   the app nor listed as unreadable. Confirmed by reading `sv-check/src/decisions.rs`.
   **Part status:** done, with the item
9. **A `planned` answer says "the app has no code yet" for an app in a language `sv` cannot read**, since
   `files_read` counts only languages it reads. Confirmed by reading `sv-cli/src/main.rs`.
   **Part status:** done, with the item
10. **The browser checks no longer see an injected script run** (S11). The driver now evaluates in a world of its
    own, which shares the page but not its JavaScript globals, and the cross-site scripting check reads
    `window.sv_<token>`, set in the page's world. So `ran` is always false: a script that runs is reported as
    stopped by the page's policy, at medium rather than high, and a page that runs it but drops the marker
    attributes is not found at all. Confirmed by reading `sv-run/assets/browser-driver.mjs` and
    `sv-check/src/browser.rs`; not run, as this machine has no Docker. The real-browser test reads only
    `document.title`, which both worlds share.
   **Part status:** done, 6 October 2026
11. **A committed secrets file in a folder with an accented name is not seen** (ADR-032's `git.rs`). Reproduced:
    `données/secrets.json` committed, and `config.secrets-file-committed` silent, where `data/secrets.json` is
    found. `git ls-files` quotes such paths; `-z` would not.
   **Part status:** done, 6 October 2026
12. **A `.gitignore` that ignores `.env` is taken as covering `.env.production`.** Reproduced: `.env.production`
    at the root, `.gitignore` holding `.env`, and `config.gitignore-covers-env` credited.
   **Part status:** done, 6 October 2026
13. **The password-guessing check sends two attempts past the limit and reads the status of one** (H16), so the
    evidence can say "answered 200 every time" when the last answer was 429. Confirmed by reading
    `signed_in/signin.rs` and `signed_in/codes.rs`.
   **Part status:** done, 6 October 2026
14. **The preflight's seed check matches `SV_ADMIN` inside `SV_ADMIN_PASSWORD`**, so a seed that hard-codes its
    admin's name is said to read the accounts. Confirmed by reading `sv-cli/src/preflight.rs`.
   **Part status:** done, 6 October 2026
15. **`inert` pairs backticks across a blank line or a list item**, where Markdown ends the code span, so HTML after
    them is left live (R13). Confirmed by reading `sv-report/src/markdown.rs`.
   **Part status:** done, with the item
16. **Three SARIF texts carry a stray backslash and a run of spaces**, from `\\` at a line end in
    `sv-report/src/sarif.rs`. Valid SARIF, garbled words. Confirmed by reading.
   **Part status:** done, 6 October 2026
17. **Smaller, suspected or narrow:** the report seal hashes the files as read back from disk, not the bytes `sv`
    wrote, so a write in that moment would be sealed (suspected, a race); `prod.env.local` and the like go into a
    bundle (confirmed by reading `bundle.rs`).
   **Part status:** done, 6 October 2026
**Items 1 to 9 and 15 done on 6 October 2026 by session securevibe-e2** (DESIGN, "The review of 5 and 6 October:
what it found, and what of it was fixed"); 15 was taken with 4, being in the same function. Items 13, 14, 16, and
17 are not claimed.
**Items 10, 11, and 12 claimed on 6 October 2026 by session securevibe-e2**, at the owner's word ("take the false
passes next"), in branch `claude/securevibe-e2-false-passes`.
**Items 10, 11, and 12 done the same day** (DESIGN, "Three false passes from the review of 5 and 6 October"). Item
10 was shown fixed in Chromium here; its test runs only where Docker does, on CI.
**Items 13, 14, 16, and 17 claimed on 6 October 2026 by session securevibe-e2**, at the owner's word ("take the
remaining review items next"), in branch `claude/securevibe-e2-review-rest`.
**Items 13, 14, 16, and 17 done the same day** (DESIGN, "The rest of the review of 5 and 6 October"). Every item of
this review is done.
