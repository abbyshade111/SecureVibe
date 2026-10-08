# Three false passes from the review of 5 and 6 October (6 October 2026)

Items 10, 11, and 12 of that review, at the owner's word ("take the false passes next"). Each credited something
`sv` had not seen.

- **The browser sees an injected script run (item 10).** Since S11 the browser driver asks its questions in a world of
  its own, which shares the page and its storage but not the page's script variables. The cross-site scripting check's
  line set `window.sv_<token>` when its script ran, and the question read that variable, so from the driver's world it
  was never set: a script that ran was reported as stopped by the page's policy, at medium rather than high, and one
  whose marker attributes the page dropped was not found at all. The script now leaves its mark on the page itself
  (`data-sv-ran` on the root element), which both worlds see. Shown in Chromium on this machine with the driver's own
  steps (`Page.createIsolatedWorld`, then `Runtime.evaluate` in it): the old mark read false and the new one true, where
  the page's own world read true for both. The real-browser test, which CI runs with Docker, now types the check's own
  line into a page that echoes it unescaped and asserts it ran; it cannot run here, where there is no Docker.
- **Names git quotes (item 11).** `git ls-files` puts a name holding an accented letter, a quote, or a backslash in
  quotes with escapes, so `données/secrets.json` was read as `"donn\303\251es/secrets.json"` and its file name as
  `secrets.json"`, and the committed secrets file was not found. `ls_files` now asks for `-z`, names ended by a zero
  byte and given as they are.
- **Every environment file left out (item 12).** A `.gitignore` passed when it left out `.env`, with
  `.env.production` beside it not left out. It now passes only when `.env` and every environment file at the root are
  left out, templates such as `.env.example` apart, and the finding names the one that is not.

Broken on purpose: items 11 and 12 five ways, each caught (the accented-name test, and the new git test, among
others). Item 10's guard is caught only by the Docker test, so on CI; here the break was shown in the browser instead.
