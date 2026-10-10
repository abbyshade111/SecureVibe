# Keep the breached-password evidence current through the Pwned Passwords API

**Status:** done, as its markers read on 8 October 2026

Asked for by the
owner on 26 September 2026. V6.2.12's sign-up probe tries `1qaz2wsx3edc4rfv`, and the only record
that it is a breached password is one range file the owner fetched in a browser and pasted into
the session that day, because this environment's network policy refused
`api.pwnedpasswords.com`. The owner has since added that host to the allowed domains, which takes
effect for sessions started after the change. Three things to do once a session can reach it:
a small script under `tools/` that re-fetches the range for `BREACHED` and rewrites
`data/breached-password-evidence.json` with the new count and date; a sampled check of
`data/knowledge/common-passwords.txt` (a few hundred entries across its ranks), so the list's
source — recorded nowhere in the repository — is at least shown to be breach data; and a line
in the report's V6.2.12 wording that carries the date of the last check. Only the five-character
hash prefix is ever sent, and none of this runs inside `sv` itself: `sv` fetches nothing, and
this is maintenance of the repository's own data, done by whoever runs the script.
**Claimed on 26 September 2026 by session relaxed-nobel-27acfa**, which runs on a machine that
can reach the API. **Done the same day.** `python3 tools/pwned_passwords.py` re-checks the password
(still 133,732) and rewrites the evidence file, and the V6.2.12 wording is now built from that file,
so it says "when last checked, on <date>" without an edit to the code. `--sample` looked up 300
entries spread across the list's ranks: all 300 are in Pwned Passwords, with counts falling from a
median of 391,080 in the top thousand to 8,932 in the last band. Results in
`data/common-passwords-breach-sample.json`; see DESIGN, "V6.2.12, breached passwords". One thing
learned: inside the Claude Code sandbox the network proxy cuts Python's reads of these answers
short, where curl gets them whole; run outside it, every answer arrived complete.
