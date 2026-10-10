# False alarms, part 2: a person's record that a finding is a false alarm, or an accepted risk

**Status:** done, 9 October 2026

From the same investigation. **The owner's decisions, 27 September 2026, each as recommended:**
1. Build it: a section in `securevibe.toml` where a finding is set aside with a verdict, who decided,
   the date, and a written reason.
2. Two verdicts: *false alarm* (the code is fine) and *accepted risk* (a real problem the owner
   chooses to live with for now).
3. The AI coding tool may propose one, and only a person's word counts. An entry the tool wrote is
   shown as the tool's opinion, the finding still counts, and the interview asks the owner to confirm
   it. (The rules the tool follows already say it must never weaken a check.)
4. A false-alarm verdict lapses when the flagged line changes; an accepted risk after 90 days; a
   lapsed entry is listed, never dropped quietly. A key or password found by the secrets scan may be
   set aside as a false alarm, but only with a stricter reason.
5. Part 1 first.
In the report, a finding set aside moves to its own section with its reason; its requirement goes
back to *not verified*, never to *checked*, since dismissing a finding does not show the protection
is there; an accepted risk stays under *needs attention*, labeled as known and accepted. The SARIF
`sv` writes marks it as suppressed, with the reason, so GitHub's Security tab agrees with the report.
Findings are matched by rule, file, and a fingerprint of the flagged line's text, never the text
itself, so a flagged key is never copied into the file. **Claimed the same day by session
securevibe-e2**, to follow part 1. **Done the same day:** see DESIGN, "False alarms: a person's record that a
finding is wrong, or accepted". One choice beyond the five decisions: a key or password cannot be an
accepted risk, since a real one is replaced and one that is not real is a false alarm.

**Marked done 9 October 2026 by session securevibe-e2**, from the roadmap (Phase 5): every part was built and recorded already (see the done notes above); the status line read the numbered decisions or proposals as parts still open.
