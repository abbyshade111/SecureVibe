# A key file committed once is still in the history (V13.3.1, 7 October 2026)

`config.secrets-file-committed` reported a file whose job is holding credentials (`.env`, `secrets.json`, a private key)
when git tracked it, using `git ls-files`, which lists what git tracks *now*. Its own fix says to stop tracking the file
(`git rm --cached`), and after that the next check said "Checked and fine" and credited V13.3.1, though every commit
that held the file still holds it, in every copy of the repository. GETTING-STARTED.md promised more ("the check for a
password or key that was ever saved into your project's history"). Found by the gap analysis (`docs/GAP-ANALYSIS.md`,
1.3), and reproduced by two of its reviewers.

**History is read now.** When no such file is tracked, the check asks git for every file ever added, in any commit on
any branch, under the app's folder (`git::ever_added`). A file found there is a finding of its own, critical as the
other: "A file that holds credentials was committed, and is still in the history". Its fix leads, as the other's does,
with changing every credential that was in the file, which is what protects the owner and is enough on its own;
rewriting the history is named as a step to take only with someone experienced, never instead.

**What is not credited any more.** V13.3.1 is credited only when neither the tracked files nor the history holds such a
file. A history git could not read is "not assessed", and so is a shallow copy (a repository holding only its newest
commits, as a CI checkout often does), which says so and how to fetch the rest.

**More names.** Firebase's and Google Cloud's server key as their guides name it (`serviceAccountKey.json`), a Firebase
admin key as the console names its download (`…-firebase-adminsdk-….json`), Cloudflare Workers' local secrets
(`.dev.vars`), and Rails' `master.key`, which unlocks its encrypted credentials.

**Running git safely.** `git log` can run a program the repository's own config names, where `ls-files` cannot: with
`log.showSignature` on, it checks each shown commit's signature with `gpg.program`. ADR-032's "Later, 7 October 2026"
says what is switched off on the command line, and the test that plants the program and watches for its mark.

**Break and watch.** Seven guards broken in turn:
- the history not read (two tests red: the untracked file, and the shallow copy that then passed);
- the shallow copy not looked at (its test);
- `--relative` dropped (the test of an app in a subfolder, whose sibling's file then counted);
- the Firebase name pattern dropped (the names test);
- both signature overrides dropped (the planted-program test).

Dropping one signature override alone is not caught, because the other still stops the program: two guards for one
hole, kept on purpose. The planted-program test was first written with a signed commit that added no file. `git log
--diff-filter=A` never shows such a commit, so the overrides could be removed with nothing turning red. The commit now
adds a file, and the test's control runs `sv`'s own `git log` without the overrides and sees the program run.
