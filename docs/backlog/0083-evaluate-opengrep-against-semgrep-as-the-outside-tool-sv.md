# Evaluate Opengrep against semgrep as the outside tool `sv --tools` runs. Done on 29 September 2026: measured; the recommendation below is the owner's to decide

**Status:** done, 3 October 2026

Asked for by the owner on 28
September 2026. **Claimed on 29 September 2026 by session securevibe-e10**, at the owner's asking, on a machine
that reaches GitHub's releases and semgrep.dev (checked the same day), in branch `claude/opengrep-evaluation`. Opengrep is the open-source fork of semgrep's engine, made in January 2025 when
semgrep moved some of its features and rules behind its own license. `sv` runs semgrep today (`data/adapters.json`,
`data/semgrep-packs.json`, `tools/semgrep_packs.py`), so the question is whether to switch, offer both, or stay.
Things to find out, each written down with how it was measured rather than recalled:
1. **Rules.** Which of the packs `sv` runs (`data/semgrep-packs.json`) Opengrep can load and run, under what
   license each is published, and whether the rules mapped in `data/adapters.json` give the same findings. Run
   both over the same apps (`examples/` and a few fixtures) and compare rule ids, files, and lines.
2. **Output.** Whether its SARIF is what `adapters::parse_sarif` reads, rule ids and levels included, and whether
   `clean_run_evidence` would credit the same requirements.
3. **Installing it.** How an owner who is not a programmer installs it on a Mac and on Linux, whether it is one
   file with no account or sign-in, and what the Docker image would need.
4. **Running it offline.** Whether it sends anything over the network by default (semgrep's metrics and rule
   downloads), since `sv` promises no network connection of its own, and how to turn that off.
5. **Speed and upkeep.** Time over the same apps, how often it is released, and who maintains it.
The result is a recommendation in this item, with the numbers, for the owner to decide; nothing in the adapters
changes until then.
**Measured on 29 September 2026 by session securevibe-e10**, on the owner's Mac (macOS, Apple silicon), semgrep
1.176.0 from Homebrew against Opengrep 1.30.0, the release of 7 September, downloaded from
`github.com/opengrep/opengrep/releases` at the owner's yes. Its signature was checked against its certificate
(Sigstore, naming `opengrep/opengrep`'s `rolling-release.yml` on `main`); its entry in Sigstore's public log was not
checked, for want of `cosign`. Nothing in `sv` was changed. What was found, by question:
1. **Rules. The same, because they are the same rules.** Opengrep fetches `p/security-audit`, `p/default`, and
   `p/ai-best-practices` from semgrep.dev exactly as semgrep does, and both loaded the same 1,114 rules. Handed
   each app's code files by name, as the adapter does, the two gave identical findings, by rule, file, line, and
   level, on all seven targets: the fixture app (28 each), the five example apps (0 or 1 each), and the owner's
   SecureFit app (98 files, 3 each). Opengrep's own rules repository, `opengrep/opengrep-rules`, was archived in
   November 2025, so the rules are semgrep's whichever engine runs them, under the Semgrep Rules License that
   semgrep.dev still serves (use "only for your own internal business purposes", no distributing, no offering
   them as a service). **Switching engines does not change the license question the owner settled on
   26 September.** One difference in defaults, found by accident: given a folder, semgrep leaves out paths such
   as `tests/` and Opengrep does not, so run over `tests/fixtures/semgrep/app` as a folder semgrep found nothing
   and Opengrep found 28. The adapter hands files by name, so it is not affected.
2. **Output. `sv` cannot tell them apart.** With a stand-in named `semgrep` that runs Opengrep, `sv report
   --tools` on the Flask example and the fixture app gave reports identical to semgrep's: the family `ran`, the
   list of files scanned (`--json-output`) accepted, the same findings (4 and 37), the same status for every one
   of the 240 and 141 requirements, the same credits, the same counts. `semgrep --version` through the
   stand-in answers `1.30.0`.
3. **Installing.** Opengrep is one file with no account or sign-in. Its documented install is a script piped
   from GitHub (`curl … install.sh | bash`) that puts it in `~/.local/bin`, checks its signature only when
   `cosign` is installed, and otherwise installs it anyway with a warning. It is not in Homebrew. Semgrep is in
   Homebrew (`brew install semgrep`, at 1.176.0 there while 1.178.0 is out) and in pip, and needs Python. For the
   Docker image Opengrep publishes a single Linux file per processor; whether it runs in the image's
   `debian:trixie-slim` with nothing added was not measured.
4. **Running offline.** With rules from a local file and the network denied, both ran and found the planted
   finding; with the network on, neither opened any connection in three runs each (connections sampled ten times
   a second, which can miss a very short one). With the registry packs, both need the network, and fail without
   it. On the network, Opengrep was seen connecting to semgrep.dev only; semgrep to semgrep.dev and to one more
   server, an Amazon address in Oregon that is not semgrep.dev and not, that day, one of metrics.semgrep.dev's.
   Semgrep has `--metrics=off` and prints "A new version of Semgrep is available", so it checks; Opengrep has no
   metrics option at all, and its binary names no metrics address. An attempt to log each denied connection
   failed its own control and is not counted.
5. **Speed and upkeep.** On an idle machine, median of three runs, the packs fetched each time: 4.5 to 5.5 seconds
   an app for either on the small apps, and on SecureFit 7.7 seconds for semgrep against 7.0 for Opengrep; most of
   it is fetching the packs. Semgrep: 16,800 stars, 23 authors among its last 100 commits, a release about every
   one to two weeks, backed by one company. Opengrep: created December 2024, 3,100 stars, a stable release every
   one to three weeks (1.25 to 1.30 between 1 July and 7 September), a 2.0 series in alpha that drops its Python
   layer, and its last 100 commits from two people, with a consortium of AppSec companies behind it. Both engines
   are LGPL 2.1.

**Recommendation from session securevibe-e10: stay with semgrep as what `sv --tools` runs, and accept Opengrep as a
stand-in when semgrep is not installed.** On everything `sv` depends on they are the same: the same rules, under the
same license, and a report `sv` reads identically. What separates them is not what `sv` sees. Opengrep sends
nothing beyond fetching the rules, where semgrep makes one more connection; but Opengrep is two people's work
today, is not in Homebrew, and installs by a piped script that skips its own signature check unless `cosign` is
there, which is a harder thing to hand an owner who is not a programmer than `brew install semgrep`. Accepting it
as a stand-in is small: the adapter tries `opengrep` when `semgrep` is not found, and the report names which ran.
Separately, and whatever is chosen, semgrep's extra connection is worth one more look: `--metrics=off` in the
adapter's arguments, and `SEMGREP_ENABLE_VERSION_CHECK=0` in its environment, would say whether either is it.
The decision is the owner's; nothing in the adapters has changed.

**The extra connection, looked at on 3 October 2026 by session securevibe-e10, at the owner's asking.** Semgrep
1.176.0, `p/default`, one file, three runs each. With nothing switched off, every run reached semgrep.dev and one
more Amazon server in Oregon (a different one most runs). With `--metrics=off`, none of the three reached the second
server; with `SEMGREP_ENABLE_VERSION_CHECK=0` alone, all three still did, and only the "new version" notice went.
So the second connection is semgrep's usage reporting (metrics.semgrep.dev is itself a rotating set of Amazon
addresses in Oregon); the version check goes to semgrep.dev, where the rules come from. Every run of all twelve
loaded the same 1,074 rules and gave the same finding. Connections were sampled about fifty times a second, which
can miss a very short one.
