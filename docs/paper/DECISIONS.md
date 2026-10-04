# Who proposed, and who chose

The major decisions in SecureVibe's first nineteen days, and for each one who first put it forward and who made the
final call: the owner, or an AI session. Every quotation is from the Claude Code session transcripts on the owner's
machine or from the repository, and was checked against its source. Times are Eastern. The figure is
`figure-decisions.html`.

The record runs to **11:37 on 4 October 2026** (`main` at `157ddc3`, Merge PR #564). The first version ran to 28
September and held decisions 1 to 23; 24 to 36 are new. **From 28 September the record is thinner.** The sessions
that did most of the later work in `sv`, securevibe-e2 and securevibe-e9, left no transcript on this machine, so for
their decisions the source is the backlog and the pull requests, written by those sessions: an entry that says "the
owner's decision" or "at the owner's word" is an AI session's account of what the owner chose, not the owner's words.
Three transcripts from that week are here and are quoted: securevibe-e10's (`be11807a`, the `loadonce` worktree),
practical-banach's (`2c599697`), and the cato-pipeline session's (`2a329d0f`), a session on the owner's other
project that wired `sv` into it, ran the comparison study, and wrote the deep review.

## The count

**36 decisions. The owner made the final call on 32, an AI session on 3, and one was split** (23, with 19, 3, and 1,
to 28 September). All 13 of the new week's final calls were the owner's; 8 of the 13 were first proposed by an AI
session.

| Proposed by | Chosen by the owner | Chosen by an AI session | Split | Total |
|---|---|---|---|---|
| The owner | 8 | — | — | 8 |
| Both: the owner raised the need, the AI shaped the answer | 13 | 1 | — | 14 |
| An AI session | 11 | 2 | 1 | 14 |
| **Total** | **32** | **3** | **1** | **36** |

**Of the 35 questions in which Claude offered a recommended option, the owner took it 28 times** (24 of 29 to 28
September). Of the other seven, the owner chose a different option four times (any AI provider instead of Anthropic
only; anonymizing a friend's app named in the docs before the repository went public; on 3 October, prompts both in a
document and in `sv` rather than "In sv itself (Recommended)"; and "Test each first" rather than "Label untested
(Recommended)"), wrote an answer of their own once, and dismissed the question twice. Three more questions to 28
September, and one after, offered no recommendation. The count is of questions asked with marked options, in
SecureVibe's own sessions, from every recorded answer in the transcripts on this machine.

**What the count cannot see.** After 28 September it covers securevibe-e10's six questions only. Securevibe-e2 and
securevibe-e9 asked the owner questions too, and the backlog records some answers as "each as recommended" or "your
recommendation", but without their transcripts the questions cannot be counted, so the 35 is a count of what
survives, not of what was asked. Outside the count:

- **The cato-pipeline session** asked nine questions with a recommended option, about using `sv` in that project,
  its home lab, and refreshing this paper; the owner took all nine. Two are decisions about `sv` itself (24 and 25 below).
- **Recommendations in prose.** Securevibe-e10 also recommended in plain text, not as marked options, at least five
  times in the new week, and the owner took each: merging #412 (26), staying with Semgrep (29), and three of the four
  choices about compressed archives (31; the fourth offered no recommendation).
- **The owner's own app builds** (my-first-app, family-hub) asked nine questions with a recommended option about the
  apps, all taken. They are decisions about the owner's apps, not about SecureVibe.

## The decisions

Sessions are named by the first eight characters of their transcript: `f9546362` is the first session (16–17
September), and `52d57cb8` is a copy of it that also kept the messages typed while Claude was working; `8f6124d7` is
the main v1 session from 18 September; `aa9c3531` is the recipe-library session; `2c599697` is the `sv` session;
`be11807a` is a later v1 and paper session, which from 28 September signed itself securevibe-e10; `e168a8a6` is the
session that wrote the first version of this; `2c599697` is also practical-banach-b1faa1; and `2a329d0f` is the
cato-pipeline session.

| # | Decision | When | Proposed by | Chosen by |
|---|---|---|---|---|
| 1 | Build SecureVibe: a wizard that turns answers into a checked app | 16 Sep 14:14 | **Owner**: "walks a user through providing all the information needed" (`f9546362`) | **Owner** |
| 2 | v1's foundations: a hardened template, TypeScript, the Node permission model (ADR-001 to 005, 007 to 010) | 16 Sep, by 15:05 | **AI**: ten records written in the first session | **AI**: no question to the owner was found |
| 3 | Evidence tiers: AI review never counts as verified (ADR-006) | 16 Sep, by 15:05 | **AI**: "AI opinions never count as verified" | **AI**: no question to the owner was found |
| 4 | A spending cap, with writing the app limited to 55% of it | 17 Sep 12:07–12:17 | **Both**. Owner: "ensure that $5 of credits will cover any build" (`52d57cb8`, 12:07). AI: "writing the app may use up to 55%" (12:16) | **AI**: the owner set the goal, and no approval of the split was found |
| 5 | Any AI provider, with keys kept in `.env` | 17 Sep 18:58–18:59 | **Owner**: "their own API key for any AI service" | **Owner**: chose "Any provider" over Claude's "Anthropic key only (Recommended)" |
| 6 | The optimization program: `CLAUDE.md`, plan then build, builds as durable jobs | 17 Sep 19:48–19:58 | **Both**. The owner asked for optimizations; the AI listed them, "Builds as durable jobs (highest value)" first (19:49) | **Owner**: "I like all these optimizations." (19:58) |
| 7 | The evaluation harness and golden apps | 17 Sep 19:48–19:58 | **Both**. Owner: "build out/refine a harness" (19:48). AI: "An evaluation harness" with golden apps (19:49) | **Owner**: "and the evaluation harness and golden apps" (19:58) |
| 8 | The recipe library | 17 Sep 16:14 to 18 Sep 17:52 | **Both**. The owner raised a skill library for SecureVibe (16:14); the AI made it "a library of *tested recipes*" (19:49) | **Owner**: "spawn a second workflow to work on the recipe library" (`8f6124d7`, 18 Sep 17:52) |
| 9 | A network fence for generated code | 17 Sep 19:49 to 18 Sep 09:42 | **AI**: "Node's permission model, which doesn't restrict the **network**", closed by "macOS `sandbox-exec`, or a container" (19:49) | **Split**. The owner chose the goal, "containerizing to fix Node's permission model not restricting the network" (19:58); the AI chose the form, `sandbox-exec` on macOS and a network namespace on Linux (`8f6124d7`, 18 Sep 09:42) |
| 10 | Git work is pre-approved, except for a list of things that always need asking first | 18 Sep 23:40–23:47 | **Owner**: "Can I pre-approve the PR" (23:40); the AI drafted the exceptions | **Owner**: "yes, put it in the file so it sticks" (23:46); committed as `0d56fcb` |
| 11 | Backlog items are claimed in `docs/BACKLOG.md`, not in messages | 20 Sep 12:14–12:18 | **AI**, after two sessions built the same recipe: "A struck-through line in `docs/BACKLOG.md` … Want that added?" (12:14) | **Owner**: "adding that to the BACKLOG.md file is a good idea" (12:17); `7c692b5` |
| 12 | "Break your own rule" goes into `CLAUDE.md` | 20 Sep 14:17–14:18 | **Both**. The practice was the AI's; the owner asked "is it worth capturing that lesson learned" (`aa9c3531`) | **Owner** asked for it, and the AI wrote the wording; `67e29b5` |
| 13 | An upload that cannot be checked for malware is refused (ADR-014) | 20 Sep 12:00–12:02 | **Both**. Owner: "any files uploaded should HAVE to go through ClamAV" (12:00). The AI offered "Refuse the upload (Recommended)" (12:01) | **Owner**: chose "Refuse the upload" (12:02) |
| 14 | Other languages are checked by outside tools only (ADR-012) | 20 Sep 15:40–16:01 | **Both**. The owner asked to support more languages; the AI recommended no rules of SecureVibe's own | **Owner**: "I do NOT want to write any custom rules for other languages." (16:01) |
| 15 | Start `sv`: a second version, language-agnostic, in Rust | 22 Sep 21:46–21:50 | **Owner**: "programming-language-agnostic", in Rust (`2c599697`, 21:46) | **Owner**, who also took all four of the AI's recommended designs, such as "Agent-written manifest, then corroborated (Recommended)" (21:48) |
| 16 | `sv` writes its own rules after all (ADR-018, reversing ADR-012) | 23 Sep 23:38 to 27 Sep 13:42 | **AI**: "I'd take tree-sitter next" (23:38) | **Owner**: "go ahead with tree-sitter" (23:43), and "I accept this ADR" four days later (`be11807a`, 27 Sep 13:42) |
| 17 | Move `sv` to the top of the repository and archive v1 | 26 Sep 19:37–19:59 | **Owner**: "would it be possible to archive v1" (19:37); the AI proposed the tags | **Owner**: "v1-paper can go on 7fa07d6, yes" (19:59) |
| 18 | Use Semgrep's rules despite their license | 26 Sep, answered 16:49 | **AI** raised the license as a question it could not answer | **Owner**: "acceptable as long as we are not monetizing/selling anything" (`2c599697`, 16:49) |
| 19 | PDF reports that SecureVibe writes itself (ADR-013) | 17 Sep 10:59 to 25 Sep 16:03 | **Both**. The owner asked for PDF export; the AI suggested "a setting in Settings, defaulting to Letter" (`be11807a`, 16:02) | **Owner**: "a PDF download that does not depend on the user's browser, agreed" (15:29); "Build it as a setting, default Letter please" (16:03) |
| 20 | The paper, and its thesis | 20 Sep 18:01–18:04 | **Owner** listed what the paper needs (18:01) | **Owner** wrote the thesis instead of picking an option: a UI "with a secure foundation based on SbD, ASVS, and AISVS provides a safer way to vibe code" (18:04) |
| 21 | A self-assessment of `sv` | 27 Sep 15:08 | **Owner**: "we should probably do a self-assessment now for v2" (`e168a8a6`) | **Owner** |
| 22 | The three-arm study: native, uploaded, and a Python app | 20 Sep 17:11 | **Both**. The owner wanted a comparison; the AI pointed out "Your comparison changes two things at once" and added an arm | **Owner**: "All three (Recommended)" |
| 23 | Make the repository public, under the MIT license | 20 Sep 19:38–19:46 | **Both**. Owner: "I could also make the repo public" (19:38); the AI recommended MIT | **Owner**: "MIT (Recommended)", and anonymizing a friend's app named in the docs (19:46) |
| 24 | Use `sv` in the owner's other project, cato-pipeline, and move that project to `sv` rather than v1 | 28 Sep 16:30–16:54 | **Both**. Owner: "I would like to consider how SecureVibe … can be integrated as well" (`2a329d0f`, 16:30). AI: "Yes, switch to v2 (Recommended)" (16:54) | **Owner**: took the recommendation |
| 25 | `report.json` says what was examined, in a form a program can read | 28 Sep 16:54 to 17:17 | **AI**: "Add a field to sv (Recommended)", so that cato closes an item only when its check ran (`2a329d0f`) | **Owner**: took it; the cato session built it in `sv` itself (#388) |
| 26 | A claim made twice: the finished work stands, and the earlier claim stands down | 28 Sep 20:47–20:50 | **AI** (securevibe-e10): "Merge #412, and e2 stands down … **My recommendation**" (`be11807a`) | **Owner**: "go with option 1, merge #412" |
| 27 | The comparison study: several of the owner's own apps, run through a pipeline | 29 Sep 17:11–17:56 | **Both**. Owner: "I have the source code for several apps that I want to test and compare for the paper I'm writing on sv" (`2a329d0f`, 17:11); the AI designed the run | **Owner**: "go with A, build the pipeline and run all three please" (17:56) |
| 28 | Raise `sv probe`'s limit from four requests to five, for OCSP stapling | 29 Sep 21:45 | **AI**: "Raise the cap to five (Recommended)" (`be11807a`) | **Owner** took it; then the AI found it unneeded ("Counting again showed that was wrong", #465), and the limit in `CLAUDE.md` stayed at four |
| 29 | Stay with Semgrep, quiet its usage reporting, and use Opengrep when Semgrep is absent | 29 Sep 22:42 to 3 Oct 10:13 | **AI**: "stay with Semgrep, and let `sv` use Opengrep when Semgrep isn't installed" (`be11807a`, 29 Sep 22:42) | **Owner**: "I agree with your recommendation to stay with semgrep" (3 Oct 10:13); #481 |
| 30 | Run the app under test in a read-only container | 29 Sep 21:55 to 3 Oct 11:58 | **AI**: the first weekly review of the decision records found the container was not read-only (securevibe-e2, #464) | **Owner**: "yes, go ahead with the read-only container" (`2c599697`, 3 Oct 11:58); #496 |
| 31 | Check compressed-archive bombs (V5.2.3), with the limits stated by the owner, never by `sv` | 3 Oct 14:04–14:07 | **AI** (securevibe-e10) set out four decisions and recommended an answer to three | **Owner**: "decision 1 - build the check and test it all; decision 2: your recommendation; decision 3: your recommendation; decision 4: your recommendation" (`be11807a`) |
| 32 | A library of prompts for the AI coding tool, in SecureVibe's own words, each tested before it is called working | 3 Oct 10:58 to 4 Oct 09:28 | **Both**. The owner asked for it after a review of `sv` against the CSA guide (#476; "prompt library, please", `be11807a`, 3 Oct 20:14); the AI recommended "Our own words" | **Owner**: took "Our own words", chose "Test each first" over the AI's "Label untested", and then kept the untested ones: "let's still include them in the prompt library with a note they haven't been tested" (4 Oct 09:28) |
| 33 | Running-app checks that attack the app: SQL injection, and sign-in tokens altered or unsigned | 3 Oct 10:18 to 20:37 | **AI**: securevibe-e9's review of the running-app checks, at the owner's asking (#471). Securevibe-e9 released both items unbuilt; securevibe-e10 declined the SQL item after "Part of my response was blocked by a safety check" (`be11807a`, 20:12) | **Owner**, recorded by securevibe-e2 (#534): SQL injection "yes, limited" to requests that only read, on the copy of the app `sv` starts itself; tokens yes, without the forms that need a key server |
| 34 | A tool that records the person's answers, every one marked as the AI tool's own | 3 Oct, recorded 20:37 | **AI**: proposed by securevibe-e2 among its MCP server improvements, at the owner's asking to look at the server (backlog) | **Owner**, recorded by securevibe-e2 (#534): "build it", with no answer counted as the owner's unless the owner confirms it |
| 35 | A deep review of `sv` by a session outside the project | 4 Oct 09:15–09:52 | **Owner**: "Can you do a deep review of sv and report any issues you find and suggest improvements?" (`2a329d0f`, 09:15) | **Owner**: "yes, send them all" (09:52): 58 findings into the backlog |
| 36 | Prompts for decisions made before any code, from the Secure by Design checklist | 4 Oct, by 09:24 | **Both**. The owner asked securevibe-e2 to look at the checklist for prompts; it proposed fifteen (#548) | **Owner**, as the backlog records it: "all the suggestions, yes. The testable batch first" |
## What this shows

The first four points were written on 28 September and still hold; the last three are about the new week.

- **The owner set the direction, and the AI supplied the mechanisms.** Everything about what SecureVibe is came from
  the owner: the product (1), any provider (5), `sv` (15), the move to the top of the repository (17), the paper
  (20), and the self-check (21). Nearly every mechanism was the AI's: the template, the evidence tiers, the form of
  the network fence, the budget split, claiming work in the backlog, and writing rules with tree-sitter.
- **The AI's influence came through the options more than through final calls.** It made only three final calls of 36,
  but the owner took its recommended option in 28 of 35 questions. Whoever writes the choices, and marks one of them
  recommended, decides a great deal of what gets chosen. A reader weighing "the owner chose" should keep that in mind.
- **The three decisions no one put to the owner were the foundations (2, 3, 4).** The first session wrote ten
  decision records in its first hour, and none of them was asked about. One of them, the evidence tiers (ADR-006),
  became the rule the whole project is judged by. It was a good rule, but the owner never made it.
- **The owner's firmest rulings changed the design.** "I do NOT want to write any custom rules" (14) held for three
  days. It was then reversed in practice by an AI recommendation the owner accepted (16), and the record caught up
  four days after that. The first time the owner overrode a recommendation (5) meant three AI providers had to be
  supported instead of one.
- **In the new week the owner made every final call, and most of the proposals were the AI's.** Of 13 decisions, the
  owner proposed one outright (the deep review, 35) and named the need in four; an AI session proposed the other
  eight. What the owner kept for themselves was scope: what may be attacked and how hard (31, 33), what counts as
  the owner's word (34), and when a prompt may be called working (32).
- **A recommendation the owner accepted could still be wrong, and the AI caught it.** The owner agreed to raise
  `sv probe`'s request limit (28), a rule written into `CLAUDE.md`; the session then counted again, found the fifth
  request unneeded, and kept the limit. Taking the recommended option is only as safe as the count behind it.
- **The owner's firmest choices went against the recommendation in the direction of more proof.** Of the two
  recommendations not taken after 28 September, one asked that every prompt be tested before it shipped rather than
  labeled untested (32). When testing showed some could not be proven, the owner kept them, labeled, which is close
  to where the recommendation started.

## Limits

- **"Proposed by" is who put it in writing first in the transcripts.** An idea discussed before a session was
  recorded, or in a session whose transcript is lost, would be missed.
- **"Chosen by the AI" means no question or approval from the owner was found**, not that the owner was asked and
  refused. The first session asked the owner nothing about design.
- **"Both" is a judgment.** It is used where the owner named the need and the AI named the answer.
- **The 36 are the decisions that shaped the product, the process, or the paper.** Many smaller choices were made
  every hour, mostly by the AI, and are not counted.
- **The transcripts are not in the repository**, and the first session's contains a credential, so they cannot be
  published as they are.
- **From 28 September, decisions made with securevibe-e2 and securevibe-e9 are known only from the backlog and pull
  requests those sessions wrote** (33, 34, and 36; for 30, the owner's answer is quoted from a transcript, `2c599697`,
  as its row says). "Proposed by" for them is the session the
  entry names; the owner's words are not on record, and none can be quoted except where the entry quotes them.
- **Dates in the backlog are sometimes a day later than the Eastern time.** The decisions the backlog dates "4
  October" in #534 were recorded at 20:37 on 3 October, Eastern.
- **The 35 recommended options are those that survive.** See "What the count cannot see" above.

## After the cut-off

Two more decisions were made on the afternoon of 4 October, after the cut-off, and are not in the table. The owner chose
to build `sv review`, with what the owner records sealed by a key kept outside the app's folder, and the record kept in
`securevibe.toml` rather than outside it; and then to give the owner's own answers the same rule. Both extend decision
34, and both are recorded in ADR-026. The owner also confirmed on 4 October that the paper keeps the friend's health
app anonymous, as decision 23 did for the repository; the paper was corrected after the cut-off (#591, #606). `SINCE-THE-CUTOFF.md` has the rest.
