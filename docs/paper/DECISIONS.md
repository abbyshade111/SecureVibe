# Who proposed, and who chose

The major decisions in SecureVibe's twelve days, and for each one who first put it forward and who made the final
call: the owner, or an AI session. Every quotation is from the Claude Code session transcripts on the owner's machine
or from the repository, and was checked against its source. Times are Eastern. The figure is
`figure-decisions.html`.

## The count

**23 decisions. The owner made the final call on 19, an AI session on 3, and one was split.**

| Proposed by | Chosen by the owner | Chosen by an AI session | Split | Total |
|---|---|---|---|---|
| The owner | 7 | — | — | 7 |
| Both: the owner raised the need, the AI shaped the answer | 9 | 1 | — | 10 |
| An AI session | 3 | 2 | 1 | 6 |
| **Total** | **19** | **3** | **1** | **23** |

**Of the 29 questions in which Claude offered a recommended option, the owner took it 24 times.** Of the other five,
the owner chose a different option twice (any AI provider instead of Anthropic only, and anonymizing a friend's app
named in the docs before the repository went public), wrote an answer of their own once, and dismissed the question twice. Three
more questions offered no recommendation. This count is taken from every recorded answer in the transcripts.

## The decisions

Sessions are named by the first eight characters of their transcript: `f9546362` is the first session (16–17
September), and `52d57cb8` is a copy of it that also kept the messages typed while Claude was working; `8f6124d7` is
the main v1 session from 18 September; `aa9c3531` is the recipe-library session; `2c599697` is the `sv` session;
`be11807a` is a later v1 and paper session; and `e168a8a6` is the session that wrote this.

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

## What this shows

- **The owner set the direction, and the AI supplied the mechanisms.** Everything about what SecureVibe is came from
  the owner: the product (1), any provider (5), `sv` (15), the move to the top of the repository (17), the paper
  (20), and the self-check (21). Nearly every mechanism was the AI's: the template, the evidence tiers, the form of
  the network fence, the budget split, claiming work in the backlog, and writing rules with tree-sitter.
- **The AI's influence came through the options more than through final calls.** It made only three final calls,
  but the owner took its recommended option in 24 of 29 questions. Whoever writes the choices, and marks one of them
  recommended, decides a great deal of what gets chosen. A reader weighing "the owner chose" should keep that in mind.
- **The three decisions no one put to the owner were the foundations (2, 3, 4).** The first session wrote ten
  decision records in its first hour, and none of them was asked about. One of them, the evidence tiers (ADR-006),
  became the rule the whole project is judged by. It was a good rule, but the owner never made it.
- **The owner's firmest rulings changed the design.** "I do NOT want to write any custom rules" (14) held for three
  days. It was then reversed in practice by an AI recommendation the owner accepted (16), and the record caught up
  four days after that. The one time the owner overrode a recommendation (5) meant three AI providers had to be
  supported instead of one.

## Limits

- **"Proposed by" is who put it in writing first in the transcripts.** An idea discussed before a session was
  recorded, or in a session whose transcript is lost, would be missed.
- **"Chosen by the AI" means no question or approval from the owner was found**, not that the owner was asked and
  refused. The first session asked the owner nothing about design.
- **"Both" is a judgment.** It is used where the owner named the need and the AI named the answer.
- **The 23 are the decisions that shaped the product, the process, or the paper.** Many smaller choices were made
  every hour, mostly by the AI, and are not counted.
- **The transcripts are not in the repository**, and the first session's contains a credential, so they cannot be
  published as they are.
