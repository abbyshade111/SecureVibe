//! The questions only a person can answer, written for the AI coding tool to ask them.
//!
//! The owner is not a programmer, and three lists of questions sat in the report waiting for them:
//! the design questions, the security notes, and the checks to make by hand. The tool that wrote the
//! app is sitting in the same conversation and knows the code, so the owner asked (26 September
//! 2026) for the tool to be given the questions and to interview them: one question at a time, with
//! what the code says offered as a tip, and the answers recorded where `sv` reads them.
//!
//! Who answered is the part that has to stay honest. An answer the owner gave is recorded as theirs
//! (`by = "owner"`) and reported as *attested by the owner*. When the owner asks the tool to answer,
//! it answers from the code and records `by = "ai-tool"`, reported one tier lower as *stated by the
//! AI coding tool*. The security notes work the same way, on a `Written by:` line at the top of each
//! answer: `owner` for the person's decision, or one the tool wrote that they read and agree with;
//! `AI coding tool` for what the tool wrote from the code and the person has not agreed to, which is
//! reported as *stated by the AI coding tool* and asked again. A section without the line counts as
//! the tool's, so the tool is told to write it every time.
//!
//! Nothing here credits anything. This writes instructions; what the answers are worth is decided
//! where they are read (`sv_check::design`, `sv_check::notes`).

use crate::{Report, Status};
use sv_check::human::{Item, Route};

/// How the tool is told to ask. Kept apart from the questions so a test can hold each rule to it.
pub const HOW_TO_ASK: &str = "\
How to ask them. These are for the person you are building this app with, not for you to answer:
- Ask one question at a time, in plain words, and wait for the answer. Never paste the whole list.
- Before each question, look at the code you wrote and offer what you found as a tip, saying where
  you looked: \"In config.py a session ends after 30 minutes without use. Is that what you want?\"
  The \"where to look\" line under each question says where the answer is usually found.
- Record the answer as the person gave it, as described in each part below. \"Not sure\" is a good
  answer, and is recorded as not-sure. A \"no\" is useful too: the report lists it as something to fix.
- Write by = \"owner\" only for an answer the person gave or confirmed. If they ask you to answer, say
  what the code does, answer from that, and write by = \"ai-tool\". The report shows that as \"stated by
  the AI coding tool\", which is weaker than the person's own word, and says so.
- The person can confirm what you answered, and then it counts as much as their own word. Suggest
  something they can look at or try themselves (a page to open, a thing to try), not a yes-or-no. If
  they do it and agree, add confirmed = { by = \"owner\", on = \"YYYY-MM-DD\", how = \"what they
  looked at and saw\" } beside your answer, repeating the answer and `where` (or the `result`) it
  confirms. A colleague can confirm too, with their name in `by`. Never write a confirmation the
  person did not make: you cannot confirm your own answer.
- Never answer yes to make the report look better. An answer is a record of how the app is, and a
  wrong yes hides the one thing the question exists to find.
- When the person has had enough, stop. What is unanswered stays on the list for next time.
- Afterward, check the app again (securevibe_check) so the answers are read.";

/// The questions for one app, as the AI coding tool is given them.
pub fn text(report: &Report) -> String {
    let design: Vec<&Item> = of(report, Route::AnswerInTheManifest);
    let notes: Vec<&Item> = of(report, Route::WriteItDown);
    let by_hand: Vec<&Item> = of(report, Route::GoAndLook);
    let total = design.len() + notes.len() + by_hand.len();

    let mut out = format!(
        "QUESTIONS FOR THE OWNER of {}: {total} to ask.\n",
        report.app_name
    );
    if total == 0 {
        out.push_str(
            "\nThere is nothing to ask: every question that applies to this app has an answer from \
             the owner. That does not make the answers right, and the report still says how much \
             of the app nothing has checked.\n",
        );
        return out;
    }
    out.push('\n');
    out.push_str(HOW_TO_ASK);
    out.push('\n');

    if !design.is_empty() {
        out.push_str(&format!(
            "\n1. HOW THE APP IS BUILT ({}). Record each answer in securevibe.toml, in the [design] \
             section, keyed by its id:\n   \"V8.3.1\" = {{ answer = \"yes\", where = \"server/auth.py\", \
             by = \"owner\" }}\n   `answer` is yes, no, or not-sure; `where` names the file that does \
             it, and is left out when there is none.\n",
            design.len()
        ));
        for item in &design {
            out.push_str(&question(item));
            if let Some(means) = &item.where_means {
                out.push_str(&format!("   `where` names {means}.\n"));
            }
            if status_of(report, &item.id) == Some(Status::Stated) {
                out.push_str(
                    "   Only you, the AI coding tool, have answered this so far. Tell the person \
                     what you answered and why, and record their answer if they give one. Or \
                     suggest how they can see it for themselves; if they look and agree, confirm \
                     it: confirmed = { by = \"owner\", on = \"YYYY-MM-DD\", answer = \"yes\", \
                     where = \"...\", how = \"what they saw\" }.\n",
                );
            }
        }
    }

    if !notes.is_empty() {
        out.push_str(&format!(
            "\n{}. WRITTEN DECISIONS ({}). These ask what the rules are, which only the person can \
             decide. Make or refresh security-notes.md first (securevibe_notes_file, or `sv notes` \
             in a terminal); it keeps whatever is already written. Write the person's decision, in \
             a sentence or two of their words, under the question headed by its id, and start it \
             with the line `Written by: owner`. If they ask you to write it from the code, you may, \
             but start it with `Written by: AI coding tool`: the report counts that for less, as \
             stated by the AI coding tool, and asks again. Change it to `Written by: owner` only \
             once they have read what you wrote and agree with it. A section without that line \
             counts as yours.\n",
            if design.is_empty() { 1 } else { 2 },
            notes.len()
        ));
        for item in &notes {
            out.push_str(&question(item));
        }
    }

    if !by_hand.is_empty() {
        out.push_str(&format!(
            "\n{}. CHECKS TO MAKE BY HAND ({}). Walk the person through each one, and help with the \
             part that is in the code. Then record what happened in securevibe.toml, in the \
             [checked-by-hand] section, keyed by its id:\n   \"V12.2.2\" = {{ result = \"done\", on = \
             \"2026-09-26\", by = \"owner\", how = \"Opened the live site; the padlock shows a \
             trusted certificate.\" }}\n   `result` is done, problem, or not-yet; `on` is the day; \
             `how` is one sentence of what was done and seen, in the person's words, and is \
             required. A check you made yourself, reading the code, is by = \"ai-tool\"; if the \
             person then makes it too and sees the same, add confirmed = {{ by = \"owner\", on = \
             \"YYYY-MM-DD\", result = \"done\", how = \"what they saw\" }} beside it. A problem is \
             worth recording: the report lists it as something to fix.\n",
            1 + usize::from(!design.is_empty()) + usize::from(!notes.is_empty()),
            by_hand.len()
        ));
        for item in &by_hand {
            out.push_str(&question(item));
        }
    }
    out
}

fn of(report: &Report, route: Route) -> Vec<&Item> {
    report
        .questions_for_you
        .iter()
        .filter(|i| i.route == route)
        .collect()
}

fn status_of(report: &Report, id: &str) -> Option<Status> {
    report
        .requirements
        .iter()
        .find(|r| r.id == id)
        .map(|r| r.status)
}

fn question(item: &Item) -> String {
    let mut out = format!(
        "\n - {}: {}\n   Ask: {}\n",
        item.id,
        item.title,
        one_line(&item.how)
    );
    if let Some(look) = &item.where_to_look {
        out.push_str(&format!("   Where to look: {}\n", one_line(look)));
    }
    out
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::HOW_TO_ASK;

    #[test]
    fn the_tool_is_told_whose_answer_is_whose() {
        // The rules that keep the tiers honest are only as good as the tool being told them.
        let flat = HOW_TO_ASK.split_whitespace().collect::<Vec<_>>().join(" ");
        for rule in [
            "one question at a time",
            "Write by = \"owner\" only for an answer the person gave or confirmed",
            "write by = \"ai-tool\"",
            "Never answer yes to make the report look better",
            "\"Not sure\" is a good answer",
        ] {
            assert!(
                flat.contains(rule),
                "the instructions lost {rule:?}:\n{HOW_TO_ASK}"
            );
        }
    }
}
