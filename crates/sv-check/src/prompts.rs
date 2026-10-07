//! Prompts the owner gives their AI coding tool, from `data/prompts.json`, and the design-time ones
//! from the Secure by Design checklist in `data/design-prompts.json`, which have the same shape.
//!
//! Each prompt asks the tool for something `sv` checks, names the requirements it targets, and names
//! the rules whose result shows whether it worked. A prompt is *shown to work* only once an app built
//! with it passed that check and the same app built without it failed (the owner's decision of 3
//! October 2026). The others are offered too, at the owner's asking on 4 October 2026, and every copy
//! of one says it is not tested.
//!
//! That a prompt's requirements are the ones its rules cite is held by `tools/coverage.py`, which a
//! test runs, beside every other citation.
//!
//! # What it is worth
//!
//! Nothing, as evidence. Handing the tool a prompt says nothing about what it then wrote, so no
//! requirement changes status because a prompt was given or read.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// The statuses in a report that no check and no document gave evidence for: a finding, nothing
/// seen either way, or only the owner's or the AI coding tool's word (`sv_report::Status`). These
/// are what a prompt can help with. `checked`, `by-hand`, and `documented` are left out: each is
/// evidence of some kind already.
pub const UNPROVEN: [&str; 4] = ["needs-attention", "not-verified", "attested", "stated"];

/// What a status means, in the words the offer uses.
fn status_words(status: &str) -> &'static str {
    match status {
        "needs-attention" => "a finding",
        "not-verified" => "nothing shown yet",
        "attested" => "only your word",
        "stated" => "only the AI tool's word",
        _ => "not shown",
    }
}

/// The requirements an app's report (`report.json`) shows with no evidence: each id with its
/// status. A report with no `requirements` list is refused, since nothing could be read from it.
pub fn gaps_in_report(report: &serde_json::Value) -> Result<BTreeMap<String, String>> {
    let requirements = report["requirements"]
        .as_array()
        .context("the report has no list of requirements")?;
    Ok(requirements
        .iter()
        .filter_map(|r| Some((r["id"].as_str()?, r["status"].as_str()?)))
        .filter(|(_, status)| UNPROVEN.contains(status))
        .map(|(id, status)| (id.to_owned(), status.to_owned()))
        .collect())
}

/// Whether a prompt has been shown to work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// The build with it passed its check, and the build without it failed.
    Shown,
    /// Tried, and the test could not show the prompt made the difference; `tested` says why.
    NotShown,
    /// Not tried yet.
    Untested,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Shown => "shown",
            Status::NotShown => "not-shown",
            Status::Untested => "untested",
        }
    }
}

/// What the check behind a prompt is, and what its result means.
#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    pub kind: String,
    pub how: String,
    #[serde(default)]
    pub rules: Vec<String>,
    pub passes_when: String,
    pub fails_when: String,
}

/// How a prompt was tried.
#[derive(Debug, Clone, Deserialize)]
pub struct Tested {
    pub date: String,
    pub brief: String,
    pub builder: String,
    pub result: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Prompt {
    pub id: String,
    pub title: String,
    pub prompt: String,
    pub requirements: Vec<String>,
    /// The Secure by Design controls a design-time prompt helps a person answer. It never meets one:
    /// every control is answered by a person.
    #[serde(default)]
    pub sbd_controls: Vec<String>,
    pub check: Check,
    pub inspired_by: String,
    pub tested: Option<Tested>,
    pub status: Status,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Prompts {
    /// Where the prompts came from, said with every copy: one paragraph per file read. Missing from a
    /// file, it is refused by `load_all` with a message that says so, rather than as a parse error.
    #[serde(default)]
    pub credit: String,
    pub prompts: Vec<Prompt>,
}

impl Prompts {
    pub fn load(path: &Path) -> Result<Prompts> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let prompts: Prompts =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        anyhow::ensure!(
            !prompts.prompts.is_empty(),
            "{} holds no prompts",
            path.display()
        );
        for (i, p) in prompts.prompts.iter().enumerate() {
            anyhow::ensure!(
                !prompts.prompts[..i].iter().any(|q| q.id == p.id),
                "{}: the id {} is used twice",
                path.display(),
                p.id
            );
            // A prompt said to be tried has to say what happened, or "not tested" and "shown" read
            // the same to the person choosing one.
            let says_what_happened = p
                .tested
                .as_ref()
                .is_some_and(|t| !t.result.trim().is_empty());
            anyhow::ensure!(
                says_what_happened == (p.status != Status::Untested),
                "{}: prompt {} is {} and {} what happened when it was tried",
                path.display(),
                p.id,
                p.status.as_str(),
                if says_what_happened {
                    "says"
                } else {
                    "does not say"
                }
            );
        }
        Ok(prompts)
    }

    /// Every file's prompts as one library, each file's credit kept. An id used in two files is
    /// refused, so `--requirement` and the tool never answer with two prompts under one name.
    pub fn load_all(paths: &[&Path]) -> Result<Prompts> {
        let mut all = Prompts {
            credit: String::new(),
            prompts: Vec::new(),
        };
        for path in paths {
            let one = Prompts::load(path)?;
            for p in &one.prompts {
                anyhow::ensure!(
                    !all.prompts.iter().any(|q| q.id == p.id),
                    "{}: the id {} is already used by another file of prompts",
                    path.display(),
                    p.id
                );
            }
            anyhow::ensure!(
                !one.credit.trim().is_empty(),
                "{} does not say where its prompts came from (`credit`)",
                path.display()
            );
            if !all.credit.is_empty() {
                all.credit.push_str("\n\n");
            }
            all.credit.push_str(one.credit.trim());
            all.prompts.extend(one.prompts);
        }
        Ok(all)
    }

    /// The prompts for one requirement or Secure by Design control, or every prompt when
    /// `requirement` is `None`; the ones shown to work first, then the rest, each group in the
    /// files' order.
    pub fn select(&self, requirement: Option<&str>) -> Vec<&Prompt> {
        let mut chosen: Vec<&Prompt> = self
            .prompts
            .iter()
            .filter(|p| {
                requirement
                    .is_none_or(|q| p.requirements.iter().chain(&p.sbd_controls).any(|r| r == q))
            })
            .collect();
        chosen.sort_by_key(|p| p.status != Status::Shown);
        chosen
    }

    /// The prompts as Markdown, each saying whether it has been shown to work, ending with the credit.
    pub fn markdown(&self, chosen: &[&Prompt]) -> String {
        let mut out = String::from("## Prompts for the AI coding tool\n\n");
        out.push_str(
            "Each asks the AI coding tool for something SecureVibe checks. A prompt is shown to work \
             only when an app built with it passed its check and the same app built without it \
             failed; every other one says it is not tested. A prompt is an instruction, not \
             evidence: check the app afterwards, whichever you use.\n",
        );
        for p in chosen {
            out.push_str(&format!("\n### {}\n\n", p.title));
            let result = p.tested.as_ref().map(|t| t.result.as_str()).unwrap_or("");
            out.push_str(&match p.status {
                Status::Shown => format!("**Shown to work.** {result}\n\n"),
                Status::NotShown => {
                    format!("**Not tested:** tried, and not shown to work. {result}\n\n")
                }
                Status::Untested => "**Not tested:** not tried yet.\n\n".to_owned(),
            });
            for line in p.prompt.lines() {
                out.push_str(&format!("> {line}\n"));
            }
            if !p.requirements.is_empty() {
                out.push_str(&format!("\nRequirements: {}.\n", p.requirements.join(", ")));
            }
            if !p.sbd_controls.is_empty() {
                out.push_str(&format!(
                    "\nSecure by Design controls it helps you answer (you still answer each): {}.\n",
                    p.sbd_controls.join(", ")
                ));
            }
        }
        out.push_str(&format!("\n{}\n", self.credit));
        out
    }

    /// The prompts for the requirements an app's report shows with no evidence, those shown to work
    /// first, each with the gaps it is for. A prompt for none of them is not offered.
    pub fn for_gaps<'a>(
        &'a self,
        gaps: &BTreeMap<String, String>,
    ) -> Vec<(&'a Prompt, Vec<String>)> {
        self.select(None)
            .into_iter()
            .filter_map(|p| {
                let mut ids: Vec<String> = p
                    .requirements
                    .iter()
                    .chain(&p.sbd_controls)
                    .filter(|r| gaps.contains_key(*r))
                    .cloned()
                    .collect();
                ids.dedup();
                (!ids.is_empty()).then_some((p, ids))
            })
            .collect()
    }

    /// The offer as Markdown: which report it was read from, then each prompt with the requirements
    /// it is for and what the report says of each.
    pub fn gaps_markdown(
        &self,
        offered: &[(&Prompt, Vec<String>)],
        gaps: &BTreeMap<String, String>,
        report: &str,
    ) -> String {
        let mut out = String::from("## Prompts for what the app has not yet shown\n\n");
        out.push_str(&format!(
            "Read from {report}: {} of the app's requirements have no evidence yet (a finding, \
             nothing shown, or only someone's word). Each prompt below asks the AI coding tool for \
             one or more of them. A prompt is an instruction, not evidence: make a new report \
             afterwards, and only what it then shows counts.\n",
            gaps.len()
        ));
        if offered.is_empty() {
            out.push_str(
                "\nNo prompt in the library targets any of them yet. `sv prompts` lists every prompt.\n",
            );
            return out;
        }
        for (p, ids) in offered {
            out.push_str(&format!("\n### {}\n\n", p.title));
            out.push_str(match p.status {
                Status::Shown => "**Shown to work.**\n\n",
                Status::NotShown => "**Not tested:** tried, and not shown to work.\n\n",
                Status::Untested => "**Not tested:** not tried yet.\n\n",
            });
            out.push_str(&format!(
                "For: {}.\n\n",
                ids.iter()
                    .map(|id| format!(
                        "{id} ({})",
                        status_words(gaps.get(id).map(String::as_str).unwrap_or(""))
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            for line in p.prompt.lines() {
                out.push_str(&format!("> {line}\n"));
            }
        }
        out.push_str(&format!("\n{}\n", self.credit));
        out
    }
}
