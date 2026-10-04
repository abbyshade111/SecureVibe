//! Prompts the owner gives their AI coding tool, from `data/prompts.json`.
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
use std::path::Path;

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
    pub check: Check,
    pub inspired_by: String,
    pub tested: Option<Tested>,
    pub status: Status,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Prompts {
    /// Where the prompts came from, said with every copy.
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

    /// The prompts for one requirement, or every prompt when `requirement` is `None`; the ones shown
    /// to work first, then the rest, each group in the file's order.
    pub fn select(&self, requirement: Option<&str>) -> Vec<&Prompt> {
        let mut chosen: Vec<&Prompt> = self
            .prompts
            .iter()
            .filter(|p| requirement.is_none_or(|q| p.requirements.iter().any(|r| r == q)))
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
        }
        out.push_str(&format!("\n{}\n", self.credit));
        out
    }
}
