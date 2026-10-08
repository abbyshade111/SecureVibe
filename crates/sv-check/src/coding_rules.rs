//! The rules an AI coding tool follows while it writes an app, from OWASP AISVS 1.0 Appendix C.
//!
//! Appendix C's 68 requirements are written for somebody auditing an organization ("Verify that…"),
//! and nothing in `sv` checks any of them. About twenty describe what a coding tool itself can do or
//! avoid while it writes code: keep keys out of the chat, treat fetched text as data, run the check
//! after each feature, add only packages that exist, never merge its own work, write CI workflows
//! that keep secrets from forks. `data/coding-rules.json` holds those, rewritten as instructions,
//! each citing the requirements it comes from. The rest are the owner's decisions (asked through the
//! security notes and the design questions) or pipeline and organization infrastructure.
//!
//! # Credit
//!
//! Every rendering carries the attribution: what the rules were adapted from, by whom, where it is,
//! its license (CC BY-SA 4.0), and what was changed. The adapted text is shared under the same
//! license; the app's own code is not touched by it.
//!
//! # What it is worth
//!
//! Nothing, as evidence. Handing the tool a rule says nothing about whether the rule was kept, so no
//! requirement changes status because the rules were written or read.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// What an AI coding tool is told to do when SecureVibe is not connected: stop and say so. Without it the
/// tool builds on, nothing is checked, and nothing tells the person (`docs/GAP-ANALYSIS.md`, 5.3).
pub const WHEN_NOT_CONNECTED: &str = "**If the `securevibe_` tools are not among the tools you can call, \
    stop and tell the person before you write any code.** SecureVibe is then not connected, and nothing \
    you build is being checked. Do not carry on without it, and never say the app was checked.";

/// Where the rules come from, and on what terms.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attribution {
    pub title: String,
    pub authors: String,
    pub url: String,
    pub license: String,
    pub license_url: String,
    pub changes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub topic: String,
    pub rule: String,
    /// Requirement id → what the rule and the requirement have in common.
    pub cites: BTreeMap<String, String>,
    /// Set when the rule is given to every app, whatever applies to it, and why: the risk a cited
    /// requirement guards against from outside also arrives from the coding tool itself.
    #[serde(default)]
    pub always: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Topic {
    pub id: String,
    pub heading: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CodingRules {
    pub attribution: Attribution,
    /// The topics, in the order the rules are grouped under them.
    pub topics: Vec<Topic>,
    pub rules: Vec<Rule>,
}

/// The markers around the section `sv` writes into `AGENTS.md`. Everything outside them is the
/// owner's, and a later run replaces only what is between them.
pub const BEGIN: &str = sv_frameworks::names::RULES_BEGIN;
pub const END: &str = sv_frameworks::names::RULES_END;
/// The markers before the rename (ADR-062): a block between them is found, and rewritten between
/// the new ones.
const OLD_BEGIN: &str = sv_frameworks::names::OLD_RULES_BEGIN;
const OLD_END: &str = sv_frameworks::names::OLD_RULES_END;

impl CodingRules {
    pub fn load(path: &Path) -> Result<CodingRules> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let rules: CodingRules =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        for rule in &rules.rules {
            anyhow::ensure!(
                rules.topics.iter().any(|t| t.id == rule.topic),
                "{}: rule {} names the topic {}, which is not listed",
                path.display(),
                rule.id,
                rule.topic
            );
            anyhow::ensure!(
                rule.always
                    .as_ref()
                    .is_none_or(|why| why.trim().len() >= 40),
                "{}: rule {} is given to every app without saying why",
                path.display(),
                rule.id
            );
            anyhow::ensure!(
                !rule.cites.is_empty(),
                "{}: rule {} cites nothing, so nothing says where it comes from",
                path.display(),
                rule.id
            );
        }
        Ok(rules)
    }

    /// The rules for an app: every rule, except one whose cited requirements all do not apply to it.
    /// `not_applicable` is `None` when nothing is known about the app yet, which gives every rule.
    pub fn for_app(&self, not_applicable: Option<&dyn Fn(&str) -> bool>) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| match not_applicable {
                None => true,
                Some(excluded) => {
                    rule.always.is_some() || !rule.cites.keys().all(|id| excluded(id))
                }
            })
            .collect()
    }

    /// The topic ids, for a caller asking for one.
    pub fn topic_ids(&self) -> Vec<&str> {
        self.topics.iter().map(|t| t.id.as_str()).collect()
    }

    /// The attribution, in one paragraph, the same wherever the rules go.
    pub fn credit(&self) -> String {
        let a = &self.attribution;
        format!(
            "Adapted from [{}]({}), by {}, licensed under [{}]({}). {} This adapted text is shared \
             under the same license; the license does not reach the app's own code.",
            a.title, a.url, a.authors, a.license, a.license_url, a.changes
        )
    }

    /// The rules as Markdown, grouped by topic, each ending with the requirements it cites.
    /// `withheld` counts the rules left out because they do not apply, so the text can say so.
    /// The rules as `sv rules` writes them into `AGENTS.md`: `markdown`, with `WHEN_NOT_CONNECTED`
    /// after the heading. Only there, because a tool reads `AGENTS.md` whether or not SecureVibe is
    /// connected, and through `securevibe_guidance` it plainly is.
    pub fn agents_markdown(&self, rules: &[&Rule], withheld: usize) -> String {
        let section = self.markdown(rules, withheld);
        match section.split_once("\n\n") {
            Some((heading, rest)) => format!("{heading}\n\n{WHEN_NOT_CONNECTED}\n\n{rest}"),
            None => section,
        }
    }

    pub fn markdown(&self, rules: &[&Rule], withheld: usize) -> String {
        let mut out = String::new();
        out.push_str("## Security rules for the AI coding tool\n\n");
        out.push_str(
            "Follow these while you write or change this app. They come from OWASP guidance for \
             AI-assisted coding, and each names the requirement it comes from (the MCP tool \
             `securevibe_explain` gives a requirement's full text). They are instructions, not a check: following \
             them is not evidence that the app meets anything, and `sv` never reports it as such.\n\n",
        );
        for Topic { id: topic, heading } in &self.topics {
            let in_topic: Vec<&&Rule> = rules.iter().filter(|r| &r.topic == topic).collect();
            if in_topic.is_empty() {
                continue;
            }
            out.push_str(&format!("### {heading}\n\n"));
            for rule in in_topic {
                let cited: Vec<&str> = rule.cites.keys().map(String::as_str).collect();
                out.push_str(&format!("- {} ({})\n", rule.rule, cited.join(", ")));
            }
            out.push('\n');
        }
        if withheld > 0 {
            out.push_str(&format!(
                "{withheld} more rule{} left out, because what {} about does not apply to this app \
                 according to stackvet.toml.\n\n",
                if withheld == 1 { " is" } else { "s are" },
                if withheld == 1 { "it is" } else { "they are" }
            ));
        }
        out.push_str(&format!("{}\n", self.credit()));
        out
    }

    /// `existing` (an `AGENTS.md`, or nothing) with the rules section put in or replaced, between
    /// the markers. Everything outside the markers is kept exactly as it was.
    pub fn into_agents_file(&self, existing: Option<&str>, section: &str) -> Result<String> {
        let block = format!(
            "{BEGIN}\n<!-- Written by `sv rules`, which replaces only what is between these two \
             markers. -->\n\n{}\n{END}\n",
            section.trim_end()
        );
        let Some(existing) = existing else {
            return Ok(block);
        };
        // The block is found under either pair of markers, and always rewritten under the new.
        let (found_begin, found_end, end_len) = match (existing.find(BEGIN), existing.find(END)) {
            (None, None) => (
                existing.find(OLD_BEGIN),
                existing.find(OLD_END),
                OLD_END.len(),
            ),
            (begin, end) => (begin, end, END.len()),
        };
        match (found_begin, found_end) {
            (Some(begin), Some(end)) if begin < end => {
                let after = end + end_len;
                let rest = existing[after..]
                    .strip_prefix('\n')
                    .unwrap_or(&existing[after..]);
                Ok(format!("{}{block}{rest}", &existing[..begin]))
            }
            (None, None) => {
                let mut out = existing.trim_end().to_owned();
                if !out.is_empty() {
                    out.push_str("\n\n");
                }
                out.push_str(&block);
                Ok(out)
            }
            // One marker without the other, or out of order: somebody edited them, and guessing
            // where the section ends could delete their writing.
            _ => anyhow::bail!(
                "the file has one of `sv`'s markers without the other, or has them out of order; \
                 put both back, or remove both, and run `sv rules` again"
            ),
        }
    }
}
