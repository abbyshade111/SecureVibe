//! The exit status of `sv check`, `sv report`, `sv audit` and `sv run`, and of every run `sv` could not
//! finish (DESIGN, "Exit codes for CI"; the deep review of 4 October 2026, R6).
//!
//! - 0: the run finished, and nothing below applies.
//! - 1: something needs a person: `sv audit` found a known vulnerability, or `--fail-on attention`
//!   was given and a finding at or above its severity is in the result.
//! - 2: not assessed: a check could not run, or no file of the app was read (always), or, with
//!   `--fail-on not-assessed`, something narrower that went unread. `sv audit`: the comparison did
//!   not cover the whole app.
//!   `sv run`: the app could not be started, or never answered, so nothing about it running was
//!   checked (the owner's decision, 6 October 2026).
//! - 3: `sv` itself failed: no securevibe.toml, a manifest it cannot read, a folder that is not
//!   there, an option it does not know. Nothing about the app is known from such a run.
//!
//! 1 outranks 2, and 3 is never combined with anything: a run that failed produced no result to rank.
//! Ctrl-C keeps 130, the usual code for it.
//!
//! Most of what a static run cannot see is not on these lists, on purpose. Every app the owner had
//! on 4 October 2026 had requirements "not verified by anything" (121 to 230 of them) and checks
//! that need a Dockerfile, a git repository, or a package manifest it lacked. Exiting 2 for those
//! would fail every pipeline every time, and a status that is always 2 says nothing.

use anyhow::{Result, bail};
use sv_check::finding::Severity;

/// The run finished and nothing it was asked to fail on happened.
pub const CLEAN: i32 = 0;
/// Something needs a person.
pub const ATTENTION: i32 = 1;
/// Not assessed: part of what was asked could not be checked.
pub const NOT_ASSESSED: i32 = 2;
/// `sv` itself failed, so there is no result at all.
pub const FAILED: i32 = 3;

/// Of two statuses, the one that says more is wrong: something needing attention, then something not
/// assessed, then clean.
pub fn worse(a: i32, b: i32) -> i32 {
    if a == ATTENTION || b == ATTENTION {
        ATTENTION
    } else if a == NOT_ASSESSED || b == NOT_ASSESSED {
        NOT_ASSESSED
    } else {
        CLEAN
    }
}

/// Ends the process with `code`, once what was printed is out.
pub fn exit_with(code: i32) -> ! {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

/// What `--fail-on` asked for. The default, nothing, still exits 2 when a check could not run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FailOn {
    /// Exit 1 for a finding at this severity or worse.
    pub attention: Option<Severity>,
    /// Exit 2 also for the narrower gaps (`Gaps::partly`).
    pub not_assessed: bool,
}

impl FailOn {
    /// `attention`, `attention:SEVERITY`, `not-assessed`, or `any`, several separated by commas.
    pub fn parse(value: &str) -> Result<FailOn> {
        let mut fail_on = FailOn::default();
        for word in value.split(',').map(str::trim) {
            match word.split_once(':') {
                None if word == "attention" => fail_on.attention = Some(Severity::Low),
                None if word == "not-assessed" => fail_on.not_assessed = true,
                None if word == "any" => {
                    fail_on.attention = Some(Severity::Low);
                    fail_on.not_assessed = true;
                }
                Some(("attention", severity)) => {
                    fail_on.attention = Some(match severity {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        "low" => Severity::Low,
                        "info" => Severity::Info,
                        other => bail!(
                            "--fail-on attention:{other}: the severity is one of critical, high, \
                             medium, low, or info"
                        ),
                    })
                }
                _ => bail!(
                    "--fail-on {word}: it takes attention, attention:SEVERITY, not-assessed, or \
                     any, several separated by commas"
                ),
            }
        }
        Ok(fail_on)
    }

    /// `--fail-on WHAT` taken out of `args`, with the arguments left over.
    pub fn take(args: &[String]) -> Result<(FailOn, Vec<String>)> {
        let mut fail_on = FailOn::default();
        let mut rest = Vec::new();
        let mut words = args.iter();
        while let Some(arg) = words.next() {
            if arg == "--fail-on" {
                let Some(value) = words.next() else {
                    bail!("--fail-on needs a value: attention[:SEVERITY], not-assessed, or any");
                };
                let more = FailOn::parse(value)?;
                fail_on.attention = match (fail_on.attention, more.attention) {
                    // Severity orders worst first, so the lower bar of two is the larger.
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                fail_on.not_assessed |= more.not_assessed;
            } else {
                rest.push(arg.clone());
            }
        }
        Ok((fail_on, rest))
    }
}

/// What a run could not see, in two lists: what always makes it exit 2, and what does only with
/// `--fail-on not-assessed`. Each entry is a sentence a person can read.
#[derive(Debug, Default, Clone)]
pub struct Gaps {
    /// A check that could not run, or an app none of whose files was read. Always exit 2.
    pub could_not_run: Vec<String>,
    /// Narrower: what a link or a special file points at, a tool `--tools` could not run, an
    /// advisory comparison that did not cover the app. Exit 2 only with `--fail-on not-assessed`.
    pub partly: Vec<String>,
}

/// The files `sv` reads for itself, which say nothing about the app: an app holding only these was
/// not read at all.
const SV_OWN_FILES: &[&str] = &["securevibe.toml", "security-notes.md"];

impl Gaps {
    /// What the checks that read the app's files could not do. The list is exactly DESIGN's:
    ///
    /// - always: no file of the app was read as text (apart from `SV_OWN_FILES`); a file or folder
    ///   that could not be opened or read, or was too large to read even in pieces (but not a file
    ///   that was read and is not text, such as an image: every web app has one, and the credential
    ///   rules read text); a file in a language the code rules read that was not opened; a file the
    ///   parser could not make sense of; a language present that nothing reads; a code rule whose
    ///   query would not compile.
    /// - with `--fail-on not-assessed`: a symbolic link not followed, and an entry that is not an
    ///   ordinary file. Common and usually harmless (`CLAUDE.md` pointing at `AGENTS.md`), so not by
    ///   default; what they point at was still not read.
    pub fn of_files(
        listing: &sv_scan::files::Listing,
        secrets: &sv_check::secrets::SecretScan,
        code: &sv_check::ast::AstScan,
    ) -> Gaps {
        let not_text = sv_scan::files::Unread::NotText.explain();
        let mut gaps = Gaps::default();
        let unread: std::collections::BTreeSet<&str> = secrets
            .coverage
            .skipped
            .iter()
            .map(|(file, _)| file.as_str())
            .collect();
        let read = listing
            .app_files()
            .filter(|f| !unread.contains(f.relative.as_str()))
            .filter(|f| !SV_OWN_FILES.contains(&f.relative.as_str()))
            .count();
        if read == 0 {
            gaps.could_not_run.push(
                "no file of the app was read (securevibe.toml and security-notes.md do not count)"
                    .to_owned(),
            );
        }
        let could_not_read: Vec<&(String, String)> = secrets
            .coverage
            .skipped
            .iter()
            .filter(|(_, why)| why != not_text)
            .collect();
        if !could_not_read.is_empty() {
            gaps.could_not_run.push(format!(
                "{} file(s) or folder(s) could not be read, such as {} ({})",
                could_not_read.len(),
                could_not_read[0].0,
                could_not_read[0].1
            ));
        }
        if !code.unread_files.is_empty() {
            gaps.could_not_run.push(format!(
                "{} file(s) in a language the code rules read were not opened, such as {} ({})",
                code.unread_files.len(),
                code.unread_files[0].0,
                code.unread_files[0].1
            ));
        }
        if !code.unparsed_files.is_empty() {
            gaps.could_not_run.push(format!(
                "{} file(s) the parser could not make sense of, such as {}",
                code.unparsed_files.len(),
                code.unparsed_files[0]
            ));
        }
        if !code.unread_languages.is_empty() {
            let names: Vec<&str> = code.unread_languages.iter().map(String::as_str).collect();
            gaps.could_not_run
                .push(format!("nothing here reads {}", names.join(", ")));
        }
        for broken in &code.broken_queries {
            gaps.could_not_run.push(format!(
                "the code rule {} could not run for {}: its query would not compile",
                broken.rule_id, broken.language
            ));
        }
        if !listing.links.is_empty() {
            gaps.partly.push(format!(
                "{} symbolic link(s) were not followed, such as {}",
                listing.links.len(),
                listing.links[0]
            ));
        }
        if !listing.special.is_empty() {
            gaps.partly.push(format!(
                "{} entry(s) are not ordinary files and were not opened, such as {}",
                listing.special.len(),
                listing.special[0]
            ));
        }
        gaps
    }

    /// The status these gaps and these findings come to under `fail_on`, with the reasons it is not 0.
    pub fn status(
        &self,
        fail_on: FailOn,
        findings: impl IntoIterator<Item = Severity>,
    ) -> (i32, Vec<String>) {
        let mut reasons = Vec::new();
        let mut code = CLEAN;
        if let Some(bar) = fail_on.attention {
            // Severity orders worst first: at or above the bar is less than or equal to it.
            let over = findings.into_iter().filter(|s| *s <= bar).count();
            if over > 0 {
                code = ATTENTION;
                reasons.push(format!(
                    "{over} finding(s) at {} or worse (--fail-on attention:{})",
                    bar.name(),
                    bar.name()
                ));
            }
        }
        if !self.could_not_run.is_empty() {
            code = worse(code, NOT_ASSESSED);
            reasons.extend(self.could_not_run.iter().cloned());
        }
        if fail_on.not_assessed && !self.partly.is_empty() {
            code = worse(code, NOT_ASSESSED);
            reasons.extend(
                self.partly
                    .iter()
                    .map(|p| format!("{p} (--fail-on not-assessed)")),
            );
        }
        (code, reasons)
    }
}

/// The closing lines that say why a run exits other than 0, or nothing when it exits 0.
pub fn explain(code: i32, reasons: &[String]) -> Vec<String> {
    if code == CLEAN {
        return Vec::new();
    }
    let what = match code {
        ATTENTION => "something needs attention",
        _ => "not assessed",
    };
    let mut lines = vec![format!("\nExit status {code} ({what}):")];
    lines.extend(reasons.iter().map(|r| format!("  {r}")));
    lines
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_fail_on_the_ai_tool_is_told_to_use_is_one_sv_takes() {
        // Gap analysis 6.3: the default exit is 0 with findings (ADR-029), so what an AI coding tool
        // reads before writing a CI workflow names `--fail-on`. A value `sv` refused would leave
        // the workflow failing on every run, or worse, edited until it no longer asks.
        for (whose, text) in [
            ("the MCP server's instructions", crate::mcp::INSTRUCTIONS),
            ("the specification", sv_manifest::spec::INSTRUCTIONS),
        ] {
            let named: Vec<&str> = text
                .split("--fail-on ")
                .skip(1)
                .map(|rest| {
                    rest.split(|c: char| c.is_whitespace() || c == '`' || c == ')')
                        .next()
                        .unwrap_or("")
                })
                .collect();
            assert!(
                named.contains(&"attention:high"),
                "{whose} must name --fail-on attention:high: {named:?}"
            );
            for value in named {
                super::FailOn::parse(value)
                    .unwrap_or_else(|e| panic!("{whose} names --fail-on {value}: {e}"));
            }
        }
    }

    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_words_fail_on_takes() {
        assert_eq!(
            FailOn::parse("attention").unwrap().attention,
            Some(Severity::Low)
        );
        assert_eq!(
            FailOn::parse("attention:high").unwrap(),
            FailOn {
                attention: Some(Severity::High),
                not_assessed: false
            }
        );
        assert_eq!(
            FailOn::parse("any").unwrap(),
            FailOn {
                attention: Some(Severity::Low),
                not_assessed: true
            }
        );
        assert_eq!(
            FailOn::parse("not-assessed, attention:critical").unwrap(),
            FailOn {
                attention: Some(Severity::Critical),
                not_assessed: true
            }
        );
        for wrong in ["", "attention:severe", "findings", "attention:", "any:low"] {
            assert!(FailOn::parse(wrong).is_err(), "{wrong:?} was taken");
        }
    }

    #[test]
    fn fail_on_is_taken_out_and_the_rest_left_in_order() {
        let (fail_on, rest) =
            FailOn::take(&strings(&["app", "--fail-on", "attention:high", "--run"])).unwrap();
        assert_eq!(fail_on.attention, Some(Severity::High));
        assert_eq!(rest, strings(&["app", "--run"]));
        // Given twice, the lower bar wins.
        let (fail_on, _) = FailOn::take(&strings(&[
            "--fail-on",
            "attention:critical",
            "--fail-on",
            "attention:medium",
        ]))
        .unwrap();
        assert_eq!(fail_on.attention, Some(Severity::Medium));
        assert!(FailOn::take(&strings(&["--fail-on"])).is_err());
    }

    #[test]
    fn attention_outranks_not_assessed_and_findings_below_the_bar_do_not_count() {
        let gaps = Gaps {
            could_not_run: vec!["x".to_owned()],
            partly: vec!["y".to_owned()],
        };
        let none = Gaps::default();
        let high = FailOn::parse("attention:high").unwrap();
        assert_eq!(
            none.status(FailOn::default(), [Severity::Critical]).0,
            CLEAN
        );
        assert_eq!(
            none.status(high, [Severity::Medium, Severity::Low]).0,
            CLEAN
        );
        assert_eq!(
            none.status(high, [Severity::Low, Severity::High]).0,
            ATTENTION
        );
        assert_eq!(gaps.status(FailOn::default(), []).0, NOT_ASSESSED);
        assert_eq!(gaps.status(high, [Severity::Critical]).0, ATTENTION);
        let partly_only = Gaps {
            could_not_run: vec![],
            partly: vec!["y".to_owned()],
        };
        assert_eq!(partly_only.status(FailOn::default(), []).0, CLEAN);
        assert_eq!(
            partly_only
                .status(FailOn::parse("not-assessed").unwrap(), [])
                .0,
            NOT_ASSESSED
        );
        assert_eq!(worse(CLEAN, CLEAN), CLEAN);
        assert_eq!(worse(NOT_ASSESSED, ATTENTION), ATTENTION);
    }
}
