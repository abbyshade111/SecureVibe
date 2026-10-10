//! The stage every reading of the app's files goes through, for `sv check` and `sv report` alike.
//!
//! Until 8 October 2026 `sv check` ran the same five scanners as `sv report` (the files listed, the
//! languages and packages recognized, the keys and passwords, the configuration, the code) and then
//! parted from it: it never merged the same weakness reported twice on one line, never marked test
//! code, a folder the manifest sets apart, or a bundled library, never applied what a person had
//! set aside through `sv review`, and counted every finding toward its exit status, where `sv
//! report` counted the findings left after the reviews. So `sv check --fail-on attention` could fail
//! a CI pipeline on a finding the owner had recorded as a false alarm, and the AI coding tool
//! reading that failure would rewrite the code until it stopped (the architecture assessment of 8
//! October 2026, item 3; ADR-023, Later, 8 October 2026). Now both read the app through
//! [`StaticScan::read`] and count what [`settle`] leaves, and the two exit alike on the same folder.

use crate::{Loaded, ReviewLookup, decisions_then_reviews};
use anyhow::Result;
use std::path::Path;

/// What the five scanners that read the app's files found, built once for a run.
pub struct StaticScan {
    /// One walk of the folder, shared by every check (DESIGN, "One walk of the app").
    pub listing: sv_scan::files::Listing,
    /// Its languages and frameworks, and the folders the manifest sets apart as applied (ADR-031).
    pub scan_report: sv_scan::ScanReport,
    /// The packages it ships, read from manifests and lockfiles; no network.
    pub bill_of_materials: sv_check::sbom::Sbom,
    pub secrets: sv_check::secrets::SecretScan,
    pub config: sv_check::config::ConfigReport,
    pub code: sv_check::ast::AstScan,
}

impl StaticScan {
    /// Reads the app at `app_dir`, calling `starting` with each stage's number (`REPORT_STAGES`,
    /// 0 to 5) as it begins. `not_the_app` is what the manifest says is not the app, or nothing.
    pub fn read(
        app_dir: &Path,
        not_the_app: &[String],
        loaded: &Loaded,
        starting: &dyn Fn(usize),
    ) -> Result<Self> {
        starting(0);
        let listing = sv_scan::files::Listing::of(app_dir);
        starting(1);
        let scan_report = sv_scan::scan_listing_app(&listing, &loaded.signatures, not_the_app)?;
        starting(2);
        let bill_of_materials = sv_check::sbom::build_in(&listing);
        starting(3);
        let secrets = sv_check::secrets::scan_listing(&loaded.secret_rules, &listing);
        starting(4);
        let config = sv_check::config::check_dir_in(&listing, &bill_of_materials);
        starting(5);
        let mut code = sv_check::ast::scan_listing(&loaded.ast_rules, &listing);
        let uses = (bill_of_materials.components.iter())
            .map(|c| (c.ecosystem.as_str(), c.name.as_str()))
            .chain((scan_report.declared.iter()).map(|d| (d.ecosystem.as_str(), d.name.as_str())));
        sv_check::ast::hold_back_for_packages(&loaded.ast_rules, &mut code, uses);
        Ok(StaticScan {
            listing,
            scan_report,
            bill_of_materials,
            secrets,
            config,
            code,
        })
    }

    /// Every finding of the five scanners, as one list. The bill of materials speaks for itself
    /// here: incomplete is a finding against V15.1.2, complete is evidence for it (`passed`), and
    /// exactly one of the two says anything.
    pub fn findings(&self) -> Vec<sv_check::Finding> {
        let mut findings = self.secrets.findings.clone();
        findings.extend(self.config.findings.iter().cloned());
        findings.extend(sv_check::sbom::incompleteness_finding(
            &self.bill_of_materials,
        ));
        findings.extend(self.code.findings.iter().cloned());
        findings
    }

    /// What was checked and found fine: the configuration checks that passed, and a complete bill
    /// of materials.
    pub fn passed(&self) -> Vec<sv_check::Verified> {
        let mut passed = self.config.passed.clone();
        passed.extend(sv_check::sbom::completeness_verified(
            &self.bill_of_materials,
        ));
        passed
    }

    /// What the checks that read the app's files could not do, for the exit status.
    pub fn file_gaps(&self) -> crate::exit::Gaps {
        crate::exit::Gaps::of_files(&self.listing, &self.secrets, &self.code)
    }

    /// The checks that read the app's files, per family, for `examined`. Each one read only part
    /// of the app when a symbolic link was not followed; the rules that read code, also when a
    /// file was not opened or did not parse, or a language had no parser; a single code rule, when
    /// it could not run or had not been taught a language here.
    pub fn examined(&self) -> Vec<sv_report::Examined> {
        let (listing, code, secrets, config) =
            (&self.listing, &self.code, &self.secrets, &self.config);
        let family = |rules: &str, short: Vec<String>| {
            if short.is_empty() {
                sv_report::Examined::ran(rules)
            } else {
                sv_report::Examined::partly(rules, short.join("; "))
            }
        };
        let mut links: Vec<String> = if listing.links.is_empty() {
            Vec::new()
        } else {
            vec![format!(
                "{} symbolic link(s) in the app were not followed",
                listing.links.len()
            )]
        };
        if !listing.special.is_empty() {
            links.push(format!(
                "{} entry(s) in the app that are not ordinary files were not opened",
                listing.special.len()
            ));
        }

        let mut code_short = links.clone();
        if !code.unread_files.is_empty() {
            code_short.push(format!(
                "{} file(s) in a language the rules read were not opened",
                code.unread_files.len()
            ));
        }
        if !code.unread_languages.is_empty() {
            let mut names: Vec<&str> = code.unread_languages.iter().map(String::as_str).collect();
            names.sort_unstable();
            code_short.push(format!("no parser for {}", names.join(", ")));
        }
        if !code.unparsed_files.is_empty() {
            code_short.push(format!(
                "{} file(s) did not parse cleanly",
                code.unparsed_files.len()
            ));
        }
        let mut examined = vec![family("ast.", code_short)];
        for broken in &code.broken_queries {
            examined.push(sv_report::Examined::partly(
                broken.rule_id.clone(),
                format!(
                    "its query for {} would not compile: {}",
                    broken.language, broken.why
                ),
            ));
        }
        for held in &code.held_back_by_packages {
            examined.push(sv_report::Examined::partly(
                held.rule_id.clone(),
                held_back_why(held),
            ));
        }
        for untaught in &code.untaught {
            examined.push(sv_report::Examined::partly(
                untaught.rule_id.clone(),
                format!("it has not been taught {}", untaught.languages.join(", ")),
            ));
        }

        let mut secrets_short = links.clone();
        if !secrets.coverage.skipped.is_empty() {
            secrets_short.push(format!(
                "{} file(s) were not read",
                secrets.coverage.skipped.len()
            ));
        }
        examined.push(family("secrets.", secrets_short));

        examined.push(family("config.", links));
        for (id, why) in &config.not_assessed {
            examined.push(sv_report::Examined::not_run(id.clone(), why.clone()));
        }
        examined
    }

    /// The rules whose clean result a package the app uses held back, as gaps in the written report.
    pub(crate) fn package_gaps(&self) -> Vec<sv_report::Gap> {
        (self.code.held_back_by_packages.iter())
            .map(|held| sv_report::Gap {
                what: format!(
                    "{}, for code that goes through {}",
                    held.rule_id, held.package
                ),
                why: held_back_why(held),
                reason: sv_report::GapReason::NoReader,
                requirements: Vec::new(),
            })
            .collect()
    }
}

/// Why a package the app uses kept a code rule from claiming anything, in the words both the gap and
/// the `examined` entry use.
fn held_back_why(held: &sv_check::ast::HeldBackByPackage) -> String {
    format!(
        "the app uses {} ({}), which builds queries through calls of its own this rule does not \
         read ({}), so finding nothing is not evidence; what it found stands",
        held.package, held.ecosystem, held.calls
    )
}

/// The findings as every report lists them and every exit status counts them, from `findings`
/// (the static scan's, and whatever else the run found): the same weakness on the same line from
/// two tools merged into one; test code, a folder the manifest sets apart, and a bundled library
/// marked; the decisions held to the running app (`decided`) and then what a person set aside
/// through `sv review` applied (`reviews`, ADR-023); and one finding per line of code. `examined`
/// is what this run looked at, complete, so an entry that matches nothing can say whether its rule
/// looked (deep review R3).
#[allow(clippy::too_many_arguments)]
pub fn settle(
    app_dir: &Path,
    reviews: &[sv_manifest::FindingReview],
    findings: Vec<sv_check::Finding>,
    scan: &StaticScan,
    examined: &[sv_report::Examined],
    loaded: &Loaded,
    seals: &sv_check::seal::Checker,
    decided: &[sv_check::decisions::Decided],
) -> sv_check::review::Outcome {
    // The same weakness on the same line, reported by two tools, is one thing to fix.
    let mut findings = sv_check::finding::merge_same_place(findings);
    // Rust keeps its unit tests beside the code, so the file's name cannot say which is which.
    sv_check::finding::mark_rust_test_code(app_dir, &mut findings);
    // What the manifest says is not the app is listed with test and sample code, as the scan used
    // it: none when the list would have set apart all the app's code (ADR-031).
    sv_check::finding::mark_not_the_app(&scan.scan_report.not_the_app, &mut findings);
    // A copy of another project's library kept in the app is listed apart, named for it.
    sv_check::bundled::mark_bundled_libraries(app_dir, &mut findings);
    let lookup = ReviewLookup {
        app_dir,
        examined,
        listing: &scan.listing,
        code: &scan.code,
        secrets: &scan.secrets,
        ast_rules: &loaded.ast_rules,
        secret_rules: &loaded.secret_rules,
    };
    decisions_then_reviews(findings, decided, |mut findings| {
        sv_check::review::fill_fingerprints(app_dir, &mut findings);
        sv_check::review::apply(
            app_dir,
            reviews,
            findings,
            sv_check::advisories::Day::today().unwrap_or(sv_check::advisories::Day(0)),
            seals,
            &|rule, file| lookup.looked(rule, file),
        )
    })
}
