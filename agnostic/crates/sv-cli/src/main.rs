//! `sv` — run the SecureVibe checks against code written anywhere, in any language.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, bucket};
use sv_frameworks::{Condition, Source};
use sv_manifest::{ClaimState, Manifest, spec};
use sv_scan::{Evidence, Signatures, scan};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") => {
            println!("{}", spec::STARTER_MANIFEST);
            println!("{}", spec::INSTRUCTIONS);
            Ok(())
        }
        Some("scope") => cmd_scope(args.get(1).map(PathBuf::from)),
        Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => {
            print_help();
            bail!("unknown command: {other}");
        }
    }
}

fn print_help() {
    println!(
        "sv — check an app against OWASP ASVS 5.0, AISVS 1.0 and Secure by Design.\n\n\
         USAGE:\n  \
         sv init            print the securevibe.toml spec to hand to your AI coding tool\n  \
         sv scope [PATH]    show which requirements apply to the app, and why\n"
    );
}

/// Where the OWASP data lives. Shared with v1 rather than copied, so an ASVS correction fixes both.
fn data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("SV_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    // From the workspace, the repository's own `data` folder is one level up.
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = here.join("../../../data");
    if candidate.join("frameworks").is_dir() {
        return Ok(candidate);
    }
    bail!("cannot find the OWASP data folder; set SV_DATA_DIR")
}

/// The v2 overlay, which replaces the applicability rules whose reasons describe v1's own template.
fn overlay_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/applicability-v2.json")
}

/// What each `derived` condition looks like in real code.
fn signatures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/tech-signatures.json")
}

fn cmd_scope(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let manifest_path = app_dir.join("securevibe.toml");
    if !manifest_path.exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    let manifest = Manifest::load(&manifest_path)?;

    let data = data_dir()?;
    let frameworks =
        Frameworks::load(&data.join("frameworks")).context("loading the OWASP frameworks")?;
    let overlay = overlay_path();
    let config = ApplicabilityConfig::load_v2(&data.join("knowledge"), &overlay)?;

    // The scanner answers the `derived` conditions. It answers nothing a claim is responsible
    // for, so every claim is still unverifiable — corroborators are the next piece of work.
    let signatures = Signatures::load(&signatures_path())?;
    let report = scan(&app_dir, &signatures)?;
    let (ctx, resolved) = sv_manifest::resolve(&manifest, &report.as_corroborator());
    let buckets = bucket(&frameworks, &config, &ctx, manifest.target_level());

    println!(
        "{} — ASVS level {}",
        if manifest.app.name.is_empty() {
            "(unnamed app)"
        } else {
            &manifest.app.name
        },
        manifest.target_level()
    );
    if !report.ecosystems.is_empty() {
        let names: Vec<&str> = report.ecosystems.iter().map(|e| e.name.as_str()).collect();
        println!(
            "\nRead {} source files in {}; package manifests: {}.",
            report.files_read,
            report
                .languages
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            names.join(", ")
        );
    }
    for eco in &report.unpinned {
        println!(
            "  {} pins no versions ({} has no lockfile), so what is actually installed cannot be known.",
            eco.name, eco.manifest
        );
    }
    if !report.unread_extensions.is_empty() {
        let exts: Vec<&str> = report
            .unread_extensions
            .iter()
            .map(String::as_str)
            .collect();
        println!(
            "  `sv` has no reader for these file types, so it cannot say a technology is absent: {}.",
            exts.join(", ")
        );
    }

    println!(
        "\n{} apply, {} do not, {} not assessed, {} above this level ({} loaded).",
        buckets.applicable.len(),
        buckets.not_applicable.len(),
        buckets.not_assessed.len(),
        buckets.out_of_level.len(),
        frameworks.len()
    );

    let unverifiable = resolved
        .iter()
        .filter(|r| r.state == ClaimState::Unverifiable && r.claimed == Some(true))
        .count();
    if unverifiable > 0 {
        println!(
            "\n{unverifiable} of the manifest's claims are asserted and not verified: nothing in \
             `sv` checks them against the code yet."
        );
    }

    let mut blocked: std::collections::BTreeMap<Condition, usize> = Default::default();
    for na in &buckets.not_assessed {
        for c in &na.blocked_on {
            *blocked.entry(*c).or_default() += 1;
        }
    }

    if !buckets.not_assessed.is_empty() {
        println!(
            "\n{} are NOT ASSESSED: something has to answer a question about this app before\n\
             anyone can say whether they apply. They are not passes and not exclusions.",
            buckets.not_assessed.len()
        );
        for (condition, n) in &blocked {
            let who = match condition.source() {
                Source::Claim => "securevibe.toml does not say",
                Source::Derived => "no scanner reads this from the code yet",
            };
            println!("  {n:>3}  {:<22} {who}", condition.name());
        }
    }

    // An exclusion resting on somebody's word is weaker than one resting on their dependencies,
    // and a report that prints them identically overstates the first.
    let claimed = buckets
        .not_applicable
        .iter()
        .filter(|na| na.source == Source::Claim)
        .count();
    let found: Vec<&sv_scan::Answer> = report
        .answers
        .iter()
        .filter(|a| a.value == Some(true))
        .collect();
    if !found.is_empty() {
        println!("\nRead from the code, so nobody had to be believed:");
        for a in &found {
            let how = match &a.evidence {
                Evidence::Dependency { name, manifest } => {
                    format!("`{name}` declared in {manifest}")
                }
                Evidence::Source { pattern, file } => format!("`{pattern}` in {file}"),
                Evidence::Language { language } => format!("the app contains {language}"),
                _ => String::new(),
            };
            println!("  {:<16} {how}", a.condition.name());
        }
    }
    println!(
        "\nDoes not apply: {} in total — {} because the manifest says so, {} read from the code.",
        buckets.not_applicable.len(),
        claimed,
        buckets.not_applicable.len() - claimed
    );
    for na in buckets.not_applicable.iter().take(8) {
        println!("  {} — {}", na.id, na.reason);
    }
    if buckets.not_applicable.len() > 8 {
        println!("  … and {} more", buckets.not_applicable.len() - 8);
    }
    Ok(())
}
