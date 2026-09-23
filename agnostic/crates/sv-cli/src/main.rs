//! `sv` — run the SecureVibe checks against code written anywhere, in any language.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, Condition, bucket};
use sv_manifest::{ClaimState, Manifest, spec};

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
    let config = ApplicabilityConfig::load(&data.join("knowledge"))?;

    // No corroborators are wired up yet, so every claim is unverifiable and says so. This is the
    // honest state of the tool today, not a placeholder that reads as a clean result.
    let (ctx, resolved) = sv_manifest::resolve(&manifest, &|_| None);
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
    println!(
        "\n{} requirements apply, {} do not, {} are above this level ({} loaded).",
        buckets.applicable.len(),
        buckets.not_applicable.len(),
        buckets.out_of_level.len(),
        frameworks.len()
    );

    let unverifiable = resolved
        .iter()
        .filter(|r| r.state == ClaimState::Unverifiable && r.claimed)
        .count();
    if unverifiable > 0 {
        println!(
            "\n{unverifiable} of the manifest's claims are asserted and not verified: nothing in \
             `sv` checks them against the code yet."
        );
    }

    // `never` rules carry reasons written about v1's Node template — "this app is written in
    // TypeScript for Node.js", "there is no CI/CD pipeline in a local build". They are claims about
    // a stack `sv` cannot assume, so they are counted and flagged, not printed as if true.
    let inherited: Vec<_> = buckets
        .not_applicable
        .iter()
        .filter(|na| na.condition == Condition::Never)
        .collect();
    if !inherited.is_empty() {
        println!(
            "\n{} of the {} exclusions come from fixed rules written for SecureVibe's own Node\n\
             template, not from this app. Their stated reasons are not safe to repeat here, and\n\
             these requirements are reported as NOT ASSESSED until v2 derives them from the code.",
            inherited.len(),
            buckets.not_applicable.len()
        );
    }

    println!("\nDoes not apply:");
    for na in buckets
        .not_applicable
        .iter()
        .filter(|na| na.condition != Condition::Never)
        .take(12)
    {
        println!("  {} — {}", na.id, na.reason);
    }
    let shown = buckets.not_applicable.len() - inherited.len();
    if shown > 12 {
        println!("  … and {} more", shown - 12);
    }
    Ok(())
}
