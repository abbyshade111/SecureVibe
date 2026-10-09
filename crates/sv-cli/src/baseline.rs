//! `--baseline <older report folder>`: fail CI only on what is new (backlog 0191, part 1; ADR-029,
//! Later, 9 October 2026).
//!
//! With `--fail-on attention`, a finding the older report already held does not set exit 1, so a
//! team can start using `sv` on an app with findings it already knows about. Nothing else changes:
//! every finding is still listed and counted, each one the baseline holds is marked so, and exit 2
//! and 3 are as they were. A baseline that cannot be read, or that names another app, stops the
//! run: comparing against nothing would let every finding through as "already there".

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The findings an older report held, by fingerprint, and the app it was made for.
#[derive(Debug, Clone)]
pub struct Baseline {
    /// The folder as it was given.
    pub folder: PathBuf,
    /// Every fingerprint the older report's findings carried, earlier forms included.
    held: BTreeSet<String>,
    /// The app the older report was made for, as its `report.json` names it.
    pub app_name: String,
}

impl Baseline {
    /// `--baseline <folder>` taken out of `args`, the rest left in order.
    pub fn take(args: &[String]) -> Result<(Option<PathBuf>, Vec<String>)> {
        let mut folder = None;
        let mut rest = Vec::new();
        let mut words = args.iter();
        while let Some(word) = words.next() {
            if let Some(value) = word.strip_prefix("--baseline=") {
                folder = Some(PathBuf::from(value));
            } else if word == "--baseline" {
                let value = words
                    .next()
                    .context("--baseline needs the folder of an older report")?;
                folder = Some(PathBuf::from(value));
            } else {
                rest.push(word.clone());
            }
        }
        Ok((folder, rest))
    }

    /// The older report in `folder`, read from its `report.json`.
    pub fn load(folder: &Path) -> Result<Baseline> {
        let path = folder.join("report.json");
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "--baseline {}: there is no report.json to compare with there ({})",
                folder.display(),
                path.display()
            )
        })?;
        let json: serde_json::Value = serde_json::from_str(&text).with_context(|| {
            format!(
                "--baseline {}: report.json is not a report `sv` wrote",
                folder.display()
            )
        })?;
        let (Some(app_name), Some(findings)) =
            (json["app_name"].as_str(), json["findings"].as_array())
        else {
            bail!(
                "--baseline {}: report.json has no app name or no list of findings, so it is not a \
                 report `sv` wrote",
                folder.display()
            );
        };
        let mut held = BTreeSet::new();
        for f in findings {
            if let Some(fp) = f["fingerprint"].as_str().filter(|s| !s.is_empty()) {
                held.insert(fp.to_owned());
            }
            for fp in f["earlier_fingerprints"].as_array().into_iter().flatten() {
                if let Some(fp) = fp.as_str().filter(|s| !s.is_empty()) {
                    held.insert(fp.to_owned());
                }
            }
        }
        Ok(Baseline {
            folder: folder.to_path_buf(),
            held,
            app_name: app_name.to_owned(),
        })
    }

    /// Stops the run when the older report names another app. Only the name is recorded, so
    /// two apps of one name are not told apart.
    pub fn same_app(&self, app_name: &str) -> Result<()> {
        if self.app_name != app_name {
            bail!(
                "--baseline {}: that report is for \"{}\", and this app is \"{}\". Comparing with \
                 another app's findings would let this one's through as already there.",
                self.folder.display(),
                self.app_name,
                app_name
            );
        }
        Ok(())
    }

    /// Whether the older report held `f`, by its fingerprint or an earlier form of it.
    pub fn holds(&self, f: &sv_check::Finding) -> bool {
        (!f.fingerprint.is_empty() && self.held.contains(&f.fingerprint))
            || f.earlier_fingerprints
                .iter()
                .any(|fp| !fp.is_empty() && self.held.contains(fp))
    }

    /// What the report records: the folder, and the fingerprints of `findings` this holds.
    pub fn note(&self, findings: &[sv_check::Finding]) -> sv_report::BaselineNote {
        sv_report::BaselineNote {
            folder: self.folder.display().to_string(),
            held: findings
                .iter()
                .filter(|f| self.holds(f))
                .map(|f| f.fingerprint.clone())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
