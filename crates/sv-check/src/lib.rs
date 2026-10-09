//! The checks that produce findings: what is wrong with this app, and what it is evidence about.
//!
//! `sv-scan` answers questions about what the app *is*. This answers what is *wrong with it*. The two are
//! kept apart because they fail differently: a scanner that cannot tell whether an app uses XML makes a
//! requirement not-assessed, while a check that cannot run makes a finding absent — and an absent finding
//! looks exactly like a clean result unless something says otherwise. `Coverage` is that something.

pub mod adapters;
pub mod advisories;
pub mod ai;
pub mod ai_tool;
pub mod ast;
pub mod browser;
pub mod browser_storage;
pub mod bundled;
pub mod cert_checks;
pub mod client_tech;
pub mod coding_rules;
pub mod config;
pub mod confirm;
pub mod cvss;
pub mod cvss4;
mod cvss4_tables;
pub mod decisions;
pub mod design;
pub mod fetch;
pub mod finding;
pub mod git;
pub mod grants;
pub mod hand;
pub mod hosted_rules;
pub mod human;
pub mod junit;
pub mod launch;
pub mod level_hints;
pub mod live_tls;
pub mod logs;
pub mod manifest_lock;
pub mod mcp_server;
pub mod model_files;
pub mod notes;
pub mod oidc;
pub mod probes;
pub mod production;
pub mod prompts;
pub mod public_keys;
pub mod review;
pub mod rich_text;
pub mod running;
pub mod sbom;
pub mod script;
pub mod seal;
pub mod secrets;
pub mod signed;
pub mod signed_in;
mod ssh_format;
pub mod stand_in;
pub mod suite;
pub mod test_report;
#[cfg(test)]
pub(crate) mod test_support;
pub mod totp;
pub mod verified;
pub mod workflows;

pub use finding::{Confidence, Finding, Location, Secret, Severity};
pub use sbom::{Sbom, build as build_sbom, to_cyclonedx};
pub use secrets::{SecretRules, SecretScan, scan_text};
pub use verified::{Tier, Verified};
