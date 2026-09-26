//! The checks that produce findings: what is wrong with this app, and what it is evidence about.
//!
//! `sv-scan` answers questions about what the app *is*. This answers what is *wrong with it*. The two are
//! kept apart because they fail differently: a scanner that cannot tell whether an app uses XML makes a
//! requirement not-assessed, while a check that cannot run makes a finding absent — and an absent finding
//! looks exactly like a clean result unless something says otherwise. `Coverage` is that something.

pub mod adapters;
pub mod advisories;
pub mod ast;
pub mod config;
pub mod cvss;
pub mod design;
pub mod finding;
pub mod human;
pub mod junit;
pub mod notes;
pub mod probes;
pub mod sbom;
pub mod secrets;
pub mod signed_in;
pub mod suite;
pub mod verified;

pub use finding::{Confidence, Finding, Location, Secret, Severity};
pub use sbom::{Sbom, build as build_sbom, to_cyclonedx};
pub use secrets::{SecretRules, SecretScan, scan_text};
pub use verified::Verified;
