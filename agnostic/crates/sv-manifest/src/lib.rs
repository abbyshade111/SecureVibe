//! `securevibe.toml` — what the app claims about itself, and what those claims are worth.
//!
//! This replaces the wizard. The user's AI coding tool writes this file during the back-and-forth
//! that builds the app; `sv init` prints the spec to hand it.
//!
//! Nothing in here is treated as a fact. Every capability is a **claim**, and `sv-corroborate`
//! tries to find evidence for it in the code. The rule that makes a manifest safe to drive an
//! ASVS assessment from is in `resolve`: corroboration only ever moves toward more requirements
//! applying, never fewer.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use sv_frameworks::applicability::{Condition, ConditionContext};

pub mod spec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Audience {
    JustMe,
    MyTeam,
    #[default]
    Customers,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Deployment {
    LocalOnly,
    LocalNetwork,
    #[default]
    Internet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    Off,
    #[serde(rename = "self")]
    SelfSigned,
    #[default]
    TerminatedUpstream,
}

/// Data categories that raise the ASVS target level to 2, carried over from v1's
/// `SENSITIVE_DATA_CATEGORIES`.
pub const SENSITIVE_DATA_CATEGORIES: &[&str] = &[
    "financial",
    "payment-card",
    "health",
    "government-id",
    "children",
];

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AppSection {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub audience: Audience,
    #[serde(default)]
    pub deployment: Deployment,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AiClaims {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub can_act: bool,
    #[serde(default)]
    pub stores_history: bool,
    #[serde(default)]
    pub moderation: bool,
    #[serde(default)]
    pub rag: bool,
    #[serde(default)]
    pub mcp: bool,
    #[serde(default)]
    pub training: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub auth: bool,
    #[serde(default)]
    pub oauth: bool,
    #[serde(default)]
    pub jwt: bool,
    #[serde(default)]
    pub uploads: bool,
    #[serde(default)]
    pub payments: bool,
    #[serde(default)]
    pub email: bool,
    #[serde(default)]
    pub public_api: bool,
    #[serde(default)]
    pub scheduler: bool,
    #[serde(default)]
    pub multi_tenant: bool,
    #[serde(default)]
    pub webrtc: bool,
    #[serde(default)]
    pub external_apis: Vec<String>,
    #[serde(default)]
    pub tls: TlsMode,
    #[serde(default)]
    pub ai: AiClaims,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RunSection {
    /// Container image to run the app in. Absent means `sv` cannot run it and says so.
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub build: Option<String>,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub test: Option<String>,
    #[serde(default)]
    pub health: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct StackSection {
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub run: RunSection,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DataSection {
    #[serde(default)]
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub manifest_version: u32,
    #[serde(default)]
    pub app: AppSection,
    #[serde(default)]
    pub stack: StackSection,
    #[serde(default)]
    pub data: DataSection,
    #[serde(default)]
    pub capabilities: Capabilities,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// The ASVS target level. Sensitive data or a public audience means level 2, as in v1.
    pub fn target_level(&self) -> u8 {
        let sensitive = self
            .data
            .categories
            .iter()
            .any(|c| SENSITIVE_DATA_CATEGORIES.contains(&c.as_str()));
        let exposed = matches!(self.app.audience, Audience::Customers | Audience::Public);
        if sensitive || exposed { 2 } else { 1 }
    }

    /// Every condition this manifest claims, before any corroboration.
    pub fn claims(&self) -> Vec<(Condition, bool)> {
        let c = &self.capabilities;
        let ai = c.ai.enabled;
        vec![
            (Condition::Auth, c.auth),
            (Condition::Oauth, c.oauth),
            (Condition::Jwt, c.jwt),
            (Condition::Uploads, c.uploads),
            (Condition::Payments, c.payments),
            (Condition::Email, c.email),
            (Condition::PublicApi, c.public_api),
            (Condition::Scheduler, c.scheduler),
            (Condition::MultiTenant, c.multi_tenant),
            (Condition::Webrtc, c.webrtc),
            (Condition::ExternalApis, !c.external_apis.is_empty()),
            (Condition::Tls, c.tls != TlsMode::Off),
            (
                Condition::Internet,
                self.app.deployment == Deployment::Internet,
            ),
            (Condition::Ai, ai),
            (Condition::AiActions, ai && c.ai.can_act),
            (Condition::AiHistory, ai && c.ai.stores_history),
            (Condition::AiModeration, ai && c.ai.moderation),
            (Condition::Rag, ai && c.ai.rag),
            (Condition::Mcp, ai && c.ai.mcp),
            (Condition::Training, c.ai.training),
            (Condition::Level2, self.target_level() == 2),
        ]
    }
}

/// What corroboration found in the code for a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimState {
    /// Claim says yes, and the code agrees.
    Confirmed,
    /// Claim says no, and the code says otherwise. The code wins, and this is a finding.
    Contradicted,
    /// Claim says yes, nothing in the code shows it. Applies anyway; not treated as evidence.
    Unsupported,
    /// No corroborator exists for this claim. Reports say "asserted, not verified".
    Unverifiable,
}

#[derive(Debug, Clone)]
pub struct ResolvedClaim {
    pub condition: Condition,
    pub claimed: bool,
    /// Whether a corroborator found the capability in the code.
    pub found_in_code: Option<bool>,
    pub state: ClaimState,
    /// What the pipeline acts on: `claimed || found_in_code`.
    pub effective: bool,
}

/// Turns claims plus corroboration into the context the applicability engine runs on.
///
/// The one rule that matters: `effective = claimed || found_in_code`. A claim of "no" cannot
/// switch off a requirement the code says applies, and a claim of "yes" is honoured even when
/// nothing corroborates it. Both directions add requirements; neither removes one.
///
/// The asymmetry is the safety argument. A wrong claim costs the user a requirement they did not
/// need to meet — never a requirement they needed and were told they did not.
pub fn resolve(
    manifest: &Manifest,
    corroboration: &dyn Fn(Condition) -> Option<bool>,
) -> (ConditionContext, Vec<ResolvedClaim>) {
    let mut ctx = ConditionContext::default();
    let mut resolved = Vec::new();

    for (condition, claimed) in manifest.claims() {
        let found_in_code = corroboration(condition);
        let effective = claimed || found_in_code.unwrap_or(false);
        let state = match (claimed, found_in_code) {
            (_, None) => ClaimState::Unverifiable,
            (true, Some(true)) => ClaimState::Confirmed,
            (true, Some(false)) => ClaimState::Unsupported,
            (false, Some(true)) => ClaimState::Contradicted,
            // Claimed no, and nothing found. Corroborators have partial coverage, so this is
            // "nothing to contradict it", not proof of absence.
            (false, Some(false)) => ClaimState::Confirmed,
        };
        ctx.set(condition, effective);
        resolved.push(ResolvedClaim {
            condition,
            claimed,
            found_in_code,
            state,
            effective,
        });
    }

    // `no-auth` is the inverse of the resolved `auth`, never an independent claim: an app cannot
    // be both, and deriving it here keeps the two from drifting apart.
    ctx.set(Condition::NoAuth, !ctx.holds(Condition::Auth));
    (ctx, resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_claiming_no_payments() -> Manifest {
        Manifest::default()
    }

    #[test]
    fn code_evidence_overrides_a_claim_of_no() {
        let m = manifest_claiming_no_payments();
        let (ctx, resolved) = resolve(&m, &|c| (c == Condition::Payments).then_some(true));
        assert!(
            ctx.holds(Condition::Payments),
            "a Stripe SDK in the code must switch payment requirements on despite the manifest"
        );
        let payments = resolved
            .iter()
            .find(|r| r.condition == Condition::Payments)
            .unwrap();
        assert_eq!(payments.state, ClaimState::Contradicted);
    }

    #[test]
    fn a_claim_with_no_evidence_still_applies() {
        let mut m = Manifest::default();
        m.capabilities.uploads = true;
        let (ctx, resolved) = resolve(&m, &|c| (c == Condition::Uploads).then_some(false));
        assert!(ctx.holds(Condition::Uploads));
        let uploads = resolved
            .iter()
            .find(|r| r.condition == Condition::Uploads)
            .unwrap();
        assert_eq!(uploads.state, ClaimState::Unsupported);
    }

    #[test]
    fn a_claim_nobody_can_check_is_unverifiable_not_confirmed() {
        let mut m = Manifest::default();
        m.capabilities.multi_tenant = true;
        let (_, resolved) = resolve(&m, &|_| None);
        let mt = resolved
            .iter()
            .find(|r| r.condition == Condition::MultiTenant)
            .unwrap();
        assert_eq!(mt.state, ClaimState::Unverifiable);
        assert!(mt.effective, "an unverifiable claim still applies");
    }

    #[test]
    fn no_auth_is_derived_from_resolved_auth_not_claimed_auth() {
        let m = Manifest::default(); // claims auth = false
        let (ctx, _) = resolve(&m, &|c| (c == Condition::Auth).then_some(true));
        assert!(ctx.holds(Condition::Auth));
        assert!(
            !ctx.holds(Condition::NoAuth),
            "code found sign-in, so requirements written for apps without accounts must not apply"
        );
    }

    #[test]
    fn sensitive_data_raises_the_target_level() {
        let mut m = Manifest::default();
        m.app.audience = Audience::JustMe;
        assert_eq!(m.target_level(), 1);
        m.data.categories = vec!["health".into()];
        assert_eq!(m.target_level(), 2);
    }
}
