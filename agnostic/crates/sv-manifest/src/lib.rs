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
use sv_frameworks::Condition;
use sv_frameworks::applicability::ConditionContext;

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
    pub enabled: Option<bool>,
    #[serde(default)]
    pub can_act: Option<bool>,
    #[serde(default)]
    pub stores_history: Option<bool>,
    #[serde(default)]
    pub moderation: Option<bool>,
    #[serde(default)]
    pub rag: Option<bool>,
    #[serde(default)]
    pub mcp: Option<bool>,
    #[serde(default)]
    pub training: Option<bool>,
    /// Does this app host, build or deploy model files of its own, rather than calling a vendor's
    /// hosted model? Thirty AISVS requirements turn on this one answer.
    #[serde(default)]
    pub self_hosted: Option<bool>,
    #[serde(default)]
    pub multi_agent: Option<bool>,
    /// Does the assistant take images, video or audio, rather than typed text only?
    #[serde(default)]
    pub multimodal: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub auth: Option<bool>,
    #[serde(default)]
    pub oauth: Option<bool>,
    #[serde(default)]
    pub jwt: Option<bool>,
    #[serde(default)]
    pub uploads: Option<bool>,
    #[serde(default)]
    pub payments: Option<bool>,
    #[serde(default)]
    pub email: Option<bool>,
    #[serde(default)]
    pub public_api: Option<bool>,
    #[serde(default)]
    pub scheduler: Option<bool>,
    #[serde(default)]
    pub multi_tenant: Option<bool>,
    #[serde(default)]
    pub webrtc: Option<bool>,
    #[serde(default)]
    pub external_apis: Option<Vec<String>>,
    #[serde(default)]
    pub tls: TlsMode,
    /// Sign-in codes sent by phone, SMS or push notification.
    #[serde(default)]
    pub out_of_band_auth: Option<bool>,
    /// Do other applications share this app's hostname?
    #[serde(default)]
    pub shared_hostname: Option<bool>,
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

/// How the code is developed and shipped. v1 knew the answers because it wrote the code into a
/// folder on one computer; `sv` is handed a repository and must ask.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RepositorySection {
    /// A CI/CD pipeline: GitHub Actions, GitLab CI, Jenkins or similar.
    #[serde(default)]
    pub ci_cd: Option<bool>,
    /// Hosted source control with branch protection or a merge queue.
    #[serde(default)]
    pub hosted_scm: Option<bool>,
    /// Code contributions from people outside the team.
    #[serde(default)]
    pub outside_contributors: Option<bool>,
    /// Infrastructure or pipeline configuration in the repository (Terraform, CloudFormation, CI
    /// workflow files).
    #[serde(default)]
    pub iac: Option<bool>,
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
    #[serde(default)]
    pub repository: RepositorySection,
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

    /// Every condition this manifest claims, before any corroboration. `None` means the manifest
    /// is silent, which is not the same as claiming "no" and must not be flattened into one.
    pub fn claims(&self) -> Vec<(Condition, Option<bool>)> {
        let c = &self.capabilities;
        let ai = c.ai.enabled;
        // A sub-claim about the AI is only meaningful once there is an AI. When the manifest says
        // there is none, its sub-claims are a definite no; when it is silent about the AI itself,
        // they stay unknown however they were filled in.
        let about_ai = |v: Option<bool>| match ai {
            Some(false) => Some(false),
            Some(true) => v,
            None => None,
        };
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
            (
                Condition::ExternalApis,
                c.external_apis.as_ref().map(|v| !v.is_empty()),
            ),
            (Condition::Tls, Some(c.tls != TlsMode::Off)),
            (
                Condition::Internet,
                Some(self.app.deployment == Deployment::Internet),
            ),
            (Condition::Ai, ai),
            (Condition::AiActions, about_ai(c.ai.can_act)),
            (Condition::AiHistory, about_ai(c.ai.stores_history)),
            (Condition::AiModeration, about_ai(c.ai.moderation)),
            (Condition::Rag, about_ai(c.ai.rag)),
            (Condition::Mcp, about_ai(c.ai.mcp)),
            (Condition::Training, about_ai(c.ai.training)),
            (Condition::Level2, Some(self.target_level() == 2)),
            // v2: the answers that replace the `never` rules describing v1's own template.
            (Condition::SelfHostedModel, about_ai(c.ai.self_hosted)),
            (Condition::MultiAgent, about_ai(c.ai.multi_agent)),
            (Condition::MultimodalAi, about_ai(c.ai.multimodal)),
            (Condition::OutOfBandAuth, c.out_of_band_auth),
            (Condition::SharedHostname, c.shared_hostname),
            (Condition::CiCd, self.repository.ci_cd),
            (Condition::HostedScm, self.repository.hosted_scm),
            (
                Condition::OutsideContributors,
                self.repository.outside_contributors,
            ),
            (Condition::Iac, self.repository.iac),
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
    /// The manifest is silent and nothing in the code answered it. Not a "no" — the requirement
    /// is reported as not assessed.
    Unanswered,
}

#[derive(Debug, Clone)]
pub struct ResolvedClaim {
    pub condition: Condition,
    pub claimed: Option<bool>,
    /// Whether a corroborator found the capability in the code.
    pub found_in_code: Option<bool>,
    pub state: ClaimState,
    /// What the pipeline acts on. `None` when nothing answered it.
    pub effective: Option<bool>,
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
        let effective = match (claimed, found_in_code) {
            // Either saying yes is a yes. Corroboration only ever adds requirements.
            (Some(true), _) | (_, Some(true)) => Some(true),
            // Nobody has said anything. Silence is not a no.
            (None, None) => None,
            // An explicit no from the owner, or from the code, with nothing contradicting it.
            _ => Some(false),
        };
        let state = match (claimed, found_in_code) {
            (None, None) => ClaimState::Unanswered,
            (Some(false), Some(true)) => ClaimState::Contradicted,
            (None, Some(true)) => ClaimState::Contradicted,
            (Some(true), Some(false)) => ClaimState::Unsupported,
            (Some(_), None) => ClaimState::Unverifiable,
            (None, Some(false)) => ClaimState::Unverifiable,
            (Some(true), Some(true)) | (Some(false), Some(false)) => ClaimState::Confirmed,
        };
        if let Some(value) = effective {
            ctx.set(condition, value);
        }
        resolved.push(ResolvedClaim {
            condition,
            claimed,
            found_in_code,
            state,
            effective,
        });
    }

    // Conditions the manifest never claims — the `derived` ones, which the code answers rather
    // than the owner — still need their answer carried through. Without this the scanner runs,
    // finds things, and nothing downstream ever hears about it.
    let claimed: Vec<Condition> = resolved.iter().map(|r| r.condition).collect();
    for condition in Condition::ALL.iter().copied() {
        if claimed.contains(&condition) {
            continue;
        }
        if let Some(value) = corroboration(condition) {
            ctx.set(condition, value);
            resolved.push(ResolvedClaim {
                condition,
                claimed: None,
                found_in_code: Some(value),
                state: ClaimState::Confirmed,
                effective: Some(value),
            });
        }
    }

    // `no-auth` is the inverse of the resolved `auth`, never an independent claim: an app cannot be
    // both, and deriving it here keeps the two from drifting apart. Unknown `auth` leaves `no-auth`
    // unknown too, rather than quietly asserting the app has no sign-in.
    if let Some(auth) = ctx.get(Condition::Auth) {
        ctx.set(Condition::NoAuth, !auth);
    }
    (ctx, resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_evidence_overrides_a_claim_of_no() {
        let mut m = Manifest::default();
        m.capabilities.payments = Some(false);
        let (ctx, resolved) = resolve(&m, &|c| (c == Condition::Payments).then_some(true));
        assert_eq!(
            ctx.get(Condition::Payments),
            Some(true),
            "a Stripe SDK in the code must switch payment requirements on despite the manifest"
        );
        assert_eq!(
            state_of(&resolved, Condition::Payments),
            ClaimState::Contradicted
        );
    }

    #[test]
    fn a_claim_with_no_evidence_still_applies() {
        let mut m = Manifest::default();
        m.capabilities.uploads = Some(true);
        let (ctx, resolved) = resolve(&m, &|c| (c == Condition::Uploads).then_some(false));
        assert_eq!(ctx.get(Condition::Uploads), Some(true));
        assert_eq!(
            state_of(&resolved, Condition::Uploads),
            ClaimState::Unsupported
        );
    }

    #[test]
    fn a_claim_nobody_can_check_is_unverifiable_not_confirmed() {
        let mut m = Manifest::default();
        m.capabilities.multi_tenant = Some(true);
        let (ctx, resolved) = resolve(&m, &|_| None);
        assert_eq!(
            state_of(&resolved, Condition::MultiTenant),
            ClaimState::Unverifiable
        );
        assert_eq!(
            ctx.get(Condition::MultiTenant),
            Some(true),
            "an unverifiable claim still applies"
        );
    }

    #[test]
    fn silence_is_not_a_no() {
        // The manifest says nothing about CI/CD and no corroborator answered. v1 could treat every
        // condition as answered because the wizard asked about all of them; `sv` cannot, and
        // `serde(default)` turning silence into `false` would quietly exclude ten requirements.
        let m = Manifest::default();
        let (ctx, resolved) = resolve(&m, &|_| None);
        assert_eq!(
            ctx.get(Condition::CiCd),
            None,
            "an unanswered claim must stay unanswered, not become a no"
        );
        assert_eq!(state_of(&resolved, Condition::CiCd), ClaimState::Unanswered);
    }

    #[test]
    fn an_explicit_no_is_honoured_where_silence_is_not() {
        // The owner's own deliberate "no" is worth something; the absence of an answer is not.
        let mut silent = Manifest::default();
        silent.capabilities.ai.enabled = Some(true);
        let (quiet_ctx, _) = resolve(&silent, &|_| None);
        assert_eq!(quiet_ctx.get(Condition::MultiAgent), None);

        let mut stated = silent.clone();
        stated.capabilities.ai.multi_agent = Some(false);
        let (loud_ctx, _) = resolve(&stated, &|_| None);
        assert_eq!(loud_ctx.get(Condition::MultiAgent), Some(false));
    }

    #[test]
    fn ai_sub_claims_are_settled_by_there_being_no_ai() {
        let mut m = Manifest::default();
        m.capabilities.ai.enabled = Some(false);
        let (ctx, _) = resolve(&m, &|_| None);
        for c in [
            Condition::AiActions,
            Condition::Rag,
            Condition::Mcp,
            Condition::Training,
            Condition::SelfHostedModel,
            Condition::MultiAgent,
        ] {
            assert_eq!(ctx.get(c), Some(false), "{} with no AI at all", c.name());
        }
    }

    #[test]
    fn an_unanswered_ai_leaves_its_sub_claims_unanswered() {
        // Filling in "the assistant does not use MCP" while never saying whether there is an
        // assistant is not an answer about this app.
        let mut m = Manifest::default();
        m.capabilities.ai.mcp = Some(false);
        let (ctx, _) = resolve(&m, &|_| None);
        assert_eq!(ctx.get(Condition::Ai), None);
        assert_eq!(ctx.get(Condition::Mcp), None);
    }

    #[test]
    fn no_auth_is_derived_from_resolved_auth_not_claimed_auth() {
        let m = Manifest::default();
        let (ctx, _) = resolve(&m, &|c| (c == Condition::Auth).then_some(true));
        assert_eq!(ctx.get(Condition::Auth), Some(true));
        assert_eq!(
            ctx.get(Condition::NoAuth),
            Some(false),
            "code found sign-in, so requirements written for apps without accounts must not apply"
        );
    }

    #[test]
    fn unknown_auth_leaves_no_auth_unknown() {
        let m = Manifest::default();
        let (ctx, _) = resolve(&m, &|_| None);
        assert_eq!(ctx.get(Condition::Auth), None);
        assert_eq!(
            ctx.get(Condition::NoAuth),
            None,
            "not knowing whether there is sign-in must not assert that there is none"
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

    #[test]
    fn the_scanner_answers_conditions_the_manifest_never_claims() {
        // The `derived` conditions are not claims, so they never appear in `claims()`. Without
        // carrying them through, the scanner runs, finds an XML parser, and nothing downstream
        // ever hears about it — the requirement stays not-assessed while the evidence sits there.
        let m = Manifest::default();
        let (ctx, resolved) = resolve(&m, &|c| (c == Condition::Xml).then_some(true));
        assert_eq!(ctx.get(Condition::Xml), Some(true));
        assert!(
            resolved.iter().any(|r| r.condition == Condition::Xml),
            "a scanner answer must be recorded, not only applied"
        );
    }

    #[test]
    fn an_unanswered_derived_condition_stays_unanswered() {
        let m = Manifest::default();
        let (ctx, _) = resolve(&m, &|_| None);
        assert_eq!(ctx.get(Condition::Xml), None);
    }

    fn state_of(resolved: &[ResolvedClaim], c: Condition) -> ClaimState {
        resolved.iter().find(|r| r.condition == c).unwrap().state
    }
}
