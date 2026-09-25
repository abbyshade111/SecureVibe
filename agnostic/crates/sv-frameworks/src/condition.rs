//! The conditions an applicability rule can test.
//!
//! v1 keeps this enum closed on purpose — "security decisions are keyed on these values" — and so does
//! `sv`. The macro defines each condition's name, its plain-language reason and its source in one place,
//! so the three cannot drift apart.
//!
//! **Source** is the part v2 adds. `Claim` means the answer comes from `securevibe.toml` and is worth
//! only what corroboration makes it worth. `Derived` means it comes from the app's own dependencies and
//! needs nobody's word. The distinction has to survive into the reports: "you told us this app has no
//! CI/CD" and "no XML parser appears in your dependencies" are not equally strong, and a report that
//! prints them identically is overstating one of them.

use serde::{Deserialize, Deserializer};

/// Where a condition's answer comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Stated in `securevibe.toml`, then corroborated against the code as far as possible.
    Claim,
    /// Read out of the app's dependency manifests and source. Needs nobody's word.
    Derived,
}

macro_rules! conditions {
    ($($variant:ident => $name:literal, $source:expr, $reason:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Condition { $($variant),* }

        impl Condition {
            /// The name as it appears in the applicability data files.
            pub fn name(self) -> &'static str {
                match self { $(Condition::$variant => $name),* }
            }

            /// Where this condition's answer comes from.
            pub fn source(self) -> Source {
                match self { $(Condition::$variant => $source),* }
            }

            /// Plain-language reason used when a rule states none. Written for someone who is not a
            /// programmer, as everything user-facing in this project is.
            pub fn default_not_applicable_reason(self) -> &'static str {
                match self { $(Condition::$variant => $reason),* }
            }

            pub fn from_name(name: &str) -> Option<Self> {
                match name { $($name => Some(Condition::$variant),)* _ => None }
            }

            pub const ALL: &'static [Condition] = &[$(Condition::$variant),*];
        }
    };
}

use Source::{Claim, Derived};

conditions! {
    // ---- v1's conditions, unchanged, so the shared applicability.json still loads ----
    Always => "always", Derived, "This requirement always applies.";
    Never => "never", Derived, "This requirement covers a technology or setup this app does not use.";
    Auth => "auth", Claim, "This app has no sign-in, so there are no accounts, passwords or sessions to protect.";
    NoAuth => "no-auth", Claim, "This app has sign-in, so this requirement for apps without accounts does not apply.";
    Uploads => "uploads", Claim, "This app does not accept file uploads.";
    Ai => "ai", Claim, "This app has no AI features.";
    AiActions => "ai-actions", Claim, "The AI can only answer questions; it cannot change data or take actions.";
    AiHistory => "ai-history", Claim, "The AI does not keep conversation history between visits.";
    AiModeration => "ai-moderation", Claim, "Content moderation is not turned on for the AI.";
    Email => "email", Claim, "This app does not send email.";
    ExternalApis => "external-apis", Claim, "This app does not call other services over the network.";
    PublicApi => "public-api", Claim, "This app does not offer API keys for other programs to connect.";
    Payments => "payments", Claim, "This app does not take payments.";
    Scheduler => "scheduler", Claim, "This app has no scheduled background jobs.";
    Tls => "tls", Claim, "This app runs on one computer only, without HTTPS, so there is no network connection to encrypt.";
    Internet => "internet", Claim, "This app is not intended to go on the internet.";
    Level2 => "level2", Claim, "This only applies at level 2, and this app targets level 1.";
    Oauth => "oauth", Claim, "This app uses its own accounts, not sign-in through another provider (OAuth or OpenID Connect).";
    Webrtc => "webrtc", Claim, "This app has no real-time audio or video calls (WebRTC).";
    Jwt => "jwt", Claim, "This app does not issue self-contained tokens such as JWTs.";
    Rag => "rag", Claim, "The AI does not search a document store or vector database (no retrieval-augmented generation).";
    Mcp => "mcp", Claim, "The AI does not use the Model Context Protocol (MCP) to talk to tools.";
    MultiTenant => "multi-tenant", Claim, "This app serves one organization, not several separate customer organizations sharing one system.";
    Training => "training", Claim, "This app does not train or fine-tune any AI model.";
    SelfAssessment => "self-assessment", Claim, "This is only evaluated when SecureVibe assesses itself.";

    // ---- v2: replacing the `never` rules whose reasons described v1's own template ----
    SelfHostedModel => "self-hosted-model", Claim, "This app does not host, build or deploy AI models of its own; it calls a model its vendor hosts.";
    CiCd => "ci-cd", Claim, "This app has no CI/CD pipeline.";
    HostedScm => "hosted-scm", Claim, "This app's code is not on a source-control server with branch protection or a merge queue.";
    OutsideContributors => "outside-contributors", Claim, "This app receives no code contributions from outside people.";
    Iac => "iac", Claim, "This app has no infrastructure or pipeline configuration (Terraform, CloudFormation, CI workflows).";
    OutOfBandAuth => "out-of-band-auth", Claim, "This app does not send sign-in codes by phone, SMS or push notification.";
    MultiAgent => "multi-agent", Claim, "There is a single assistant, not several AI agents that must identify each other.";
    MultimodalAi => "multimodal-ai", Claim, "The assistant accepts typed text only; it does not take images, video or audio.";
    SharedHostname => "shared-hostname", Claim, "This is a single application on its own address; no separate applications share its hostname.";
    MultipleServices => "multiple-services", Claim, "This app runs as one service, so there are no boundaries between services to design, no traffic between them to protect, and no cross-service transactions to get right.";
    // Using OAuth and *being* the authorization server are different jobs with different rules.
    // ASVS V10.4, V10.6, and V10.7 are written for whoever runs the server; an app with "Sign in
    // with Google" runs none of it, and was being asked about a server it does not have.
    AuthorizationServer => "authorization-server", Claim, "This app does not run an OAuth authorization server or OpenID provider of its own; these rules are for whoever runs one.";

    // Technology questions the dependency manifests answer, so nobody has to be believed.
    Websockets => "websockets", Derived, "No WebSocket library is used; every request is a normal web request.";
    Graphql => "graphql", Derived, "No GraphQL library is used.";
    Ldap => "ldap", Derived, "No LDAP client library is used, so LDAP injection is not possible.";
    Xpath => "xpath", Derived, "No XPath library is used.";
    Xml => "xml", Derived, "No XML parser is used, so XML external entity (XXE) attacks are not possible.";
    Latex => "latex", Derived, "No LaTeX processing library is used.";
    Jndi => "jndi", Derived, "JNDI is a Java technology and this app does not run on the JVM.";
    Memcache => "memcache", Derived, "No memcache client library is used.";
    FormatStrings => "format-strings", Derived, "This app's languages have no C-style format strings that user input could reach.";
    UnmanagedCode => "unmanaged-code", Derived, "This app's languages are memory-safe and it contains no unmanaged (C/C++) code.";
    PostMessage => "postmessage", Derived, "This app's pages do not use the browser postMessage feature.";
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        Condition::from_name(&name)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown condition `{name}`")))
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match String::deserialize(d)?.as_str() {
            "claim" => Ok(Source::Claim),
            "derived" => Ok(Source::Derived),
            other => Err(serde::de::Error::custom(format!(
                "unknown source `{other}`"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_condition_round_trips_through_its_name() {
        for c in Condition::ALL {
            assert_eq!(Condition::from_name(c.name()), Some(*c), "{}", c.name());
        }
    }

    #[test]
    fn names_are_unique() {
        let mut names: Vec<&str> = Condition::ALL.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "two conditions share a name");
    }
}
