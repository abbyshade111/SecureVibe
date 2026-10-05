//! The conditions an applicability rule can test.
//!
//! v1 keeps this enum closed on purpose — "security decisions are keyed on these values" — and so does
//! `sv`. The macro defines each condition's name, its plain-language reason, its source and its question in
//! one place, so they cannot drift apart.
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
    ($($variant:ident => $name:literal, $source:expr, $reason:literal, $question:literal;)*) => {
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

            /// The same thing asked as a question, for a list of what is still open: the reason is
            /// written as the exclusion ("This app does not send email."), the wrong voice for a
            /// question nobody has answered ("Does the app send email?").
            pub fn question(self) -> &'static str {
                match self { $(Condition::$variant => $question),* }
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
    Always => "always", Derived, "This requirement always applies.",
        "Does this requirement apply?";
    Never => "never", Derived, "This requirement covers a technology or setup this app does not use.",
        "Does the app use the technology or setup this requirement covers?";
    Auth => "auth", Claim, "This app has no sign-in, so there are no accounts, passwords or sessions to protect.",
        "Does the app have sign-in, with accounts, passwords, or sessions?";
    NoAuth => "no-auth", Claim, "This app has sign-in, so this requirement for apps without accounts does not apply.",
        "Is the app used with no sign-in at all?";
    Uploads => "uploads", Claim, "This app does not accept file uploads.",
        "Does the app accept file uploads?";
    Ai => "ai", Claim, "This app has no AI features.",
        "Does the app have AI features?";
    AiActions => "ai-actions", Claim, "The AI can only answer questions; it cannot change data or take actions.",
        "Can the AI change data or take actions, rather than only answer questions?";
    AiHistory => "ai-history", Claim, "The AI does not keep conversation history between visits.",
        "Does the AI keep conversation history between visits?";
    AiModeration => "ai-moderation", Claim, "Content moderation is not turned on for the AI.",
        "Is content moderation turned on for the AI?";
    Email => "email", Claim, "This app does not send email.",
        "Does the app send email?";
    ExternalApis => "external-apis", Claim, "This app does not call other services over the network.",
        "Does the app call other services over the network?";
    PublicApi => "public-api", Claim, "This app does not offer API keys for other programs to connect.",
        "Does the app offer API keys for other programs to connect?";
    Payments => "payments", Claim, "This app does not take payments.",
        "Does the app take payments?";
    Scheduler => "scheduler", Claim, "This app has no scheduled background jobs.",
        "Does the app run scheduled background jobs?";
    Tls => "tls", Claim, "This app runs on one computer only, without HTTPS, so there is no network connection to encrypt.",
        "Does the app's traffic cross a network, so there is a connection to encrypt with HTTPS?";
    Internet => "internet", Claim, "This app is not intended to go on the internet.",
        "Is the app meant to go on the internet?";
    Level2 => "level2", Claim, "This only applies at level 2, and this app targets level 1.",
        "Does the app target level 2?";
    Oauth => "oauth", Claim, "This app uses its own accounts, not sign-in through another provider (OAuth or OpenID Connect).",
        "Does the app sign people in through another provider (OAuth or OpenID Connect)?";
    Webrtc => "webrtc", Claim, "This app has no real-time audio or video calls (WebRTC).",
        "Does the app have real-time audio or video calls (WebRTC)?";
    Jwt => "jwt", Claim, "This app does not issue self-contained tokens such as JWTs.",
        "Does the app issue self-contained tokens such as JWTs?";
    Rag => "rag", Claim, "The AI does not search a document store or vector database (no retrieval-augmented generation).",
        "Does the AI search a document store or vector database (retrieval-augmented generation)?";
    // Searching the web is retrieval too, and four of the seven `rag` requirements fit it (citing
    // what was retrieved, logging each retrieval); the vector-database ones do not. Asked apart
    // since 27 September 2026, when one question led a tool to count web search as a vector store.
    WebSearch => "web-search", Claim, "The AI does not search the web or read web pages.",
        "Does the AI search the web or read web pages?";
    // Watermarking what the AI makes (C7.4.4) was gated on `rag`, which has nothing to do with it.
    // Asked apart at the owner's decision, 27 September 2026.
    GeneratesMedia => "generates-media", Claim, "The AI makes text only, not images, audio, or video.",
        "Does the AI make images, audio, or video, not only text?";
    Mcp => "mcp", Claim, "The AI does not use the Model Context Protocol (MCP) to talk to tools.",
        "Does the AI use the Model Context Protocol (MCP) to talk to tools?";
    // Serving tools over MCP is a different job from using them, with its own requirements (the
    // server's tokens, its Origin and Host checks, the parameters it accepts), and it needs no AI
    // of its own: `sv` is one. Asked apart since 27 September 2026, when `sv`'s self-assessment
    // found the server requirements were never asked of it, because `mcp` asks about the client.
    McpServer => "mcp-server", Claim, "This app does not serve tools to AI models over the Model Context Protocol (MCP).",
        "Does the app serve tools to AI models over the Model Context Protocol (MCP)?";
    MultiTenant => "multi-tenant", Claim, "This app serves one organization, not several separate customer organizations sharing one system.",
        "Does the app serve several separate customer organizations that share one system?";
    Training => "training", Claim, "This app does not train or fine-tune any AI model.",
        "Does the app train or fine-tune an AI model?";
    SelfAssessment => "self-assessment", Claim, "This is only evaluated when SecureVibe assesses itself.",
        "Is this SecureVibe assessing itself?";

    // ---- v2: replacing the `never` rules whose reasons described v1's own template ----
    SelfHostedModel => "self-hosted-model", Claim, "This app does not host, build or deploy AI models of its own; it calls a model its vendor hosts.",
        "Does the app host, build, or deploy AI models of its own?";
    CiCd => "ci-cd", Claim, "This app has no CI/CD pipeline.",
        "Does the app have a CI/CD pipeline?";
    HostedScm => "hosted-scm", Claim, "This app's code is not on a source-control server with branch protection or a merge queue.",
        "Is the app's code on a source-control server with branch protection or a merge queue?";
    OutsideContributors => "outside-contributors", Claim, "This app receives no code contributions from outside people.",
        "Does the app take code contributions from outside people?";
    Iac => "iac", Claim, "This app has no infrastructure or pipeline configuration (Terraform, CloudFormation, CI workflows).",
        "Does the app have infrastructure or pipeline configuration (Terraform, CloudFormation, CI workflows)?";
    OutOfBandAuth => "out-of-band-auth", Claim, "This app does not send sign-in codes by phone, SMS or push notification.",
        "Does the app send sign-in codes by phone, SMS, or push notification?";
    MultiAgent => "multi-agent", Claim, "There is a single assistant, not several AI agents that must identify each other.",
        "Are there several AI agents that must identify each other, rather than a single assistant?";
    MultimodalAi => "multimodal-ai", Claim, "The assistant accepts typed text only; it does not take images, video or audio.",
        "Does the assistant take images, video, or audio, not only typed text?";
    SharedHostname => "shared-hostname", Claim, "This is a single application on its own address; no separate applications share its hostname.",
        "Do other applications share this app's hostname?";
    MultipleServices => "multiple-services", Claim, "This app runs as one service, so there are no boundaries between services to design, no traffic between them to protect, and no cross-service transactions to get right.",
        "Does the app run as more than one service?";
    // Using OAuth and *being* the authorization server are different jobs with different rules.
    // ASVS V10.4, V10.6, and V10.7 are written for whoever runs the server; an app with "Sign in
    // with Google" runs none of it, and was being asked about a server it does not have.
    AuthorizationServer => "authorization-server", Claim, "This app does not run an OAuth authorization server or OpenID provider of its own; these rules are for whoever runs one.",
        "Does the app run an OAuth authorization server or OpenID provider of its own?";

    // Technology questions the dependency manifests answer, so nobody has to be believed.
    Websockets => "websockets", Derived, "No WebSocket library is used; every request is a normal web request.",
        "Does the app use WebSockets?";
    Graphql => "graphql", Derived, "No GraphQL library is used.",
        "Does the app use GraphQL?";
    Ldap => "ldap", Derived, "No LDAP client library is used, so LDAP injection is not possible.",
        "Does the app use an LDAP client?";
    Xpath => "xpath", Derived, "No XPath library is used.",
        "Does the app use XPath?";
    Xml => "xml", Derived, "No XML parser is used, so XML external entity (XXE) attacks are not possible.",
        "Does the app parse XML?";
    Latex => "latex", Derived, "No LaTeX processing library is used.",
        "Does the app process LaTeX?";
    Jndi => "jndi", Derived, "JNDI is a Java technology and this app does not run on the JVM.",
        "Does the app run on the JVM, where JNDI lookups are possible?";
    Memcache => "memcache", Derived, "No memcache client library is used.",
        "Does the app use memcache?";
    FormatStrings => "format-strings", Derived, "This app's languages have no C-style format strings that user input could reach.",
        "Do the app's languages have C-style format strings that user input could reach?";
    UnmanagedCode => "unmanaged-code", Derived, "This app's languages are memory-safe and it contains no unmanaged (C/C++) code.",
        "Does the app contain unmanaged (C or C++) code?";
    PostMessage => "postmessage", Derived, "This app's pages do not use the browser postMessage feature.",
        "Do the app's pages use the browser's postMessage feature?";
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

    #[test]
    fn every_condition_asks_a_question_of_its_own_in_its_own_words() {
        // A list of what is still open reads as questions; a reason copied across reads as an
        // answer nobody gave ("No WebSocket library is used").
        let mut questions = Vec::new();
        for c in Condition::ALL {
            let q = c.question();
            assert!(q.ends_with('?'), "{}: {q}", c.name());
            assert_eq!(q.matches('?').count(), 1, "{}: one question, {q}", c.name());
            assert!(q.starts_with(char::is_uppercase), "{}: {q}", c.name());
            assert_ne!(q, c.default_not_applicable_reason(), "{}", c.name());
            questions.push(q);
        }
        questions.sort_unstable();
        let before = questions.len();
        questions.dedup();
        assert_eq!(before, questions.len(), "two conditions ask the same question");
    }
}
