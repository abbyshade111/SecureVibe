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

pub mod consistency;
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
    /// Does this app *run* an OAuth authorization server or OpenID provider, rather than sign in
    /// through somebody else's?
    ///
    /// A separate question from `oauth`, because ASVS V10.4, V10.6, and V10.7 are written for
    /// whoever runs the server. An app with "Sign in with Google" answers `oauth = true` and this
    /// one `false`, and is then not asked about a server it does not have.
    #[serde(default)]
    pub authorization_server: Option<bool>,
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
    /// Does this run as more than one service talking to each other over a network?
    ///
    /// Fifteen of the Secure by Design checklist's thirty-six controls are about the space between
    /// services — trust zones, service discovery, contracts between them, sagas, circuit breakers.
    /// On a single service they are not merely passed, they are meaningless, and nothing else the
    /// manifest asks comes close to answering it.
    #[serde(default)]
    pub multiple_services: Option<bool>,
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
    /// Where the test command writes a JUnit XML report, relative to the app folder.
    ///
    /// Without it a failing suite credits nothing at all, because one exit code does not say which
    /// tests it came from. With it, the tests the runner reports as passing still count.
    pub test_report: Option<String>,
    #[serde(default)]
    pub health: Option<String>,
    /// How to sign in, so the probes can ask what a signed-in user can do and not only what
    /// somebody who has not signed in can. Absent means authorization and sessions are reported as
    /// not assessed, which is what they always were.
    #[serde(default)]
    pub users: Option<UsersSection>,
    /// Where the app answers GraphQL, if it does. The probes ask it for its schema and send one
    /// request of a thousand aliases, which needs no knowledge of the schema at all.
    #[serde(default)]
    pub graphql: Option<String>,
    /// Where the app accepts WebSocket connections, if it does. The probes open a handshake with
    /// no `Origin` and one from a site the app has never heard of.
    #[serde(default)]
    pub websocket: Option<String>,
    /// How the app signs people in through another service ("Sign in with Google"), so the run
    /// can point it at a test provider of `sv`'s own and see what it accepts.
    #[serde(default)]
    pub oidc: Option<OidcSection>,
}

/// `[stack.run.oidc]`: the app signs in through OpenID Connect.
///
/// For the run, the app is given a test provider instead of the real one, in `OIDC_ISSUER`,
/// `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET`, and has to use those. The provider signs anybody in
/// without asking, and can be told to get one thing wrong in the next token it issues — which is
/// how the probes see whether the app notices.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OidcSection {
    /// The path that starts signing in: it answers by sending the browser to the provider.
    pub start: String,
    /// A page only a signed-in person sees, to tell whether a sign-in worked.
    pub private: String,
}

/// One request the probes make on the app's behalf: how to sign up, sign in, or create something.
///
/// Values may use `{user}`, `{password}`, `{csrf}` (a token read from the page first), `{marker}`
/// (a unique string the probe can look for afterwards), and, in `change-password`, `{new_password}`. A body is sent as a form unless `json` is
/// used instead; never both.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RequestTemplate {
    #[serde(default = "post")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub form: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub json: std::collections::BTreeMap<String, String>,
}

fn post() -> String {
    "POST".to_owned()
}

/// A resource one user creates and another must not be able to read.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OwnedSection {
    /// Creates it, as the first user. Put `{marker}` in a field so it can be recognized later.
    pub create: RequestTemplate,
    /// Where it is read, with `{id}` for what `create` returned. Without `{id}`, the `Location`
    /// header the create response sends is used instead.
    #[serde(default)]
    pub read: Option<String>,
    /// The field of a JSON create response holding the new id. Defaults to `id`.
    #[serde(default)]
    pub id_field: Option<String>,
}

/// `[stack.run.users]`: how the probes get two ordinary users (and optionally an admin), sign in as
/// them, and what to ask.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct UsersSection {
    /// A command run inside the app's container once it is up, which creates the accounts. It is
    /// given `SV_USER_A`, `SV_PASSWORD_A`, `SV_USER_B`, `SV_PASSWORD_B` and, when `admin` pages are
    /// listed, `SV_ADMIN` and `SV_ADMIN_PASSWORD`; when `totp` is set, `SV_USER_TOTP`,
    /// `SV_PASSWORD_TOTP`, and `SV_TOTP_SECRET` (base32) for an account to enroll in two-factor
    /// sign-in with that secret.
    #[serde(default)]
    pub seed: Option<String>,
    /// Or the app's own sign-up request, used for both ordinary users when there is no `seed`.
    #[serde(default)]
    pub signup: Option<RequestTemplate>,
    pub login: Option<RequestTemplate>,
    #[serde(default)]
    pub logout: Option<RequestTemplate>,
    /// When sign-in answers with a token in JSON rather than a cookie, the field it is in.
    #[serde(default)]
    pub token_field: Option<String>,
    /// Pages only a signed-in user should see.
    #[serde(default)]
    pub private: Vec<String>,
    /// Pages only an admin should see. Needs `seed`, which is the only way to make an admin.
    #[serde(default)]
    pub admin: Vec<String>,
    #[serde(default)]
    pub owned: Option<OwnedSection>,
    /// Changes the signed-in user's password: `{password}` is the current one, `{new_password}`
    /// the new. Asked last, with an account made for it through `signup`, or with A when there is
    /// no `signup`.
    #[serde(default)]
    pub change_password: Option<RequestTemplate>,
    /// Deletes the signed-in user's own account; `{password}` if it asks for the password again.
    /// Only ever used on an account made for it through `signup`, never on A or B.
    #[serde(default)]
    pub delete_account: Option<RequestTemplate>,
    /// How the app takes a file, so the probes can send it ones it ought to refuse.
    #[serde(default)]
    pub upload: Option<UploadSection>,
    /// How a forgotten password is reset, so the probes can follow the link the app emails. Only
    /// used when the run has a mail sink for the app to send to.
    #[serde(default)]
    pub reset: Option<ResetSection>,
    /// How to sign in with a code or link the app emails, beside the password: `use` with `{code}`,
    /// in the same session that asked for it. Only used when the run has a mail sink.
    #[serde(default)]
    pub email_code: Option<ResetSection>,
    /// A flow of more than one step, so the probes can try skipping one.
    #[serde(default)]
    pub flow: Option<FlowSection>,
    /// The second step of a two-factor sign-in: `{code}` for the six-digit code, sent in the
    /// session the password step began. Needs `seed`, which is given a third account and its
    /// secret (`SV_USER_TOTP`, `SV_PASSWORD_TOTP`, `SV_TOTP_SECRET`) to enroll.
    #[serde(default)]
    pub totp: Option<RequestTemplate>,
}

/// Something the app emails a code for — a password reset, or a sign-in — asked for, and the code
/// used.
///
/// The run gives the app a mail server that keeps what it is sent (`SMTP_HOST`, `SMTP_PORT`), so
/// the probes can read the email as the account's owner would and use the code or link in it. The
/// type keeps the name of its first use.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResetSection {
    /// Asks for a reset email, with `{user}` for the account's address.
    pub request: RequestTemplate,
    /// Uses what the email carried: `{code}` for the code or the token from the link, and for a
    /// reset `{new_password}` for the password, in the path or a field.
    #[serde(rename = "use")]
    pub use_code: RequestTemplate,
    /// Where the code is in the email: a regular expression whose first group is the code. Absent
    /// means a link's `token`, `code`, or `key` parameter, or the last part of a link's path under
    /// `reset` (for a reset) or a sign-in word (for `email-code`), or a code after the word `code`.
    #[serde(default)]
    pub code_pattern: Option<String>,
}

/// A flow of more than one step, such as a checkout, and how to tell that it really finished.
///
/// V2.3.1 asks that steps are taken in order and none is skipped. The probes go through the steps
/// in order as the first user, which has to end in `completed` or nothing can be told, and then, as
/// the second user in a fresh session, go straight to the last step, and do the first and then the
/// last. Either of those ending in `completed` is a step the app let somebody skip.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FlowSection {
    /// The steps, in the order a person takes them, each with `{csrf}` and `{marker}` as elsewhere.
    pub steps: Vec<RequestTemplate>,
    /// Text the last step answers with only when the whole flow really finished: in the page, or in
    /// the address it sends the browser on to. "Order placed", say, or `/orders/`.
    pub completed: String,
}

/// How to upload a file, and what the owner says the app accepts.
///
/// The probes send three files an app ought to refuse — one too large, one whose contents do not
/// match its extension, and one that is server-side code — and, when `serves-at` says where to
/// fetch an upload back, read what the app does with it afterwards.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct UploadSection {
    /// The path the file is posted to.
    pub path: String,
    /// The form field the file itself goes in.
    pub field: String,
    /// The other fields the form needs, `{csrf}` and `{marker}` included, as elsewhere.
    #[serde(default)]
    pub form: std::collections::BTreeMap<String, String>,
    /// Where an uploaded file can be fetched back, with `{name}` standing for its file name.
    ///
    /// Absent means the probes cannot see what the app serves, and V5.3.1 and V3.2.1 are reported
    /// as not assessed rather than guessed at: an app may well store uploads somewhere no URL
    /// reaches, which is the safest thing it can do and must not read as a failure.
    #[serde(default)]
    pub serves_at: Option<String>,
    /// The largest file, in bytes, the owner says the app accepts.
    ///
    /// The documented policy for V5.2.1, in the same spirit as `[policy] failed-sign-ins`: prose
    /// cannot be checked, a number can. Absent means V5.2.1 is not assessed.
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

impl UsersSection {
    /// What is missing for the signed-in probes to run at all, in the words the report will use.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.login.is_none() {
            out.push("`login` is not set, so there is no way to sign in".to_owned());
        }
        if self.seed.is_none() && self.signup.is_none() {
            out.push("neither `seed` nor `signup` is set, so no accounts can be made".to_owned());
        }
        if self.private.is_empty() && self.admin.is_empty() && self.owned.is_none() {
            out.push(
                "none of `private`, `admin` or `owned` is set, so there is nothing to ask as a \
                 signed-in user"
                    .to_owned(),
            );
        }
        if !self.admin.is_empty() && self.seed.is_none() {
            out.push(
                "`admin` pages are listed without `seed`, and an admin can only be made by `seed`"
                    .to_owned(),
            );
        }
        if let Some(reset) = &self.reset {
            let t = &reset.use_code;
            let says = |needle: &str| {
                t.path.contains(needle)
                    || t.form
                        .values()
                        .chain(t.json.values())
                        .any(|v| v.contains(needle))
            };
            if !says("{code}") {
                out.push(format!(
                    "`reset.use` ({}) has no `{{code}}`, so what the email carried is never sent",
                    t.path
                ));
            }
            if !says("{new_password}") {
                out.push(format!(
                    "`reset.use` ({}) has no `{{new_password}}`, so there is nothing to reset the \
                     password to",
                    t.path
                ));
            }
        }
        if let Some(code) = &self.email_code {
            let t = &code.use_code;
            if !(t.path.contains("{code}")
                || t.form
                    .values()
                    .chain(t.json.values())
                    .any(|v| v.contains("{code}")))
            {
                out.push(format!(
                    "`email-code.use` ({}) has no `{{code}}`, so what the email carried is never sent",
                    t.path
                ));
            }
        }
        if let Some(t) = &self.change_password
            && !t
                .form
                .values()
                .chain(t.json.values())
                .any(|v| v.contains("{new_password}"))
        {
            out.push(format!(
                "`change-password` ({}) has no field with `{{new_password}}`, so there is nothing to \
                 change the password to",
                t.path
            ));
        }
        for t in [
            &self.signup,
            &self.login,
            &self.logout,
            &self.change_password,
            &self.delete_account,
        ]
        .into_iter()
        .flatten()
        .chain(self.owned.as_ref().map(|o| &o.create))
        .chain(self.reset.iter().flat_map(|r| [&r.request, &r.use_code]))
        .chain(
            self.email_code
                .iter()
                .flat_map(|r| [&r.request, &r.use_code]),
        ) {
            if !t.form.is_empty() && !t.json.is_empty() {
                out.push(format!("{} sets both `form` and `json`; pick one", t.path));
            }
        }
        out
    }
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

/// The numbers the owner states as policy, so a probe can hold the app to them.
///
/// A requirement like V6.3.1 asks that brute-force controls are implemented *according to the
/// application's documentation*. Nothing can check that against a document written in prose, but a
/// number is a claim a running app can be held to: say five, and the probe makes six wrong attempts
/// and watches whether the app pushes back. The number is the documented policy for this purpose,
/// and the report says so.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicySection {
    /// Wrong passwords in a row before the app should push back: a delay, a lockout, or a refusal.
    #[serde(default)]
    pub failed_sign_ins: Option<u32>,
    /// The window the count applies within, in minutes. Recorded rather than tested: the probe
    /// makes its attempts in a few seconds, which is inside any window worth stating.
    #[serde(default)]
    pub within_minutes: Option<u32>,
    /// Wrong emailed sign-in codes in a row before the app should push back, for V6.6.3: the same
    /// kind of stated number as `failed-sign-ins`, for the codes `email-code` sends.
    #[serde(default)]
    pub failed_codes: Option<u32>,
    /// Minutes a signed-in session may sit unused before the app asks for the password again, for
    /// V7.3.1. Held to it only by `sv run --slow`, which waits that long.
    #[serde(default)]
    pub idle_timeout_minutes: Option<u32>,
    /// Minutes a session may last however busy it is, for V7.3.2. Held to it only by
    /// `sv run --slow`, and only when it is short enough to wait out.
    #[serde(default)]
    pub session_lifetime_minutes: Option<u32>,
    /// How many days a known vulnerability may stay unfixed, by how serious it is: V15.1.1's time
    /// frames, as numbers `sv audit` can hold the app's packages to for V15.2.1.
    #[serde(default)]
    pub fix_within_days: Option<FixWithinDays>,
    /// Words a password must not be built from: the app's name, the organization's, a product or
    /// project name. V6.2.11's documented list of context-specific words, as a list the sign-up
    /// probe can try one of.
    #[serde(default)]
    pub context_words: Vec<String>,
}

/// The remediation time frames, one per severity. A severity left out has no time frame, and a
/// vulnerability of that severity is counted against V15.2.1 whatever its age, exactly as when no
/// time frames are stated at all.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FixWithinDays {
    #[serde(default)]
    pub critical: Option<u32>,
    #[serde(default)]
    pub high: Option<u32>,
    #[serde(default)]
    pub medium: Option<u32>,
    #[serde(default)]
    pub low: Option<u32>,
}

/// One answer to a design question: how the app is built, in the owner's own words.
///
/// `yes` is the weakest positive answer `sv` has. It is the owner asserting a property, which is
/// not the property, so it never becomes *checked* and never settles a threat. `no` is the owner
/// saying the control is missing, which is a finding on their own word. Silence and `not-sure` add
/// nothing at all, which is the point of having a third answer: a question the owner cannot answer
/// must not be rounded down to "no" or up to "yes".
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DesignAnswer {
    /// `yes`, `no`, or `not-sure`. Anything else is refused at load.
    pub answer: String,
    /// The file that does it, so somebody can go and look, and so a stale pointer can be caught.
    #[serde(default)]
    pub r#where: Option<String>,
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
    /// The design questions, keyed by requirement id. See `sv-check::design`.
    #[serde(default)]
    pub design: std::collections::BTreeMap<String, DesignAnswer>,
    /// The policy numbers a probe can hold the running app to.
    #[serde(default)]
    pub policy: PolicySection,
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
        // Running an OAuth authorization server is a way of using OAuth, so an app that uses
        // none is certainly not one. That is an entailment rather than a guess, which is why it
        // is drawn here at all: the applicability engine deliberately guesses nothing, and a
        // manifest written before this question existed would otherwise leave V10.4, V10.6, and
        // V10.7 unanswered for every app that has no OAuth anywhere near it.
        //
        // An explicit yes is taken first and never overruled. A manifest that says "no OAuth" and
        // "runs an authorization server" contradicts itself, and the reading that keeps the
        // requirements is the only safe one to act on.
        let authorization_server = match (c.oauth, c.authorization_server) {
            (_, Some(true)) => Some(true),
            (Some(false), _) => Some(false),
            (_, stated) => stated,
        };
        vec![
            (Condition::Auth, c.auth),
            (Condition::Oauth, c.oauth),
            (Condition::AuthorizationServer, authorization_server),
            (Condition::Jwt, c.jwt),
            (Condition::Uploads, c.uploads),
            (Condition::Payments, c.payments),
            (Condition::Email, c.email),
            (Condition::PublicApi, c.public_api),
            (Condition::Scheduler, c.scheduler),
            (Condition::MultiTenant, c.multi_tenant),
            (Condition::MultipleServices, c.multiple_services),
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
    /// The manifest is silent. Not a "no", even when the code was searched and nothing was found:
    /// the requirement is reported as not assessed.
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
/// switch off a requirement the code says applies, and a claim of "yes" is honored even when
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
            // Nobody has said anything. Silence is not a no — and a scan that found nothing does
            // not break the silence. These are the questions the manifest asks the owner, and
            // not finding a CI file in an uploaded app is not finding the pipeline absent: the
            // file is often left out, and a pipeline can be configured on a server. It excluded
            // twelve requirements on a manifest that answered nothing, until 26 September 2026.
            // The derived conditions, which no one is asked, are answered below and keep a "no".
            (None, _) => None,
            // The owner's own no, with nothing in the code contradicting it.
            (Some(false), _) => Some(false),
        };
        let state = match (claimed, found_in_code) {
            (None, None) | (None, Some(false)) => ClaimState::Unanswered,
            (Some(false), Some(true)) => ClaimState::Contradicted,
            (None, Some(true)) => ClaimState::Contradicted,
            (Some(true), Some(false)) => ClaimState::Unsupported,
            (Some(_), None) => ClaimState::Unverifiable,
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
    fn a_password_change_with_nothing_to_change_to_is_named_as_a_problem() {
        let template = |fields: &[(&str, &str)]| RequestTemplate {
            method: "POST".into(),
            path: "/password".into(),
            form: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            json: Default::default(),
        };
        let mut users = UsersSection {
            seed: Some("seed".into()),
            login: Some(template(&[("password", "{password}")])),
            private: vec!["/account".into()],
            change_password: Some(template(&[
                ("current", "{password}"),
                ("new", "{password}"),
            ])),
            ..Default::default()
        };
        let problems = users.problems();
        assert!(
            problems.iter().any(|p| p.contains("{new_password}")),
            "{problems:?}"
        );
        users.change_password = Some(template(&[
            ("current", "{password}"),
            ("new", "{new_password}"),
        ]));
        assert!(users.problems().is_empty(), "{:?}", users.problems());
    }

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

#[cfg(test)]
mod authorization_server_tests {
    use super::*;

    fn manifest(toml_text: &str) -> Manifest {
        toml::from_str(toml_text).expect("manifest parses")
    }

    /// What the pipeline would act on, with nothing in the code corroborating anything.
    fn effective(toml_text: &str, condition: Condition) -> Option<bool> {
        resolve(&manifest(toml_text), &|_| None).0.get(condition)
    }

    #[test]
    fn an_app_with_no_oauth_at_all_is_not_an_authorization_server() {
        // The entailment, and the reason a manifest written before this question existed does not
        // have to be rewritten for V10.4 to be answered: running an authorization server is a way
        // of using OAuth, so an app that uses none is certainly not one.
        let m = "[capabilities]\nauth = true\noauth = false\n";
        assert_eq!(effective(m, Condition::AuthorizationServer), Some(false));
    }

    #[test]
    fn an_oauth_app_that_has_not_said_which_side_it_is_on_leaves_it_unanswered() {
        // `oauth = true` alone does not say whether the app signs in *through* a provider or *is*
        // one, and guessing either way is exactly what this must not do.
        let m = "[capabilities]\nauth = true\noauth = true\n";
        assert_eq!(effective(m, Condition::AuthorizationServer), None);
    }

    #[test]
    fn saying_yes_survives_a_manifest_that_contradicts_itself() {
        // "No OAuth" and "runs an authorization server" cannot both be true. The reading that
        // keeps the requirements is the only safe one to act on, so the explicit yes wins over
        // the entailment rather than being quietly discarded by it.
        let m = "[capabilities]\noauth = false\nauthorization-server = true\n";
        assert_eq!(effective(m, Condition::AuthorizationServer), Some(true));
    }

    #[test]
    fn the_code_can_answer_it_over_a_manifest_that_says_no() {
        // `effective = claimed || found_in_code`, on this condition like every other: an app
        // shipping an authorization server gets V10.4 back whatever securevibe.toml says.
        let m = "[capabilities]\noauth = true\nauthorization-server = false\n";
        let found = |c: Condition| (c == Condition::AuthorizationServer).then_some(true);
        let (ctx, resolved) = resolve(&manifest(m), &found);
        assert_eq!(ctx.get(Condition::AuthorizationServer), Some(true));
        assert_eq!(
            resolved
                .iter()
                .find(|r| r.condition == Condition::AuthorizationServer)
                .map(|r| r.state),
            Some(ClaimState::Contradicted)
        );
    }

    #[test]
    fn a_self_contradicting_manifest_still_gets_the_authorization_server_requirements() {
        // The second witness for the rule above, at the level a reader of the report would feel
        // it. The claim being `Some(true)` is an implementation detail; what must not happen is
        // that "no OAuth" quietly deletes V10.4 from the requirements of somebody who has just
        // said in the same file that they run an authorization server.
        use sv_frameworks::Frameworks;
        use sv_frameworks::applicability::{ApplicabilityConfig, bucket};

        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let config = ApplicabilityConfig::load_v2(
            &root.join("../data/knowledge"),
            &root.join("data/applicability-v2.json"),
        )
        .unwrap();
        let frameworks = Frameworks::load(&root.join("../data/frameworks")).unwrap();

        let m = "[capabilities]\noauth = false\nauthorization-server = true\n";
        let (ctx, _) = resolve(&manifest(m), &|_| None);
        let buckets = bucket(&frameworks, &config, &ctx, 2);
        for id in ["V10.4.1", "V10.6.1", "V10.7.1"] {
            assert!(
                buckets.applicable.iter().any(|a| a == id),
                "{id} was dropped for an owner who said they run an authorization server"
            );
        }
    }

    #[test]
    fn the_answer_the_context_acts_on_is_the_one_the_resolved_claim_reports() {
        // The entailment is drawn in `claims()`, before resolution, so that these two cannot
        // disagree. Drawing it afterwards would leave the report saying "nothing answered this"
        // beside an exclusion made on the strength of an answer.
        let m = "[capabilities]\noauth = false\n";
        let (ctx, resolved) = resolve(&manifest(m), &|_| None);
        let claim = resolved
            .iter()
            .find(|r| r.condition == Condition::AuthorizationServer)
            .expect("authorization-server is among the resolved claims");
        assert_eq!(claim.effective, ctx.get(Condition::AuthorizationServer));
        assert_eq!(claim.effective, Some(false));
    }
}

#[cfg(test)]
mod time_frame_tests {
    use super::*;

    #[test]
    fn the_time_frames_are_read_one_per_severity() {
        let m: Manifest =
            toml::from_str("[policy]\nfix-within-days = { critical = 7, high = 30 }\n")
                .expect("manifest parses");
        assert_eq!(
            m.policy.fix_within_days,
            Some(FixWithinDays {
                critical: Some(7),
                high: Some(30),
                medium: None,
                low: None,
            })
        );
    }

    #[test]
    fn a_severity_that_does_not_exist_is_refused_rather_than_ignored() {
        // "urgent = 1" silently ignored would leave the owner believing they had set a time frame,
        // and every critical finding would be judged against none.
        let bad = toml::from_str::<Manifest>("[policy]\nfix-within-days = { urgent = 1 }\n");
        assert!(bad.is_err(), "{bad:?}");
    }
}

#[cfg(test)]
mod reset_tests {
    use super::*;

    fn users(reset: &str) -> UsersSection {
        let text = format!(
            "[stack.run.users]\nseed = \"s\"\nlogin = {{ path = \"/login\" }}\nprivate = [\"/a\"]\n{reset}\n"
        );
        let m: Manifest = toml::from_str(&text).expect("manifest parses");
        m.stack.run.users.expect("users section")
    }

    #[test]
    fn a_reset_entry_is_read_with_its_use_request() {
        let u = users(
            "reset = { request = { path = \"/forgot\", form = { email = \"{user}\" } }, use = { \
             path = \"/reset/{code}\", form = { password = \"{new_password}\" } }, code-pattern = \
             \"n=(\\\\d+)\" }",
        );
        let reset = u.reset.as_ref().expect("reset read");
        assert_eq!(reset.use_code.path, "/reset/{code}");
        assert_eq!(reset.code_pattern.as_deref(), Some("n=(\\d+)"));
        assert!(u.problems().is_empty(), "{:?}", u.problems());
    }

    #[test]
    fn a_reset_that_never_sends_the_code_or_the_password_says_so() {
        let u = users(
            "reset = { request = { path = \"/forgot\" }, use = { path = \"/reset\", form = { \
             token = \"{user}\" } } }",
        );
        let problems = u.problems().join("\n");
        assert!(problems.contains("no `{code}`"), "{problems}");
        assert!(problems.contains("no `{new_password}`"), "{problems}");
    }

    #[test]
    fn an_email_code_entry_must_send_the_code() {
        let u = users(
            "email-code = { request = { path = \"/login/code\", form = { email = \"{user}\" } }, \
             use = { path = \"/login/verify\" } }",
        );
        assert!(u.email_code.is_some());
        let problems = u.problems().join("\n");
        assert!(problems.contains("`email-code.use`"), "{problems}");
        let u = users(
            "email-code = { request = { path = \"/login/code\" }, use = { path = \
             \"/login/verify/{code}\" } }",
        );
        assert!(u.problems().is_empty(), "{:?}", u.problems());
    }
}

#[cfg(test)]
mod silence_tests {
    use super::*;

    /// A manifest that says nothing about the repository, resolved against a scan that looked for
    /// CI and infrastructure files and found none.
    fn resolved_with(found: Option<bool>) -> (ConditionContext, Vec<ResolvedClaim>) {
        let m: Manifest =
            toml::from_str("manifest-version = 1\n[app]\nname = \"x\"\n").expect("manifest parses");
        resolve(&m, &|c| {
            matches!(c, Condition::CiCd | Condition::Iac)
                .then_some(found)
                .flatten()
        })
    }

    #[test]
    fn an_unanswered_question_stays_unanswered_when_the_scan_found_nothing() {
        // Found reviewing the manifest questions: `ci-cd` and `iac` unanswered, and a scan that
        // found no CI file, excluded twelve requirements as not applicable. An uploaded app often
        // leaves `.github` out, and a pipeline can be configured on a server; not finding the file
        // is not finding the pipeline absent, and the owner was never asked to say either way.
        let (ctx, resolved) = resolved_with(Some(false));
        for condition in [Condition::CiCd, Condition::Iac] {
            assert_eq!(
                ctx.get(condition),
                None,
                "{condition:?} was answered for the owner"
            );
            let claim = resolved
                .iter()
                .find(|r| r.condition == condition)
                .expect("the question is among the claims");
            assert_eq!(claim.state, ClaimState::Unanswered, "{condition:?}");
            assert_eq!(
                claim.found_in_code,
                Some(false),
                "what the scan saw is still shown"
            );
        }
    }

    #[test]
    fn what_the_scan_found_still_counts_beside_an_answer() {
        // Silence is the only case that changes. A `no` the scan agrees with is confirmed, and a
        // `yes` it cannot see is unsupported and still applies.
        let with = |text: &str| {
            let m: Manifest = toml::from_str(&format!(
                "manifest-version = 1\n[app]\nname = \"x\"\n[repository]\nci-cd = {text}\n"
            ))
            .expect("manifest parses");
            resolve(&m, &|c| (c == Condition::CiCd).then_some(false))
        };
        let (ctx, resolved) = with("false");
        assert_eq!(ctx.get(Condition::CiCd), Some(false));
        assert_eq!(
            resolved
                .iter()
                .find(|r| r.condition == Condition::CiCd)
                .unwrap()
                .state,
            ClaimState::Confirmed
        );
        let (ctx, resolved) = with("true");
        assert_eq!(ctx.get(Condition::CiCd), Some(true));
        assert_eq!(
            resolved
                .iter()
                .find(|r| r.condition == Condition::CiCd)
                .unwrap()
                .state,
            ClaimState::Unsupported
        );
        // And a scan that did find it still answers yes, for the owner or not.
        let (ctx, _) = resolved_with(Some(true));
        assert_eq!(ctx.get(Condition::CiCd), Some(true));
    }
}
