//! `stackvet.toml` — what the app claims about itself, and what those claims are worth.
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
pub mod schema;
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

/// Every data category the spec lists (`spec.rs`), sensitive or not. A name not among them cannot
/// be shown not to be sensitive, so it holds the app to level 2, and the report names it
/// (the documentation review of 6 October 2026, item 7; ADR-024, Later).
pub const DATA_CATEGORIES: &[&str] = &[
    "contact",
    "financial",
    "payment-card",
    "health",
    "government-id",
    "credentials",
    "children",
    "location",
    "files",
    "business-confidential",
    "other-personal",
];

/// A category as the lists spell it: `"Health"` and ` health ` are `health`.
fn category_name(listed: &str) -> String {
    listed.trim().to_ascii_lowercase()
}

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
    /// Does the AI search the web or read web pages? Retrieval, like `rag`, but with no document
    /// store or vector database of the app's own.
    #[serde(default)]
    pub web_search: Option<bool>,
    /// Does the AI make images, audio, or video? Decides whether what it makes must be watermarked
    /// (AISVS C7.4.4).
    #[serde(default)]
    pub generates_media: Option<bool>,
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
    /// Does this app *serve* tools to AI models over the Model Context Protocol, as an MCP server?
    ///
    /// Not under `[capabilities.ai]`: a server needs no AI of its own, and answering "no AI" must
    /// not answer this. `mcp` there asks the other side, whether the app's AI uses MCP tools.
    #[serde(default)]
    pub mcp_server: Option<bool>,
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
    /// Install the app's packages before the run (ADR-052): in a container of their own that is
    /// given only `requirements.txt`, or `package.json` and `package-lock.json`, and can reach the
    /// internet, with no package's code run there; then given to the fenced app read-only. Only
    /// when `image` is one of Docker's own `python` or `node` images, whose programs are known.
    /// Absent or false means nothing is installed and nothing is downloaded, as before.
    #[serde(default)]
    pub install: Option<bool>,
    /// Where the test command writes its report (JUnit XML, TAP, `go test -json`, or jest/Vitest JSON),
    /// relative to the app folder.
    ///
    /// Without it a failing suite credits nothing at all, because one exit code does not say which
    /// tests it came from. With it, the tests the runner reports as passing still count.
    pub test_report: Option<String>,
    /// How many seconds the test command may run before `sv` stops it. Absent (or 0) means ten
    /// minutes. A suite that is stopped credits nothing, and the report says it was stopped.
    #[serde(default)]
    pub test_time_limit: Option<u64>,
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
    /// How to talk to the app's AI feature, so the run can give it a test model of `sv`'s own and
    /// see what the app does when that model misbehaves.
    #[serde(default)]
    pub ai: Option<AiSection>,
    /// Where the app answers as an MCP server, when it serves tools to AI models itself, so the
    /// run can ask whether it checks where requests come from and ends sessions when told to.
    #[serde(default)]
    pub mcp_server: Option<McpServerSection>,
    /// A feature that fetches an address a person gives it (a link preview, an import from a
    /// web address), so the run can ask where it will go and whether it follows a redirect.
    #[serde(default)]
    pub fetch: Option<FetchSection>,
}

/// Whether a name is one an environment variable can have: letters, digits, and `_`, and not empty.
/// What a name from stackvet.toml must be before it goes on a command line as `NAME=value`.
pub fn is_variable_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `[stack.run.fetch]`: the app fetches an address a person gives it.
///
/// For the run, it is given the address of a test server of `sv`'s own on the app's private network,
/// a host nobody allowed on a port no service uses, and that server records whether it was fetched.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FetchSection {
    /// The request that hands the feature an address, with `{url}` where the address goes.
    pub request: RequestTemplate,
    /// Whether it needs a signed-in user. The second test user is used, from `[stack.run.users]`.
    #[serde(default)]
    pub signed_in: bool,
    /// Following a redirect is what the feature is for, so whether it does is not asked (V15.3.2).
    #[serde(default)]
    pub follows_redirects: bool,
}

/// `[stack.run.mcp-server]`: the app serves tools over the Model Context Protocol's HTTP transport.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct McpServerSection {
    /// The path the MCP endpoint answers on, such as `/mcp`.
    pub path: String,
    /// The environment variable the app reads the access token it accepts from, for a server that
    /// takes one fixed token. The run gives it a new random token and sends that with every request,
    /// and asks, with none and with a made-up one, whether the server checks it (C10.2.1). A server
    /// that checks tokens from a sign-in service cannot be given one yet.
    #[serde(default)]
    pub token_env: Option<String>,
    /// The server is meant to answer anyone, with no token: then whether it checks one is not asked.
    #[serde(default)]
    pub public: bool,
    /// A tool that is safe to call any number of times, and arguments it accepts, for the questions
    /// about what it does with arguments it should refuse (C10.4.3, C10.4.4, C10.4.5).
    #[serde(default)]
    pub probe_tool: Option<RecordTool>,
}

/// `[stack.run.ai]`: the app has a feature that sends what a person types to a language model.
///
/// For the run, the app is pointed at a test model instead of the real service, through
/// `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, and `GOOGLE_GEMINI_BASE_URL` (with placeholder keys in
/// `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, and `GOOGLE_API_KEY`), and through any
/// other variables `base-url-env` names. It answers the way
/// those services do, costs nothing, and does on purpose what a model can be talked into doing.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AiSection {
    /// The request that sends a message to the AI feature, with `{prompt}` where the text goes.
    pub chat: RequestTemplate,
    /// Whether it needs a signed-in user. The second test user is used, from `[stack.run.users]`.
    #[serde(default)]
    pub signed_in: bool,
    /// Other environment variables the app reads the model's address from, each given the test
    /// model's OpenAI-style address (ending `/v1`).
    #[serde(default)]
    pub base_url_env: Vec<String>,
    /// The setting that turns the AI feature off, as `NAME=value`: a second copy of the app is
    /// started with it in its environment, and must answer without calling the model.
    #[serde(default)]
    pub kill_switch: Option<String>,
    /// The environment variable the app reads its MCP server's address from, when the feature
    /// gives the model tools from one. The run gives it a test MCP server of `sv`'s own there.
    #[serde(default)]
    pub mcp_url_env: Option<String>,
    /// A tool of the app's own that the model can call to read one record, with `{id}` where the
    /// record's id goes. The test model asks it, as the second user, for the first user's record
    /// (C9.5.3). Needs `signed-in` and an `owned` record under [stack.run.users].
    #[serde(default)]
    pub record_tool: Option<RecordTool>,
    /// Whether the AI feature reads the people's own `owned` records when it answers: searches their
    /// notes or documents for what a question is about. When it does, the first test user saves one
    /// with a private marker, and the second asks about it (C5.2.2, C8.1.3, C5.2.4). Needs
    /// `signed-in` and an `owned` record under [stack.run.users].
    #[serde(default)]
    pub reads_owned: bool,
}

/// The tool the model calls to read a record, and the arguments it takes.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RecordTool {
    /// The tool's name as the app offers it to the model, such as `get_note`.
    pub name: String,
    /// Its arguments, with `{id}` where the record's id goes, such as `{ id = "{id}" }`.
    #[serde(default)]
    pub args: std::collections::BTreeMap<String, String>,
    /// The owner's word that the tool only reads, changing nothing. Only then does the run call it
    /// again after every result, up to the test model's cap, to see whether the app limits how
    /// many tools one message may run (C9.1.2; ADR-045). Not evidence of anything itself.
    #[serde(default)]
    pub read_only: bool,
}

impl AiSection {
    /// What would stop the checks from being asked, in words for the report.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let t = &self.chat;
        if !(t.path.contains("{prompt}")
            || t.form
                .values()
                .chain(t.json.values())
                .any(|v| v.contains("{prompt}")))
        {
            out.push(format!(
                "`ai.chat` ({}) has no `{{prompt}}`, so nothing would be sent to the AI feature",
                t.path
            ));
        }
        if let Some(switch) = &self.kill_switch {
            let named = switch.split_once('=').is_some_and(|(name, _)| {
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
            if !named {
                out.push(format!(
                    "`ai.kill-switch` is `{switch}`, which is not `NAME=value` for an environment \
                     variable"
                ));
            }
        }
        if let Some(tool) = &self.record_tool
            && !tool.args.values().any(|v| v.contains("{id}"))
        {
            out.push(format!(
                "`ai.record-tool` ({}) has no argument with `{{id}}`, so the test model could not \
                 name a record",
                tool.name
            ));
        }
        for name in self.base_url_env.iter().chain(&self.mcp_url_env) {
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                out.push(format!(
                    "`ai.base-url-env` names `{name}`, which is not an environment variable name"
                ));
            }
        }
        out
    }
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
    /// Saves something as the signed-in person, with `{marker}` in a field (and `{csrf}` where the
    /// page's anti-forgery token goes). With it, the probes can tell whose account a sign-in lands
    /// in: two people who share an email address at the provider must not share an account
    /// (V10.5.2).
    #[serde(default)]
    pub create: Option<RequestTemplate>,
    /// A page, for the signed-in person, where what `create` saved appears. Defaults to `private`.
    #[serde(default)]
    pub shows: Option<String>,
}

/// One request the probes make on the app's behalf: how to sign up, sign in, or create something.
///
/// Values may use `{user}`, `{password}`, `{csrf}` (a token read from the page first), `{marker}`
/// (a unique string the probe can look for afterwards), in `change-password`, `{new_password}`,
/// and, in `change-email`, `{new_email}`. A body is sent as a form unless `json` is used instead;
/// never both.
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

/// A request only an admin should be able to make, such as publishing an announcement or changing
/// another user's role.
///
/// The ordinary user sends it first and the admin second, and a refusal counts only when the admin's
/// own request took effect. How the probe tells: put `{marker}` in a field, and name in `check` a page
/// where that text appears once the action has been done. Each send carries a marker of its own, so
/// the page says whose request worked. Without `check`, only an ordinary user's request answered
/// with a 2xx is reported, and nothing is credited, because a refusal cannot be told from a request
/// that did nothing. The run's container is thrown away afterwards, so an action that changes data is
/// safe to list; it is sent twice.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AdminAction {
    #[serde(default = "post")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub form: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub json: std::collections::BTreeMap<String, String>,
    /// A page, read by the admin, where the action's `{marker}` shows once it has taken effect.
    #[serde(default)]
    pub check: Option<String>,
}

/// An action that should go through only once, such as booking the last seat or redeeming a
/// one-time code: the probes send it many times at the same instant, as the first user, and count
/// how many answers say it went through. The app has to start the run with exactly one of the thing
/// to take, set up by `seed` or by the app itself, and nothing else in the run takes it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OnceAction {
    #[serde(default = "post")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub form: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub json: std::collections::BTreeMap<String, String>,
    /// Text the answer carries only when the action went through: in the page, or in the address
    /// it sends the browser on to. "Booked", say, or `/bookings/`.
    pub completed: String,
}

impl OnceAction {
    /// The request itself, in the shape every other request here has.
    pub fn request(&self) -> RequestTemplate {
        RequestTemplate {
            method: self.method.clone(),
            path: self.path.clone(),
            form: self.form.clone(),
            json: self.json.clone(),
        }
    }
}

impl AdminAction {
    /// The request itself, in the shape every other request here has.
    pub fn request(&self) -> RequestTemplate {
        RequestTemplate {
            method: self.method.clone(),
            path: self.path.clone(),
            form: self.form.clone(),
            json: self.json.clone(),
        }
    }

    /// Whether the request carries `{marker}` anywhere it is sent.
    pub fn carries_marker(&self) -> bool {
        self.path.contains("{marker}")
            || self
                .form
                .values()
                .chain(self.json.values())
                .any(|v| v.contains("{marker}"))
    }
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
    /// Where a signed-in user's records are listed (`/notes`, `/api/notes`). The second user opens it,
    /// as they open every `private` page, and the first user's record shown there is a finding
    /// (V8.2.2, ADR-053).
    #[serde(default)]
    pub list: Option<String>,
    /// Changes a record, with `{id}` for which and `{marker}` where the new text goes. Sent by the
    /// second user at the first user's record; the first user then reads it back, and the change
    /// showing there is a finding (V8.2.2, ADR-053).
    #[serde(default)]
    pub update: Option<RequestTemplate>,
    /// Deletes a record, with `{id}` for which. Sent by the second user at the first user's record,
    /// last of all; the first user then reads it back, and the record gone is a finding (V8.2.2,
    /// ADR-053).
    #[serde(default)]
    pub delete: Option<RequestTemplate>,
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
    /// sign-in with that secret, and, when there is an admin too, `SV_ADMIN_TOTP_SECRET` (base32)
    /// to enroll the admin with, for an app that asks admins for a code.
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
    /// The app's own addresses that send the browser on to an address they are given, outside the
    /// sign-in flow (a "continue to" link, a language switch that returns where it came from): each is
    /// asked by the first user, signed in, with an address outside the app in the parameters a return
    /// address is usually read from (V3.7.2). Only ever a finding.
    #[serde(default)]
    pub redirects: Vec<String>,
    /// Pages only an admin should see. Needs `seed`, which is the only way to make an admin.
    #[serde(default)]
    pub admin: Vec<String>,
    /// Requests only an admin should be able to make: each is sent by the first ordinary user and
    /// then by the admin. Needs `seed`, as `admin` does.
    #[serde(default)]
    pub admin_actions: Vec<AdminAction>,
    /// An action that should go through only once however many times it is sent at the same
    /// instant (V2.3.4).
    #[serde(default)]
    pub once: Option<OnceAction>,
    #[serde(default)]
    pub owned: Option<OwnedSection>,
    /// Other requests that each create a record, beside `owned`'s `create`: each is sent one more
    /// time than `[policy] requests-per-minute` inside a minute by the second user, as `owned`'s is
    /// (V2.4.1). Put `{marker}` where a value must differ from one record to the next.
    #[serde(default)]
    pub creates: Vec<RequestTemplate>,
    /// Changes the signed-in user's password: `{password}` is the current one, `{new_password}`
    /// the new. Asked last, with an account made for it through `signup`, or with A when there is
    /// no `signup`.
    #[serde(default)]
    pub change_password: Option<RequestTemplate>,
    /// Changes the signed-in user's email address: `{password}` is the current password, asked for
    /// again, and `{new_email}` the new address. Only ever used on an account made for it through
    /// `signup`, and only judged when sign-in is by email address (`{user}`).
    #[serde(default)]
    pub change_email: Option<RequestTemplate>,
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
    /// How an account made through `signup` is activated with the code the app emails at sign-up:
    /// `use` with `{code}`. Only used with `signup` and a mail sink.
    #[serde(default)]
    pub activation: Option<ActivationSection>,
    /// A flow of more than one step, so the probes can try skipping one.
    #[serde(default)]
    pub flow: Option<FlowSection>,
    /// The second step of a two-factor sign-in: `{code}` for the six-digit code, sent in the
    /// session the password step began. Needs `seed`, which is given a third account and its
    /// secret (`SV_USER_TOTP`, `SV_PASSWORD_TOTP`, `SV_TOTP_SECRET`) to enroll, and a secret for the
    /// admin (`SV_ADMIN_TOTP_SECRET`) when admin pages are listed; the admin's sign-in is finished
    /// with its code when the password alone does not open the private page.
    #[serde(default)]
    pub totp: Option<RequestTemplate>,
    /// Checks made in a real browser, signed in as the first user. Present, even empty, it starts
    /// a headless Chromium on the fenced network for the run.
    #[serde(default)]
    pub browser: Option<BrowserSection>,
    /// A WebSocket path that only a signed-in user should be able to open. The handshake is sent
    /// with the first user's session, with none, and with one the probes made up.
    #[serde(default)]
    pub private_websocket: Option<String>,
}

/// `[stack.run.users.browser]`: what a real browser is asked to do as the first user.
///
/// Every private page is opened in it to see whether the sign-out control can be seen; a sign-in of
/// its own is signed out with that control to see whether the browser's storage is emptied; and, with
/// `text-form`, a line of text containing markup is typed into a form to see whether the page that
/// shows it draws the markup or the text.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BrowserSection {
    /// A page with a form a signed-in user types text into, such as a new note or a comment.
    #[serde(default)]
    pub text_form: Option<String>,
    /// The page that shows what was typed. Absent means the page the form leads to.
    #[serde(default)]
    pub shows: Option<String>,
}

/// Activating a new account with the code emailed at sign-up.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ActivationSection {
    /// Uses the code: `{code}` for it, in the path or a field; `{user}` if the app wants the address.
    #[serde(rename = "use")]
    pub use_code: RequestTemplate,
    /// Where the code is in the email, as for `reset`.
    #[serde(default)]
    pub code_pattern: Option<String>,
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
    /// The compressed formats the owner says the app unpacks (V5.2.3; ADR-046). Absent means not
    /// said, and no archive is sent; empty means none, and none is sent either. Only the formats
    /// listed are sent, so an app that unpacks zip and not gzip is never judged on gzip.
    #[serde(default)]
    pub unpacks_archives: Option<Vec<ArchiveFormat>>,
    /// The most, in bytes, the owner says one archive may unpack to. Absent means that half of
    /// V5.2.3 is not assessed: `sv` sets no limit of its own.
    #[serde(default)]
    pub max_unpacked_bytes: Option<u64>,
    /// The most files the owner says one archive may hold. Absent means that half is not assessed.
    #[serde(default)]
    pub max_files: Option<u64>,
}

/// A compressed format an app may unpack, as `unpacks-archives` names it.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveFormat {
    /// A `.zip`, which may hold many files.
    Zip,
    /// A `.gz`, which holds one.
    Gzip,
}

impl ArchiveFormat {
    /// The name it is written with in `stackvet.toml` and in the report.
    pub fn name(self) -> &'static str {
        match self {
            ArchiveFormat::Zip => "zip",
            ArchiveFormat::Gzip => "gzip",
        }
    }
}

impl UsersSection {
    /// Whether the run makes an admin account: for the admin pages, and for the admin actions,
    /// which are sent as the admin too. Until 6 October 2026 only `admin` made one, so
    /// `admin-actions` alone were never asked (the documentation review, item 3).
    pub fn makes_an_admin(&self) -> bool {
        !self.admin.is_empty() || !self.admin_actions.is_empty()
    }

    /// What is missing for the signed-in probes to run at all, in the words the report will use.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.login.is_none() {
            out.push("`login` is not set, so there is no way to sign in".to_owned());
        }
        if self.seed.is_none() && self.signup.is_none() {
            out.push("neither `seed` nor `signup` is set, so no accounts can be made".to_owned());
        }
        if self.private.is_empty()
            && self.admin.is_empty()
            && self.admin_actions.is_empty()
            && self.owned.is_none()
        {
            out.push(
                "none of `private`, `admin` or `owned` is set, so there is nothing to ask as a \
                 signed-in user"
                    .to_owned(),
            );
        }
        if !self.admin_actions.is_empty() && self.seed.is_none() {
            out.push(
                "`admin-actions` are listed without `seed`, and an admin can only be made by `seed`"
                    .to_owned(),
            );
        }
        for action in &self.admin_actions {
            if !action.form.is_empty() && !action.json.is_empty() {
                out.push(format!(
                    "the admin action `{}` has both `form` and `json`; a request sends one",
                    action.path
                ));
            }
            if let Some(check) = &action.check {
                if !check.starts_with('/') {
                    out.push(format!(
                        "the admin action `{}` has `check = \"{check}\"`, which is not a path on the \
                         app; it has to begin with `/`",
                        action.path
                    ));
                }
                if !action.carries_marker() {
                    out.push(format!(
                        "the admin action `{}` has a `check` page and no `{{marker}}` in the request, so \
                         there is nothing to look for on that page",
                        action.path
                    ));
                }
            }
        }
        if let Some(once) = &self.once {
            if !once.form.is_empty() && !once.json.is_empty() {
                out.push(format!(
                    "`once` ({}) has both `form` and `json`; a request sends one",
                    once.path
                ));
            }
            if once.completed.trim().is_empty() {
                out.push(format!(
                    "`once` ({}) has no `completed` text, so an answer that went through cannot be \
                     told from one that was refused",
                    once.path
                ));
            }
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
        if let Some(activation) = &self.activation {
            let t = &activation.use_code;
            if !(t.path.contains("{code}")
                || t.form
                    .values()
                    .chain(t.json.values())
                    .any(|v| v.contains("{code}")))
            {
                out.push(format!(
                    "`activation.use` ({}) has no `{{code}}`, so what the email carried is never sent",
                    t.path
                ));
            }
        }
        if let Some(path) = &self.private_websocket
            && !path.starts_with('/')
        {
            out.push(format!(
                "`private-websocket` ({path}) is not a path on the app; it has to begin with `/`"
            ));
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
        if let Some(t) = &self.change_email
            && !t
                .form
                .values()
                .chain(t.json.values())
                .any(|v| v.contains("{new_email}"))
        {
            out.push(format!(
                "`change-email` ({}) has no field with `{{new_email}}`, so there is no new address \
                 to change to",
                t.path
            ));
        }
        for t in [
            &self.signup,
            &self.login,
            &self.logout,
            &self.change_password,
            &self.change_email,
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
        )
        .chain(self.activation.iter().map(|a| &a.use_code))
        {
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
    /// Folders that hold something other than the app: test fixtures, example apps, sample code.
    /// Their code is still checked and its findings still count, listed apart; what is in them
    /// cannot change which requirements apply. See `Manifest::not_the_app`.
    #[serde(default)]
    pub not_the_app: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DataSection {
    /// What the app holds about people. `None` when nobody answered, which is not the same as
    /// `[]`, "nothing": an unanswered list must not lower the target level.
    #[serde(default)]
    pub categories: Option<Vec<String>>,
}

impl DataSection {
    /// The categories as written, or none when nobody answered.
    pub fn listed(&self) -> &[String] {
        self.categories.as_deref().unwrap_or_default()
    }
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
    /// Messages a minute the AI feature should pass on to its model before refusing more, for
    /// C11.2.2: sized to how much an attacker could learn by asking, which only the owner can say.
    #[serde(default)]
    pub ai_requests_per_minute: Option<u32>,
    /// Records a minute one user should be able to create through `owned` before the app pushes
    /// back, for V2.4.1: the number the owner would defend, which only the owner can say.
    #[serde(default)]
    pub requests_per_minute: Option<u32>,
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

/// One answer to a design question: how the app is built, in the owner's words or the AI tool's.
///
/// `yes` is the weakest positive answer `sv` has. It is the owner asserting a property, which is
/// not the property, so it never becomes *checked* and never settles a threat. `no` is the owner
/// saying the control is missing, which is a finding on their own word. Silence and `not-sure` add
/// nothing at all, which is the point of having a third answer: a question the owner cannot answer
/// must not be rounded down to "no" or up to "yes". `planned` is a decision made before the code,
/// which credits nothing and is held to once the code exists (`sv-check::design`).
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DesignAnswer {
    /// `yes`, `no`, `not-sure`, or `planned`. Anything else is reported as unreadable.
    pub answer: String,
    /// The file that does it, so somebody can go and look, and so a stale pointer can be caught.
    #[serde(default)]
    pub r#where: Option<String>,
    /// Who answered: `owner`, or `ai-tool` for the AI coding tool that wrote the app. Left out, it
    /// counts as the AI tool's, the weaker of the two, because this file is usually written by the
    /// tool and an answer must not be credited to the owner on nobody's say-so.
    #[serde(default)]
    pub by: Option<String>,
    /// A person confirming the AI tool's answer, with what they looked at. See `sv-check::confirm`.
    #[serde(default)]
    pub confirmed: Option<Confirmed>,
    /// What `sv review` writes when the owner records the answer as theirs. Without one that holds,
    /// `by = "owner"` counts as the AI tool's word. See `sv-check::seal`.
    #[serde(default)]
    pub seal: Option<String>,
}

/// A person confirming what the AI coding tool said. See `sv-check::confirm`.
///
/// It names the answer it confirms (`answer` and `where`, or `result`), so an answer changed later
/// is not carried by a confirmation of the old one.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Confirmed {
    /// `owner`, or the name of whoever confirmed it. Never the AI coding tool.
    #[serde(default)]
    pub by: Option<String>,
    /// The day it was confirmed, `YYYY-MM-DD`.
    #[serde(default)]
    pub on: Option<String>,
    /// What the person looked at or tried, and saw, in a sentence.
    #[serde(default)]
    pub how: Option<String>,
    /// For a design answer: the answer confirmed.
    #[serde(default)]
    pub answer: Option<String>,
    /// For a design answer: its `where` when confirmed.
    #[serde(default)]
    pub r#where: Option<String>,
    /// For a check made by hand: the result confirmed.
    #[serde(default)]
    pub result: Option<String>,
    /// What `sv review` writes when a person records the confirmation. Without one that holds, the
    /// confirmation is a proposal. See `sv-check::seal`.
    #[serde(default)]
    pub seal: Option<String>,
}

/// One check made by hand, and what was seen. See `sv-check::hand`.
///
/// A person looked at the running app or its setup — the certificate on the live site, whether a
/// booking can be made twice — and says what happened. `how` is required because it is the whole of
/// the evidence: one sentence anyone can read and judge. `on` is required because a check goes out
/// of date; what held in March says little about the app in October.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HandCheck {
    /// `done`, `problem`, or `not-yet`. Anything else is reported as unreadable.
    pub result: String,
    /// The day it was checked, `YYYY-MM-DD`.
    #[serde(default)]
    pub on: Option<String>,
    /// `owner` or `ai-tool`, as for a design answer; left out, it counts as the AI tool's.
    #[serde(default)]
    pub by: Option<String>,
    /// What was done and what was seen, in a sentence.
    #[serde(default)]
    pub how: Option<String>,
    /// A person confirming a check the AI tool made. See `sv-check::confirm`.
    #[serde(default)]
    pub confirmed: Option<Confirmed>,
    /// What `sv review` writes when the owner records the check as theirs. Without one that holds,
    /// `by = "owner"` counts as the AI tool's word. See `sv-check::seal`.
    #[serde(default)]
    pub seal: Option<String>,
}

/// The `manifest-version` this `sv` reads.
pub const MANIFEST_VERSION: u32 = 1;

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
    /// The checks made by hand, keyed by requirement id. See `sv-check::hand`.
    #[serde(default)]
    pub checked_by_hand: std::collections::BTreeMap<String, HandCheck>,
    /// The policy numbers a probe can hold the running app to.
    #[serde(default)]
    pub policy: PolicySection,
    /// Findings a person has looked at and set aside: a false alarm, or a risk they accept for now.
    /// See `sv-check::review`.
    #[serde(default, rename = "finding-review")]
    pub finding_review: Vec<FindingReview>,
}

/// One finding set aside, as `[[finding-review]]` in stackvet.toml.
///
/// It names the finding by its rule, its file, and the fingerprint the report prints beside it, and
/// says what a person decided and why. Only an entry a person recorded through `sv review`, which
/// seals it, counts: any other is shown as a proposal and the finding still counts.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FindingReview {
    pub rule: String,
    pub file: String,
    pub fingerprint: String,
    /// `false-alarm` (the code is fine) or `accepted-risk` (a real problem, lived with for now).
    pub verdict: String,
    /// Why, in a sentence or more: what was looked at, and what it showed.
    #[serde(default)]
    pub why: String,
    /// Who decided: `owner`, a person's name, or `ai-tool` for the tool's own proposal.
    #[serde(default)]
    pub by: Option<String>,
    /// When, as YYYY-MM-DD.
    #[serde(default)]
    pub on: Option<String>,
    /// What `sv review` writes when a person records the entry. Without one that holds, the entry is
    /// a proposal. See `sv-check::seal`.
    #[serde(default)]
    pub seal: Option<String>,
}

impl Manifest {
    /// The folders `[repository] not-the-app` names, as paths from the app folder with `/`
    /// separators, and the entries refused, each with why. `*` stands for one whole folder name, as
    /// in `crates/*/tests`. An entry that would name the whole app, or reach outside it, is refused:
    /// the list moves findings down the page and keeps code from changing which requirements apply,
    /// so an entry that covered the app would silence the check it exists to sharpen.
    pub fn not_the_app(&self) -> (Vec<String>, Vec<String>) {
        let mut folders = Vec::new();
        let mut refused = Vec::new();
        for entry in &self.repository.not_the_app {
            let path = entry.trim().replace('\\', "/");
            let path = path.trim_start_matches("./").trim_end_matches('/');
            let parts: Vec<&str> = path.split('/').collect();
            let why = if path.is_empty() || path == "." || parts.iter().all(|p| *p == "*") {
                Some("it names the whole app")
            } else if path.starts_with('/') || path.contains(':') {
                Some("it is not a path inside the app folder")
            } else if parts
                .iter()
                .any(|p| *p == ".." || p.is_empty() || *p == ".")
            {
                Some("it is not a plain path inside the app folder")
            } else if parts.iter().any(|p| p.contains('*') && *p != "*") {
                Some("`*` can only stand for a whole folder name")
            } else {
                None
            };
            // A folder holding the file the start command runs is the app (gap analysis, item 19).
            let starts = self
                .start_files()
                .into_iter()
                .find(|file| why.is_none() && within(file, &parts));
            match (why, starts) {
                (Some(why), _) => refused.push(format!("`{entry}`: {why}, so it is not used")),
                (None, Some(file)) => refused.push(format!(
                    "`{entry}`: it holds `{file}`, which the start command runs, so it is not used"
                )),
                (None, None) => folders.push(path.to_owned()),
            }
        }
        (folders, refused)
    }

    /// The files `[stack.run] start` names, as paths from the app folder: a word that is a path
    /// (`server/index.js`, `./app.py`), a Python module run with `-m` (`app.server` is
    /// `app/server`), and an ASGI or WSGI app named as `module:object` (`app.main:app` is
    /// `app/main.py`). A start that names no file (`npm start`) gives none.
    pub fn start_files(&self) -> Vec<String> {
        const CODE: &[&str] = &[
            "py", "js", "mjs", "cjs", "ts", "mts", "rb", "php", "go", "sh", "jar", "dll", "exs",
        ];
        let Some(start) = self.stack.run.start.as_deref() else {
            return Vec::new();
        };
        let words: Vec<&str> = start
            .split_whitespace()
            .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
            .collect();
        let mut out = Vec::new();
        for (i, word) in words.iter().enumerate() {
            let word = word.trim_start_matches("./");
            if word.starts_with('-')
                || word.contains('=')
                || word.starts_with('/')
                || word.is_empty()
            {
                continue;
            }
            let module = |m: &str| m.replace('.', "/");
            if i > 0 && words[i - 1] == "-m" {
                out.push(module(word));
            } else if let Some((m, object)) = word.split_once(':')
                && !m.is_empty()
                && !object.is_empty()
                && m.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
            {
                out.push(format!("{}.py", module(m)));
            } else if word
                .rsplit_once('.')
                .is_some_and(|(_, ext)| CODE.contains(&ext))
                || word.contains('/')
            {
                out.push(word.to_owned());
            }
        }
        out
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text, path)
    }

    /// The manifest of the app at `app_dir`, by whichever name it has (`locate`), or the error
    /// every command gives when there is none.
    pub fn load_in(app_dir: &Path) -> Result<(Self, Located)> {
        let located = locate_or_bail(app_dir)?;
        Ok((Self::load(&located.path)?, located))
    }

    /// The manifest in `text`, read from `path`, which only names it in an error. For a caller that
    /// needs the bytes it parsed as well, such as `sv report` recording their hash.
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        // A version this `sv` does not know is not read as if it were the one it knows: its fields
        // may mean something else, and a manifest read wrongly changes what applies. A file with no
        // `manifest-version` line is read as version 1, as it always was (the deep review's
        // improvement 6). Asked before the fields are read, so a later version's own field is not
        // reported as a mistake to move, and a stated 0 is not taken for the line left out (the
        // review of 6 October, item 3).
        let stated = toml::from_str::<toml::Table>(text)
            .ok()
            .and_then(|table| table.get("manifest-version").cloned());
        if let Some(stated) = stated {
            anyhow::ensure!(
                stated.as_integer() == Some(i64::from(MANIFEST_VERSION)),
                "{} says manifest-version = {stated}, and this sv reads version {MANIFEST_VERSION} \
                 only. A later sv may read it; this one would read it wrongly, so it does not read \
                 it at all.",
                path.display(),
            );
        }
        // A field in the wrong section is named with the section it was read in, and with where a
        // field of that name belongs (`schema::explain`).
        let manifest: Self = toml::from_str(text)
            .map_err(|e| anyhow::anyhow!(schema::explain(text, &e)))
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(manifest)
    }

    /// The ASVS target level. Sensitive data or a public audience means level 2, as in v1.
    ///
    /// So does not saying what data the app holds: level 1 is a claim that nothing sensitive is
    /// held, and a list nobody filled in makes no claim. The starter file once wrote `categories =
    /// []`, and an owner who never looked at it got level 1 as a quiet "no".
    pub fn target_level(&self) -> u8 {
        let sensitive = match &self.data.categories {
            None => true,
            Some(listed) => listed.iter().map(|c| category_name(c)).any(|c| {
                SENSITIVE_DATA_CATEGORIES.contains(&c.as_str())
                    || !DATA_CATEGORIES.contains(&c.as_str())
            }),
        };
        let exposed = matches!(self.app.audience, Audience::Customers | Audience::Public);
        if sensitive || exposed { 2 } else { 1 }
    }

    /// Why the level is 2 when only the unanswered data list made it so, in words for the owner;
    /// `None` when the level rests on an answer.
    pub fn level_from_unanswered_data(&self) -> Option<&'static str> {
        let exposed = matches!(self.app.audience, Audience::Customers | Audience::Public);
        (self.data.categories.is_none() && !exposed).then_some(
            "stackvet.toml does not say what information the app holds about people (`[data] \
             categories`), so the app is held to ASVS level 2, the level for apps that hold \
             sensitive information such as health or financial details. List what it holds, or \
             write `categories = []` if it holds nothing about people; if nothing on the list is \
             sensitive, the level becomes 1.",
        )
    }

    /// The names under `[data] categories` that are not on the list, as written, and why they hold
    /// the app to level 2; `None` when every name is on it. A misspelled `"helth"` is not an answer
    /// that the app holds nothing sensitive.
    pub fn level_from_unknown_data(&self) -> Option<String> {
        let unknown: Vec<&str> = self
            .data
            .categories
            .iter()
            .flatten()
            .filter(|c| !DATA_CATEGORIES.contains(&category_name(c).as_str()))
            .map(String::as_str)
            .collect();
        (!unknown.is_empty()).then(|| {
            format!(
                "stackvet.toml lists {} under `[data] categories`, which {} not among the names \
                 `sv` knows ({}), so nothing shows {} not sensitive, and the app is held to ASVS \
                 level 2. Use the names on that list.",
                unknown
                    .iter()
                    .map(|c| format!("`{c}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                if unknown.len() == 1 { "is" } else { "are" },
                DATA_CATEGORIES.join(", "),
                if unknown.len() == 1 {
                    "it is"
                } else {
                    "they are"
                }
            )
        })
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
            (Condition::McpServer, c.mcp_server),
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
            (Condition::WebSearch, about_ai(c.ai.web_search)),
            (Condition::GeneratesMedia, about_ai(c.ai.generates_media)),
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

/// Whether a path from the app folder is the entry whose path parts are `folder`, or lies inside it,
/// a `*` standing for any one name, as `sv_scan::under_any` reads a `not-the-app` entry.
fn within(path: &str, folder: &[&str]) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    folder.len() <= parts.len()
        && folder
            .iter()
            .zip(&parts)
            .all(|(want, got)| *want == "*" || want == got)
}

#[cfg(test)]
mod tests {
    #[test]
    fn folders_that_are_not_the_app_are_read_and_the_whole_app_is_refused() {
        let manifest: Manifest = toml::from_str(
            "[repository]\nnot-the-app = [\"examples/\", \"./crates/*/tests\", \"tests\\\\fixtures\", \
             \".\", \"\", \"*\", \"*/*\", \"../other\", \"/etc\", \"C:/app\", \"a//b\", \"a/./b\", \"test*\"]\n",
        )
        .unwrap();
        let (folders, refused) = manifest.not_the_app();
        assert_eq!(
            folders,
            vec!["examples", "crates/*/tests", "tests/fixtures"]
        );
        assert_eq!(refused.len(), 10, "{refused:#?}");
        assert!(refused[0].contains("names the whole app"), "{}", refused[0]);
        assert!(refused.iter().all(|r| r.ends_with("so it is not used")));
    }

    use super::*;

    #[test]
    fn the_file_the_start_command_runs_is_read_and_its_folder_refused() {
        // Gap analysis, item 19.
        let files = |start: &str| {
            let m: Manifest = toml::from_str(&format!("[stack.run]\nstart = {start:?}\n")).unwrap();
            m.start_files()
        };
        assert_eq!(files("node ./server/index.js"), ["server/index.js"]);
        assert_eq!(files("PORT=3000 python app.py --debug"), ["app.py"]);
        assert_eq!(files("python -m api.server"), ["api/server"]);
        assert_eq!(
            files("uvicorn app.main:app --host 0.0.0.0"),
            ["app/main.py"]
        );
        assert_eq!(files("gunicorn 'web.wsgi:application'"), ["web/wsgi.py"]);
        assert!(files("npm start").is_empty());
        assert!(files("/usr/bin/env node").is_empty());

        let manifest: Manifest = toml::from_str(
            "[stack.run]\nstart = \"node server/index.js\"\n\
             [repository]\nnot-the-app = [\"server\", \"*\", \"examples\", \"server/index.js/x\"]\n",
        )
        .unwrap();
        let (folders, refused) = manifest.not_the_app();
        assert_eq!(folders, ["examples", "server/index.js/x"]);
        assert!(
            refused.iter().any(|r| r
                == "`server`: it holds `server/index.js`, which the start command runs, so it is not used"),
            "{refused:#?}"
        );
        // A `*` folder holds it too.
        let manifest: Manifest = toml::from_str(
            "[stack.run]\nstart = \"node server/index.js\"\n[repository]\nnot-the-app = [\"*/index.js\"]\n",
        )
        .unwrap();
        assert!(manifest.not_the_app().0.is_empty());
    }

    #[test]
    fn a_record_tool_is_read_only_only_when_it_says_so() {
        // ADR-045: the loop question calls the app's own tool only on the owner's word.
        let marked: AiSection = toml::from_str(
            "chat = { path = \"/chat\" }\nrecord-tool = { name = \"get_note\", args = { id = \"{id}\" }, read-only = true }",
        )
        .expect("parses");
        assert!(marked.record_tool.as_ref().expect("read").read_only);
        let unmarked: AiSection = toml::from_str(
            "chat = { path = \"/chat\" }\nrecord-tool = { name = \"get_note\", args = { id = \"{id}\" } }",
        )
        .expect("parses");
        assert!(!unmarked.record_tool.as_ref().expect("read").read_only);
        // Spelled as Rust names it, it is refused rather than read as unmarked.
        assert!(
            toml::from_str::<AiSection>(
                "chat = { path = \"/chat\" }\nrecord-tool = { name = \"get_note\", read_only = true }",
            )
            .is_err()
        );
    }

    #[test]
    fn a_once_action_is_read_and_held_to_its_completed_text() {
        let users: UsersSection = toml::from_str(
            "seed = \"seed\"\nlogin = { path = \"/login\" }\nprivate = [\"/account\"]\n\
             once = { path = \"/book\", form = { slot = \"1\" }, completed = \"Booked\" }",
        )
        .expect("parses");
        let once = users.once.as_ref().expect("read");
        assert_eq!(
            (once.method.as_str(), once.completed.as_str()),
            ("POST", "Booked")
        );
        assert_eq!(
            once.request().form.get("slot").map(String::as_str),
            Some("1")
        );
        assert!(users.problems().is_empty(), "{:?}", users.problems());
        let mut blank = users.clone();
        blank.once.as_mut().unwrap().completed = " ".into();
        assert!(
            blank
                .problems()
                .iter()
                .any(|p| p.contains("no `completed`")),
            "{:?}",
            blank.problems()
        );
        let mut both = users;
        both.once
            .as_mut()
            .unwrap()
            .json
            .insert("slot".into(), "1".into());
        assert!(
            both.problems()
                .iter()
                .any(|p| p.contains("both `form` and `json`")),
            "{:?}",
            both.problems()
        );
    }

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
        users.change_email = Some(template(&[("password", "{password}"), ("email", "{user}")]));
        let problems = users.problems();
        assert!(
            problems.iter().any(|p| p.contains("{new_email}")),
            "{problems:?}"
        );
        users.change_email = Some(template(&[
            ("password", "{password}"),
            ("email", "{new_email}"),
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
    fn the_starter_file_answers_no_capability_for_the_tool() {
        // The owner's decision, 27 September 2026: every capability line in the starter file starts
        // commented out, because a tool that leaves a line as it found it had answered "no" to it,
        // and whole sets of requirements were switched off on nobody's word.
        let m: Manifest =
            toml::from_str(crate::spec::STARTER_MANIFEST).expect("the starter parses");
        let (ctx, _) = resolve(&m, &|_| None);
        let claims: Vec<Condition> = Condition::ALL
            .iter()
            .copied()
            .filter(|c| c.source() == sv_frameworks::Source::Claim)
            .collect();
        assert!(
            claims.len() > 20,
            "the setup must reach the claims: {}",
            claims.len()
        );
        // What the starter still states outright, on purpose: TLS has a default mode, and the
        // internet and level answers come from other lines.
        let stated_on_purpose = [Condition::Tls, Condition::Internet, Condition::Level2];
        for c in claims {
            if stated_on_purpose.contains(&c) {
                continue;
            }
            assert_eq!(
                ctx.get(c),
                None,
                "{} is answered by the starter file itself; it must start unanswered",
                c.name()
            );
        }
        // And a line uncommented without an answer is refused, not read as anything.
        let careless = crate::spec::STARTER_MANIFEST.replacen("# auth = ?", "auth = ?", 1);
        assert!(
            toml::from_str::<Manifest>(&careless).is_err(),
            "`auth = ?` must not parse"
        );
    }

    #[test]
    fn media_the_ai_makes_is_its_own_answer() {
        let m: Manifest =
            toml::from_str("[capabilities.ai]\nenabled = true\ngenerates-media = true\n").unwrap();
        let (ctx, _) = resolve(&m, &|_| None);
        assert_eq!(ctx.get(Condition::GeneratesMedia), Some(true));
        assert_eq!(ctx.get(Condition::Rag), None, "nor is it read as retrieval");
    }

    #[test]
    fn a_web_search_is_its_own_answer_and_not_a_document_store() {
        let m: Manifest =
            toml::from_str("[capabilities.ai]\nenabled = true\nrag = false\nweb-search = true\n")
                .expect("manifest parses");
        let (ctx, _) = resolve(&m, &|_| None);
        assert_eq!(ctx.get(Condition::WebSearch), Some(true));
        assert_eq!(ctx.get(Condition::Rag), Some(false));
        // Left out, it is unanswered, never a quiet no.
        let silent: Manifest = toml::from_str("[capabilities.ai]\nenabled = true\n").unwrap();
        let (ctx, _) = resolve(&silent, &|_| None);
        assert_eq!(ctx.get(Condition::WebSearch), None);
    }

    #[test]
    fn ai_sub_claims_are_settled_by_there_being_no_ai() {
        let mut m = Manifest::default();
        m.capabilities.ai.enabled = Some(false);
        let (ctx, _) = resolve(&m, &|_| None);
        for c in [
            Condition::AiActions,
            Condition::Rag,
            Condition::WebSearch,
            Condition::GeneratesMedia,
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
        m.data.categories = Some(vec!["contact".into()]);
        assert_eq!(m.target_level(), 1);
        m.data.categories = Some(vec!["health".into()]);
        assert_eq!(m.target_level(), 2);
    }

    #[test]
    fn a_data_category_not_on_the_list_is_not_a_quiet_no_either() {
        // The documentation review of 6 October 2026, item 7: a misspelled "helth" allowed
        // level 1, and nothing said so.
        let mut m = Manifest::default();
        m.app.audience = Audience::JustMe;
        m.data.categories = Some(vec!["contact".into(), "helth".into()]);
        assert_eq!(m.target_level(), 2);
        let why = m.level_from_unknown_data().expect("the name is said");
        assert!(why.contains("`helth`") && why.contains("level 2"), "{why}");
        // Spelled with capitals or spaces, a name on the list is that name.
        m.data.categories = Some(vec![" Health ".into()]);
        assert_eq!(m.target_level(), 2);
        assert!(m.level_from_unknown_data().is_none());
        m.data.categories = Some(vec!["Contact".into(), "files".into()]);
        assert_eq!(m.target_level(), 1);
        // The control: every name on the list, none sensitive, is level 1, and nothing is said.
        m.data.categories = Some(
            DATA_CATEGORIES
                .iter()
                .filter(|c| !SENSITIVE_DATA_CATEGORIES.contains(c))
                .map(|c| (*c).to_owned())
                .collect(),
        );
        assert_eq!(m.target_level(), 1);
        assert!(m.level_from_unknown_data().is_none());
    }

    #[test]
    fn the_spec_lists_every_data_category_sv_knows() {
        let spec = crate::spec::STARTER_MANIFEST;
        for c in DATA_CATEGORIES {
            assert!(spec.contains(c), "{c}");
        }
    }

    #[test]
    fn data_nobody_described_is_not_a_quiet_no() {
        // Level 1 says nothing sensitive is held. A list nobody filled in says nothing at all,
        // so it must not buy the lower level; an explicit empty list is an answer and does.
        let parse = |data: &str| -> Manifest {
            toml::from_str(&format!(
                "manifest-version = 1\n[app]\naudience = \"just-me\"\n{data}"
            ))
            .unwrap()
        };
        let silent = parse("");
        assert_eq!(silent.data.categories, None);
        assert_eq!(silent.target_level(), 2, "no [data] section at all");
        assert_eq!(
            parse("[data]\n").target_level(),
            2,
            "an empty [data] section"
        );
        let none = parse("[data]\ncategories = []\n");
        assert_eq!(none.data.categories, Some(vec![]));
        assert_eq!(none.target_level(), 1, "\"nothing\" is an answer");
        // The report says why, and only when the unanswered list is the reason.
        assert!(silent.level_from_unanswered_data().is_some());
        assert!(none.level_from_unanswered_data().is_none());
        let public: Manifest =
            toml::from_str("manifest-version = 1\n[app]\naudience = \"public\"\n").unwrap();
        assert_eq!(public.target_level(), 2);
        assert!(
            public.level_from_unanswered_data().is_none(),
            "a public app is level 2 whatever it holds; blaming the data list would be untrue"
        );
    }

    #[test]
    fn the_starter_file_leaves_the_data_unanswered() {
        let m: Manifest =
            toml::from_str(crate::spec::STARTER_MANIFEST).expect("the starter file parses");
        assert_eq!(
            m.data.categories, None,
            "the starter file must not answer what the app holds on the owner's behalf"
        );
        assert!(
            crate::spec::STARTER_MANIFEST.contains("# categories = ?"),
            "the unanswered line has to be there for the owner to find"
        );
    }

    /// After the spec's two sentences of 6 October 2026, the commonest file `sv` could not read in
    /// the delivery test had `ai = true` straight under [capabilities] (BACKLOG, "`ai = true` under
    /// `[capabilities]`"). The spec says, among the [capabilities] answers, where that answer goes;
    /// and a builder who writes it there anyway is told the same.
    #[test]
    fn the_spec_says_the_ai_answer_is_not_under_capabilities() {
        let spec = crate::spec::STARTER_MANIFEST;
        let capabilities = spec
            .split_once("\n[capabilities]\n")
            .and_then(|(_, rest)| rest.split_once("\n[").map(|(section, _)| section))
            .expect("the starter file has a [capabilities] section");
        assert!(
            capabilities.contains(
                "No `ai` here: whether the app has an AI feature is `enabled` under \
                 [capabilities.ai], below."
            ),
            "{capabilities}"
        );
        assert!(
            spec.contains("[capabilities.ai]\n# enabled = ?"),
            "the section it points to starts with `enabled`"
        );
        // The same mistake, written into the starter file itself, whose [capabilities.ai] header
        // further down makes toml call it a duplicate key.
        let careless = spec.replacen("\n[capabilities]\n", "\n[capabilities]\nai = true\n", 1);
        assert_ne!(careless, spec, "the line was put in");
        let message = format!(
            "{:#}",
            Manifest::parse(&careless, Path::new("stackvet.toml"))
                .expect_err("ai = true under [capabilities] is not read")
        );
        assert!(
            message.contains(
                "[capabilities.ai] starts a section here, but `ai` was already given a value \
                 under [capabilities]"
            ) && message.contains("as `enabled = true` or `enabled = false`"),
            "{message}"
        );
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
        // shipping an authorization server gets V10.4 back whatever stackvet.toml says.
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
            &root.join("data/knowledge"),
            &root.join("data/applicability-v2.json"),
        )
        .unwrap();
        let frameworks = Frameworks::load(&root.join("data/frameworks")).unwrap();

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

    #[test]
    fn an_admin_action_is_read_and_checked_for_what_it_needs() {
        let text = r#"
manifest-version = 1
[app]
name = "x"
[stack.run.users]
login = { path = "/login", form = { email = "{user}", password = "{password}" } }
admin = ["/admin"]

[[stack.run.users.admin-actions]]
path = "/admin/announce"
form = { text = "{marker}" }
check = "/announcements"

[[stack.run.users.admin-actions]]
method = "DELETE"
path = "/admin/users/2"
check = "announcements"
"#;
        let manifest: Manifest = toml::from_str(text).unwrap();
        let users = manifest.stack.run.users.unwrap();
        assert_eq!(users.admin_actions.len(), 2);
        assert_eq!(
            users.admin_actions[0].method, "POST",
            "POST unless it says otherwise"
        );
        assert!(users.admin_actions[0].carries_marker());
        let problems = users.problems().join("\n");
        assert!(
            problems.contains("`admin-actions` are listed without `seed`"),
            "{problems}"
        );
        assert!(problems.contains("not a path on the app"), "{problems}");
        assert!(problems.contains("no `{marker}`"), "{problems}");
        assert!(
            !problems.contains("/admin/announce`"),
            "the first action is written correctly: {problems}"
        );
    }

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

#[cfg(test)]
mod mcp_server_tests {
    use super::*;

    fn effective(toml_text: &str, condition: Condition) -> Option<bool> {
        let m: Manifest = toml::from_str(toml_text).expect("manifest parses");
        resolve(&m, &|_| None).0.get(condition)
    }

    #[test]
    fn an_app_with_no_ai_can_still_serve_tools_over_mcp() {
        // `sv` is one. Every question under [capabilities.ai] reads `false` when `enabled = false`;
        // this one is not under it, so it keeps its answer.
        let m = "[capabilities]\nmcp-server = true\n[capabilities.ai]\nenabled = false\n";
        assert_eq!(effective(m, Condition::McpServer), Some(true));
        assert_eq!(effective(m, Condition::Mcp), Some(false));
    }

    #[test]
    fn saying_nothing_leaves_it_unanswered_whatever_the_ai_does() {
        let m = "[capabilities.ai]\nenabled = true\nmcp = true\n";
        assert_eq!(effective(m, Condition::McpServer), None);
        let m = "[capabilities.ai]\nenabled = false\n";
        assert_eq!(effective(m, Condition::McpServer), None);
    }

    #[test]
    fn the_archive_formats_and_limits_are_read_and_an_unknown_format_is_refused() {
        let base = "path = \"/upload\"\nfield = \"file\"\n";
        let u: UploadSection = toml::from_str(&format!(
            "{base}unpacks-archives = [\"gzip\", \"zip\"]\nmax-unpacked-bytes = 1048576\nmax-files = 10\n"
        ))
        .unwrap();
        assert_eq!(
            u.unpacks_archives,
            Some(vec![ArchiveFormat::Gzip, ArchiveFormat::Zip])
        );
        assert_eq!(
            (u.max_unpacked_bytes, u.max_files),
            (Some(1_048_576), Some(10))
        );
        // Left out is not said, which is not the same as none.
        let u: UploadSection = toml::from_str(base).unwrap();
        assert_eq!(u.unpacks_archives, None);
        let u: UploadSection = toml::from_str(&format!("{base}unpacks-archives = []\n")).unwrap();
        assert_eq!(u.unpacks_archives, Some(vec![]));
        // A format `sv` cannot send is refused by name, rather than quietly never sent.
        let refused =
            toml::from_str::<UploadSection>(&format!("{base}unpacks-archives = [\"rar\"]\n"))
                .expect_err("rar was read");
        assert!(refused.to_string().contains("rar"), "{refused}");
    }

    #[test]
    fn a_manifest_version_this_sv_does_not_know_is_refused() {
        let path = Path::new("stackvet.toml");
        assert!(Manifest::parse("manifest-version = 1\n", path).is_ok());
        assert!(
            Manifest::parse("[app]\nname = \"x\"\n", path).is_ok(),
            "no line is version 1, as it always was"
        );
        // 0 stated is a version this sv does not know, not the line left out; and a later version
        // is refused as one even when it has a field this sv does not (the review of 6 October).
        for (version, more) in [
            (0, ""),
            (2, ""),
            (7, ""),
            (100, ""),
            (2, "[app.channels]\nemail = true\n"),
            (2, "a-later-field = 1\n"),
        ] {
            let text = format!("manifest-version = {version}\n[app]\nname = \"x\"\n{more}");
            let refused = Manifest::parse(&text, path).expect_err("an unknown version was read");
            let said = format!("{refused:#}");
            assert!(
                said.contains(&format!("manifest-version = {version}"))
                    && said.contains("reads version 1 only"),
                "{said}"
            );
        }
    }
}

/// Where an app's manifest is: `stackvet.toml`, or `stackvet.toml` while only it exists, since
/// the file was written under that name until 8 October 2026 (ADR-062).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub path: std::path::PathBuf,
    /// The file still has the old name; `note` says so.
    pub old_name: bool,
}

impl Located {
    /// What the report and the terminal say, once per run, when the old name was read.
    pub fn note(&self) -> Option<String> {
        self.old_name.then(|| {
            format!(
                "{} Every sentence here that names {} means that file.",
                sv_frameworks::names::read_under_old_name(
                    sv_frameworks::names::OLD_MANIFEST,
                    sv_frameworks::names::MANIFEST
                ),
                sv_frameworks::names::MANIFEST
            )
        })
    }
}

/// The manifest in `app_dir`, if there is one: the new name, or the old one while only it exists.
/// A folder with both is refused: two manifests are two answers.
pub fn locate(app_dir: &Path) -> Result<Option<Located>> {
    use sv_frameworks::names::{MANIFEST, OLD_MANIFEST};
    let new = app_dir.join(MANIFEST);
    let old = app_dir.join(OLD_MANIFEST);
    match (new.exists(), old.exists()) {
        (true, true) => anyhow::bail!(
            "{} holds both {MANIFEST} and {OLD_MANIFEST}, and two manifests are two answers. Keep \
             one: {MANIFEST} is the name `sv` writes and reads first.",
            app_dir.display()
        ),
        (true, false) => Ok(Some(Located {
            path: new,
            old_name: false,
        })),
        (false, true) => Ok(Some(Located {
            path: old,
            old_name: true,
        })),
        (false, false) => Ok(None),
    }
}

/// `locate`, or the error every command gives when there is no manifest.
pub fn locate_or_bail(app_dir: &Path) -> Result<Located> {
    locate(app_dir)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no {} in {}. Run `sv init` and give the spec to your AI coding tool.",
            sv_frameworks::names::MANIFEST,
            app_dir.display()
        )
    })
}
