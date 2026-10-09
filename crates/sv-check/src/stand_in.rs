//! The protocol between `sv` and the stand-ins it runs inside the fence: the test model
//! (`crates/sv-run/assets/model-provider.mjs`) and the test sign-in provider (`oidc-provider.mjs`).
//! The scripts are the servers; every Rust client, the Docker runner, and the fakes the tests use
//! in their place take the addresses, markers, and mode names from here rather than writing their
//! own, and the contract tests in `crates/sv-run/tests/` run the real scripts and hold them to these
//! (the architecture assessment of 8 October 2026, item 9: the protocol was written out in each
//! place, and only the model's script was ever run by a test).

/// The address each stand-in answers `{"ok": true}` on once it is up.
pub const HEALTH: &str = "/_sv/health";

/// Where the test model records what reached it for a tag: `seen(tag)`.
pub const SEEN: &str = "/_sv/seen/";
/// An address for a feature of the app that fetches what it is given: `fetch(tag)`.
pub const FETCH: &str = "/_sv/fetch/";
/// The same, answered with a redirect to `FETCH` and the tag with `-after`: `redirect(tag)`.
pub const REDIRECT: &str = "/_sv/redirect/";
/// Whether anything was fetched for a tag through `FETCH`, `REDIRECT`, or `KEYS`: `fetched(tag)`.
pub const FETCHED: &str = "/_sv/fetched/";
/// Where a sign-in token says its key is, answered with public keys alone: `keys(tag)`.
pub const KEYS: &str = "/_sv/keys/";
/// The link the test model hides in a HIDDEN reply.
pub const HIDDEN_LINK: &str = "/_sv/x/";
/// The image address the test model puts in a reply, as a page that leaks would fetch it.
pub const EXFIL: &str = "/_sv/exfil/";

/// The start of the marker every message to the test model carries: `marker(kind, tag)`.
pub const MARKER: &str = "SV-PROBE-";

pub fn seen(tag: &str) -> String {
    format!("{SEEN}{tag}")
}

pub fn fetch(tag: &str) -> String {
    format!("{FETCH}{tag}")
}

pub fn redirect(tag: &str) -> String {
    format!("{REDIRECT}{tag}")
}

pub fn fetched(tag: &str) -> String {
    format!("{FETCHED}{tag}")
}

pub fn keys(tag: &str) -> String {
    format!("{KEYS}{tag}")
}

/// `SV-PROBE-<KIND>-<tag>`, which tells the test model how to answer and what to record.
pub fn marker(kind: &str, tag: &str) -> String {
    format!("{MARKER}{kind}-{tag}")
}

/// The test sign-in provider: `POST MODE` with `mode=<name>` sets how the next ID token is made,
/// once (`oidc-provider.mjs` says what each does).
pub mod oidc {
    pub const MODE: &str = "/_sv/mode";
    pub const NORMAL: &str = "normal";
    pub const WRONG_NONCE: &str = "wrong-nonce";
    pub const WRONG_AUD: &str = "wrong-aud";
    pub const UNSIGNED: &str = "unsigned";
    pub const WRONG_KEY: &str = "wrong-key";
    pub const WRONG_ISS: &str = "wrong-iss";
    pub const WRONG_TOKEN_ISS: &str = "wrong-token-iss";
    pub const OTHER_PERSON: &str = "other-person";
    pub const NEW_EMAIL: &str = "new-email";
    /// Every mode the provider takes, in the order its script lists them.
    pub const MODES: [&str; 9] = [
        NORMAL,
        WRONG_NONCE,
        WRONG_AUD,
        UNSIGNED,
        WRONG_KEY,
        WRONG_ISS,
        WRONG_TOKEN_ISS,
        OTHER_PERSON,
        NEW_EMAIL,
    ];
}
