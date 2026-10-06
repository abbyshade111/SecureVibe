//! The report's "Before going live" list: the requirements only the app's own live site can
//! answer, for an app that will be on the internet (`deployment = "internet"`).
//!
//! `sv report` never reaches outside the machine, so it cannot answer these, and in a report they
//! read "not verified" with nothing saying what would settle them. `sv probe`, run by the owner
//! against their own address, asks most of them in a few read-only requests (ADR-027); one is left
//! to a scanner the owner runs (the owner's decision on V12.1.2, 6 October 2026). The list says
//! which is which and the command. It credits nothing: `sv probe`'s answers are printed where it
//! runs and never folded into a report.

use crate::{RequirementLine, Status};
use serde::Serialize;

/// Who answers a requirement about the live site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asker {
    /// `sv probe ADDRESS`, as it is.
    Probe,
    /// `sv probe ADDRESS` with this option added.
    ProbeWith(&'static str),
    /// Not `sv probe`: what the owner does instead.
    ByHand(&'static str),
}

/// One requirement only the live site can answer: its id, what it asks in the owner's words, and
/// who answers it.
pub struct LiveCheck {
    pub id: &'static str,
    pub what: &'static str,
    pub asker: Asker,
}

/// Every requirement `sv probe`'s checks cite (`crates/sv-check/src/production.rs` and
/// `live_tls.rs`, held to this list by `every_requirement_sv_probe_answers_is_listed`), and the
/// one left to a scanner.
pub const LIVE_SITE: &[LiveCheck] = &[
    LiveCheck {
        id: "V12.2.1",
        what: "The site answers over HTTPS, and plain HTTP is no way in",
        asker: Asker::Probe,
    },
    LiveCheck {
        id: "V12.2.2",
        what: "Its certificate is one browsers trust",
        asker: Asker::Probe,
    },
    LiveCheck {
        id: "V12.1.1",
        what: "Old versions of TLS (1.0 and 1.1) are refused",
        asker: Asker::Probe,
    },
    LiveCheck {
        id: "V3.4.1",
        what: "Browsers are told to use HTTPS only (HSTS)",
        asker: Asker::Probe,
    },
    LiveCheck {
        id: "V3.3.3",
        what: "The session cookie's name carries the `__Host-` prefix",
        asker: Asker::Probe,
    },
    LiveCheck {
        id: "V4.1.2",
        what: "A program calling the API over plain HTTP is refused rather than redirected",
        asker: Asker::ProbeWith("--api /a/path/of/your/api"),
    },
    LiveCheck {
        id: "V3.7.4",
        what: "The site is on browsers' HSTS preload list",
        asker: Asker::ProbeWith("--hsts-preload FILE (the list, downloaded)"),
    },
    LiveCheck {
        id: "V12.1.4",
        what: "Revocation answers are stapled to the certificate (OCSP stapling)",
        asker: Asker::Probe,
    },
    LiveCheck {
        id: "V12.1.5",
        what: "Encrypted Client Hello is offered",
        asker: Asker::Probe,
    },
    LiveCheck {
        id: "V12.1.2",
        what: "Only strong encryption settings (cipher suites) are offered",
        asker: Asker::ByHand(
            "a scanner made for it, such as testssl.sh or SSL Labs' online test (see \"What only you can check\")",
        ),
    },
];

/// One line of the list, as the reports show it: the command that asks it, or, when `sv probe`
/// does not, what the owner does instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveItem {
    pub id: String,
    pub what: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_hand: Option<String>,
}

/// The command every line names, with the address left for the owner to fill in.
pub const COMMAND: &str = "sv probe https://your-address";

/// The live-site requirements among `requirements` (those that apply to this app) that nothing has
/// settled: everything but a check that ran here or a check the owner recorded by hand.
pub fn before_going_live(requirements: &[RequirementLine]) -> Vec<LiveItem> {
    LIVE_SITE
        .iter()
        .filter(|live| {
            requirements
                .iter()
                .any(|r| r.id == live.id && !matches!(r.status, Status::Checked | Status::ByHand))
        })
        .map(|live| LiveItem {
            id: live.id.to_owned(),
            what: live.what.to_owned(),
            command: match live.asker {
                Asker::Probe => Some(COMMAND.to_owned()),
                Asker::ProbeWith(option) => Some(format!("{COMMAND} {option}")),
                Asker::ByHand(_) => None,
            },
            by_hand: match live.asker {
                Asker::ByHand(what) => Some(format!("Not sv probe: check it with {what}.")),
                _ => None,
            },
        })
        .collect()
}
