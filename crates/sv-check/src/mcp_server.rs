//! An app that is itself an MCP server, asked over the Model Context Protocol's HTTP transport.
//!
//! Two questions, each with a control from the same run, when `[stack.run.mcp-server]` says where
//! the endpoint answers:
//!
//! - C10.3.3 asks that the server checks the `Origin` header and the `Host` header, each on its
//!   own, which is what stops a web page in someone's browser from reaching a server on their own
//!   computer (DNS rebinding). A session is started as usual (the control), then once with an
//!   `Origin` from a site it has never heard of, and once under a `Host` that is not its own.
//! - C10.2.6 asks that a session's artifacts are removed when it ends. What a request can see is
//!   the session itself: one is ended with `DELETE` and its `Mcp-Session-Id`, as the transport
//!   says, and then used again. The transport says the server must answer that with 404. Files or
//!   caches the session left behind are not visible from here.

use crate::finding::Severity;
use crate::probes::{ProbeRequest, ProbeResponse};
use crate::signed_in::{Http, Outcome, Rule, finding, status};
use sv_manifest::McpServerSection;

const WHERE_FROM: Rule = Rule {
    rule_id: "probe.mcp-server-origin-unchecked",
    requirement_ids: &["C10.3.3"],
    cwe: &["CWE-346", "CWE-350"],
    impact: "A web page open in someone's browser can send requests to an MCP server on their own \
             computer or network, by pointing its own name at it (DNS rebinding). A server that \
             does not check where requests come from answers them, and hands the page its tools.",
    fix: "Refuse any request whose `Origin` is not one you expect (403), and any whose `Host` is \
          not a name the server is meant to answer to, checking each on its own. The official \
          MCP libraries have a setting for both (for example `allowedOrigins` and `allowedHosts` \
          with DNS rebinding protection turned on).",
};

const SESSION_KEPT: Rule = Rule {
    rule_id: "probe.mcp-session-survives-end",
    requirement_ids: &["C10.2.6"],
    cwe: &["CWE-613"],
    impact: "A session that still works after it was ended can be picked up by whoever learns its \
             ID, and whatever the server kept for it is still there.",
    fix: "When a client ends a session with `DELETE`, forget its ID and everything kept for it, and \
          answer any later request carrying that ID with 404, as the MCP transport requires.",
};

const PROTOCOL: &str = "2025-06-18";
const STRANGER: &str = "http://sv-evil.invalid";
const REBOUND: &str = "sv-rebind.invalid";

fn rpc(id: u32, method: &str) -> String {
    let params = if method == "initialize" {
        serde_json::json!({
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "sv", "version": env!("CARGO_PKG_VERSION")},
        })
    } else {
        serde_json::json!({})
    };
    serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

fn request(
    id: &str,
    method: &str,
    path: &str,
    body: Option<String>,
    session: Option<&str>,
    extra: &[(&str, &str)],
) -> ProbeRequest {
    let mut headers: Vec<(String, String)> = vec![
        ("Content-Type".into(), "application/json".into()),
        (
            "Accept".into(),
            "application/json, text/event-stream".into(),
        ),
    ];
    if let Some(session) = session {
        headers.push(("Mcp-Session-Id".into(), session.to_owned()));
        headers.push(("MCP-Protocol-Version".into(), PROTOCOL.into()));
    }
    headers.extend(
        extra
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned())),
    );
    ProbeRequest {
        id: id.to_owned(),
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body: body.map(String::into_bytes),
    }
}

/// A JSON-RPC result in the answer, plain or as a server-sent event.
fn answered(r: &Option<ProbeResponse>) -> bool {
    r.as_ref()
        .is_some_and(|r| (200..300).contains(&r.status) && r.body.contains("\"result\""))
}

pub fn run(http: &mut dyn Http, section: &McpServerSection) -> Outcome {
    let mut out = Outcome::default();
    let path = section.path.as_str();
    let say = |ids: &str, why: String, out: &mut Outcome| {
        out.not_assessed.push((ids.to_owned(), why));
    };
    if !path.starts_with('/') {
        say(
            "C10.3.3, C10.2.6",
            format!("[stack.run.mcp-server] path must begin with `/`; it is `{path}`."),
            &mut out,
        );
        return out;
    }

    // The control: a session started as any client starts one.
    let first = http.send(&request(
        "mcp-initialize",
        "POST",
        path,
        Some(rpc(1, "initialize")),
        None,
        &[],
    ));
    out.steps.push(format!(
        "started an MCP session at {path} ({})",
        status(&first)
    ));
    if !answered(&first) {
        say(
            "C10.3.3, C10.2.6",
            format!(
                "The MCP endpoint at {path} did not start a session for an ordinary request ({}), \
                 so a refusal of the others would show nothing. If it needs a token, that is not \
                 something the run can give it yet.",
                status(&first)
            ),
            &mut out,
        );
        return out;
    }
    let session = first
        .as_ref()
        .and_then(|r| r.header("mcp-session-id"))
        .map(str::to_owned);
    if let Some(session) = &session {
        let _ = http.send(&request(
            "mcp-initialized",
            "POST",
            path,
            Some(
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
                    .to_string(),
            ),
            Some(session),
            &[],
        ));
    }

    // C10.3.3: a foreign Origin, then a foreign Host, each on its own.
    let from_page = http.send(&request(
        "mcp-foreign-origin",
        "POST",
        path,
        Some(rpc(2, "initialize")),
        None,
        &[("Origin", STRANGER)],
    ));
    let rebound = http.send(&request(
        "mcp-foreign-host",
        "POST",
        path,
        Some(rpc(3, "initialize")),
        None,
        &[("Host", REBOUND)],
    ));
    out.steps.push(format!(
        "asked it again with the Origin {STRANGER} ({}) and under the Host {REBOUND} ({})",
        status(&from_page),
        status(&rebound)
    ));
    let mut unchecked = Vec::new();
    if answered(&from_page) {
        unchecked.push(format!("with `Origin: {STRANGER}`"));
    }
    if answered(&rebound) {
        unchecked.push(format!("with `Host: {REBOUND}`"));
    }
    if !unchecked.is_empty() {
        out.findings.push(finding(
            &WHERE_FROM,
            "The MCP server answers requests from a foreign web page or name",
            Severity::High,
            format!(
                "The MCP endpoint at {path} started a session for a request {}, as it did for an \
                 ordinary one. In the fenced run nothing stood in front of the app, so this is the \
                 app's own check; a proxy in production might also refuse them.",
                unchecked.join(" and for one ")
            ),
        ));
    } else if from_page.is_some() && rebound.is_some() {
        out.verified.push(crate::Verified::new(
            WHERE_FROM.rule_id,
            WHERE_FROM.requirement_ids,
            format!(
                "the MCP endpoint at {path} refused a request with a foreign `Origin` ({}) and one \
                 with a foreign `Host` ({}), each on its own, where an ordinary request started a \
                 session",
                status(&from_page),
                status(&rebound)
            ),
        ));
    } else {
        say(
            "C10.3.3",
            "Whether the MCP server checks Origin and Host: one of the two requests got no answer \
             at all, which is not a refusal."
                .to_owned(),
            &mut out,
        );
    }

    // C10.2.6: the session ended as the transport says, then used again.
    let Some(session) = session else {
        say(
            "C10.2.6",
            format!(
                "The MCP endpoint at {path} gave no `Mcp-Session-Id`, so it keeps no session a \
                 client could end, and there is nothing of one to ask about."
            ),
            &mut out,
        );
        return out;
    };
    let before = http.send(&request(
        "mcp-list-before",
        "POST",
        path,
        Some(rpc(4, "tools/list")),
        Some(&session),
        &[],
    ));
    let ended = http.send(&request(
        "mcp-delete",
        "DELETE",
        path,
        None,
        Some(&session),
        &[],
    ));
    let after = http.send(&request(
        "mcp-list-after",
        "POST",
        path,
        Some(rpc(5, "tools/list")),
        Some(&session),
        &[],
    ));
    out.steps.push(format!(
        "listed its tools in the session ({}), ended it ({}), and listed them again with the same \
         session ({})",
        status(&before),
        status(&ended),
        status(&after)
    ));
    let ended_status = ended.as_ref().map_or(0, |r| r.status);
    if !answered(&before) {
        say(
            "C10.2.6",
            format!(
                "Whether an ended MCP session stays usable: the session did not list its tools \
                 before it was ended ({}), so a refusal afterwards shows nothing.",
                status(&before)
            ),
            &mut out,
        );
    } else if ended_status == 405 {
        say(
            "C10.2.6",
            "Whether an ended MCP session stays usable: the server does not let clients end a \
             session (405), which the transport allows, so what ending one leaves behind cannot be \
             asked here."
                .to_owned(),
            &mut out,
        );
    } else if !(200..300).contains(&ended_status) {
        say(
            "C10.2.6",
            format!(
                "Whether an ended MCP session stays usable: ending it was refused ({}).",
                status(&ended)
            ),
            &mut out,
        );
    } else if answered(&after) {
        out.findings.push(finding(
            &SESSION_KEPT,
            "An MCP session still works after it was ended",
            Severity::Medium,
            format!(
                "The MCP endpoint at {path} accepted the end of a session ({}) and then listed \
                 its tools for the same `Mcp-Session-Id` ({}).",
                status(&ended),
                status(&after)
            ),
        ));
    } else if after.is_some() {
        out.verified.push(crate::Verified::new(
            SESSION_KEPT.rule_id,
            SESSION_KEPT.requirement_ids,
            format!(
                "an MCP session that listed its tools, ended with DELETE ({}), and refused \
                 afterwards ({}); this is the session ID, and files or caches it left behind were \
                 not visible",
                status(&ended),
                status(&after)
            ),
        ));
    } else {
        say(
            "C10.2.6",
            "Whether an ended MCP session stays usable: the request after it was ended got no \
             answer at all, which is not a refusal."
                .to_owned(),
            &mut out,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// What the fake MCP server gets wrong, one switch each.
    #[derive(Default, Clone, Copy)]
    struct Flaws {
        origin_unchecked: bool,
        host_unchecked: bool,
        session_survives: bool,
        stateless: bool,
        no_delete: bool,
        needs_token: bool,
        /// Answers with server-sent events rather than plain JSON.
        streams: bool,
    }

    #[derive(Default)]
    struct FakeMcp {
        flaws: Flaws,
        sessions: BTreeSet<String>,
        next: u32,
        sent: Vec<ProbeRequest>,
    }

    impl FakeMcp {
        fn header<'a>(r: &'a ProbeRequest, name: &str) -> Option<&'a str> {
            r.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    impl Http for FakeMcp {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.sent.push(r.clone());
            let reply = |status: u16, headers: Vec<(String, String)>, body: String| {
                Some(ProbeResponse {
                    id: r.id.clone(),
                    status,
                    headers,
                    body,
                })
            };
            if r.path != "/mcp" {
                return reply(404, Vec::new(), String::new());
            }
            if self.flaws.needs_token {
                return reply(401, Vec::new(), "{\"error\":\"token\"}".into());
            }
            if Self::header(r, "origin").is_some_and(|o| o != "http://localhost")
                && !self.flaws.origin_unchecked
            {
                return reply(403, Vec::new(), "{\"error\":\"origin\"}".into());
            }
            if Self::header(r, "host").is_some_and(|h| h != "app") && !self.flaws.host_unchecked {
                return reply(421, Vec::new(), "{\"error\":\"host\"}".into());
            }
            let session = Self::header(r, "mcp-session-id").map(str::to_owned);
            if r.method == "DELETE" {
                if self.flaws.no_delete {
                    return reply(405, Vec::new(), String::new());
                }
                if !self.flaws.session_survives
                    && let Some(s) = &session
                {
                    self.sessions.remove(s);
                }
                return reply(200, Vec::new(), String::new());
            }
            let body: serde_json::Value =
                serde_json::from_slice(r.body.as_deref().unwrap_or(b"{}")).unwrap();
            let Some(id) = body.get("id").cloned() else {
                return reply(202, Vec::new(), String::new());
            };
            let method = body["method"].as_str().unwrap_or_default();
            let mut headers = Vec::new();
            if method == "initialize" {
                if !self.flaws.stateless {
                    self.next += 1;
                    let s = format!("sess-{}", self.next);
                    self.sessions.insert(s.clone());
                    headers.push(("mcp-session-id".into(), s));
                }
            } else if !self.flaws.stateless
                && !session.as_ref().is_some_and(|s| self.sessions.contains(s))
            {
                return reply(404, Vec::new(), "{\"error\":\"no such session\"}".into());
            }
            let result = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}});
            let text = if self.flaws.streams {
                format!("event: message\ndata: {result}\n\n")
            } else {
                result.to_string()
            };
            reply(200, headers, text)
        }
    }

    fn ask(flaws: Flaws) -> (Outcome, FakeMcp) {
        let mut server = FakeMcp {
            flaws,
            ..Default::default()
        };
        let out = run(
            &mut server,
            &McpServerSection {
                path: "/mcp".into(),
            },
        );
        (out, server)
    }

    fn found(o: &Outcome) -> Vec<&str> {
        o.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn credited(o: &Outcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    fn why<'o>(o: &'o Outcome, id: &str) -> Vec<&'o str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == id))
            .map(|(_, w)| w.as_str())
            .collect()
    }

    #[test]
    fn a_careful_server_is_credited_for_both() {
        for streams in [false, true] {
            let (o, server) = ask(Flaws {
                streams,
                ..Default::default()
            });
            assert!(found(&o).is_empty(), "{:?}", o.findings);
            assert_eq!(
                credited(&o),
                [WHERE_FROM.rule_id, SESSION_KEPT.rule_id],
                "{:?}",
                o.steps
            );
            // The setup: the foreign Host was sent in place of the app's, and the session id was
            // carried on the requests after the first.
            let rebound = server
                .sent
                .iter()
                .find(|r| r.id == "mcp-foreign-host")
                .unwrap();
            assert_eq!(FakeMcp::header(rebound, "host"), Some(REBOUND));
            let after = server
                .sent
                .iter()
                .find(|r| r.id == "mcp-list-after")
                .unwrap();
            assert_eq!(FakeMcp::header(after, "mcp-session-id"), Some("sess-1"));
        }
    }

    #[test]
    fn each_fault_is_found_by_its_own_rule_and_not_credited() {
        for (flaws, rule, words) in [
            (
                Flaws {
                    origin_unchecked: true,
                    ..Default::default()
                },
                WHERE_FROM.rule_id,
                "`Origin: http://sv-evil.invalid`",
            ),
            (
                Flaws {
                    host_unchecked: true,
                    ..Default::default()
                },
                WHERE_FROM.rule_id,
                "`Host: sv-rebind.invalid`",
            ),
            (
                Flaws {
                    session_survives: true,
                    ..Default::default()
                },
                SESSION_KEPT.rule_id,
                "listed its tools for the same",
            ),
        ] {
            let (o, _) = ask(flaws);
            assert_eq!(found(&o), [rule], "{:?}", o.steps);
            assert!(!credited(&o).contains(&rule));
            assert!(
                o.findings[0].description.contains(words),
                "{}",
                o.findings[0].description
            );
        }
        // Both headers unchecked: one finding naming both.
        let (o, _) = ask(Flaws {
            origin_unchecked: true,
            host_unchecked: true,
            ..Default::default()
        });
        assert_eq!(found(&o), [WHERE_FROM.rule_id]);
        assert!(o.findings[0].description.contains("and for one"));
    }

    #[test]
    fn what_cannot_be_asked_is_said_and_not_credited() {
        let (o, _) = ask(Flaws {
            needs_token: true,
            ..Default::default()
        });
        assert!(found(&o).is_empty() && credited(&o).is_empty());
        assert!(
            why(&o, "C10.3.3")
                .iter()
                .any(|w| w.contains("did not start a session"))
        );
        assert!(!why(&o, "C10.2.6").is_empty());

        let (o, _) = ask(Flaws {
            stateless: true,
            ..Default::default()
        });
        assert_eq!(credited(&o), [WHERE_FROM.rule_id]);
        assert!(
            why(&o, "C10.2.6")
                .iter()
                .any(|w| w.contains("no `Mcp-Session-Id`"))
        );

        let (o, _) = ask(Flaws {
            no_delete: true,
            ..Default::default()
        });
        assert!(!credited(&o).contains(&SESSION_KEPT.rule_id));
        assert!(
            why(&o, "C10.2.6")
                .iter()
                .any(|w| w.contains("does not let clients end"))
        );

        let o = run(
            &mut FakeMcp::default(),
            &McpServerSection { path: "mcp".into() },
        );
        assert!(credited(&o).is_empty() && o.steps.is_empty());
        assert!(
            why(&o, "C10.3.3")
                .iter()
                .any(|w| w.contains("must begin with"))
        );
    }
}
