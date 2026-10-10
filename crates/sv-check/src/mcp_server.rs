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

const TOKEN_UNCHECKED: Rule = Rule {
    rule_id: "probe.mcp-server-token-unchecked",
    requirement_ids: &["C10.2.1"],
    cwe: &["CWE-306", "CWE-287"],
    impact: "Anyone who can reach the MCP server can use its tools, with no token or with one they \
             made up: whatever the tools can do, any AI client on the network can have done.",
    fix: "Check the access token on every request, before anything else, and answer 401 when it is \
          missing or wrong; within a session as well as when one starts.",
};

const PARAMETERS_UNCHECKED: Rule = Rule {
    rule_id: "probe.mcp-server-takes-unknown-or-oversized-arguments",
    requirement_ids: &["C10.4.3"],
    cwe: &["CWE-20"],
    impact: "A tool runs with arguments it never declared, or with one far longer than any real use \
             needs. A model can be talked into writing either, and the tool's code then works on \
             something nobody planned for.",
    fix: "Validate each call against the tool's declared input schema before running it, with \
          `additionalProperties: false` and a `maxLength` on strings, and answer an error for \
          anything else.",
};

const TYPES_UNCHECKED: Rule = Rule {
    rule_id: "probe.mcp-server-takes-wrong-types",
    requirement_ids: &["C10.4.4"],
    cwe: &["CWE-20"],
    impact: "A tool runs with an argument of a type its schema does not allow, so its own code meets \
             a value it was not written for.",
    fix: "Validate each call against the declared schema, types included, before running the tool \
          (the official MCP libraries do when a tool's input is declared with a schema library \
          such as Zod or Pydantic), and answer an error for anything that does not fit.",
};

const NO_SIZE_LIMIT: Rule = Rule {
    rule_id: "probe.mcp-server-no-size-limit",
    requirement_ids: &["C10.4.5"],
    cwe: &["CWE-770"],
    impact: "The MCP endpoint reads and answers a request of several megabytes, far past what a tool \
             call needs, so a few such requests can use up its memory.",
    fix: "Set a maximum request size where the endpoint reads requests (a body-size limit in the web \
          framework or the proxy in front of it), well below a megabyte unless a tool really needs \
          more, and answer 413 above it.",
};

/// How long the over-long argument is, in characters: no real argument to a tool needs a megabyte.
const LONG_ARGUMENT: usize = 1_000_000;
/// How large the very large request is, in bytes: past any tool call, and inside what the run's
/// request path carries (16 MB).
const LARGE_REQUEST: usize = 8_000_000;

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

/// The requirements the run asks, for a reason that stops all of them.
fn asked(section: &McpServerSection) -> String {
    let mut ids = vec!["C10.3.3", "C10.2.6"];
    if section.token_env.is_some() && !section.public {
        ids.push("C10.2.1");
    }
    if section.probe_tool.is_some() {
        ids.extend(["C10.4.3", "C10.4.4", "C10.4.5"]);
    }
    ids.join(", ")
}

/// Sends every request with the run's token, unless the request carries its own `Authorization`
/// header: a made-up token is sent as it is, and an empty one means none at all.
struct Authed<'a> {
    inner: &'a mut dyn Http,
    bearer: Option<String>,
}

impl Http for Authed<'_> {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        let mut request = request.clone();
        let own = request
            .headers
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case("authorization"));
        match (own, &self.bearer) {
            (Some(at), _) if request.headers[at].1.is_empty() => {
                request.headers.remove(at);
            }
            (Some(_), _) | (None, None) => {}
            (None, Some(bearer)) => request
                .headers
                .push(("Authorization".into(), bearer.clone())),
        }
        self.inner.send(&request)
    }
}

/// What an answer to a call came to.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// A JSON-RPC result that is not a tool's error: the request was taken.
    Took,
    /// An HTTP error below 500, a JSON-RPC error, or a tool's own `isError`.
    Refused,
    /// No answer, or a server error: not an answer to the question.
    NoAnswer,
}

fn verdict(r: &Option<ProbeResponse>) -> Verdict {
    // A server error is not an answer, and neither is a rate limiter's (429, or 503 with
    // `Retry-After`): a refusal it gave is the limiter's, not the server's own check (ADR-021; the
    // review of 1 to 4 October, item 4). One rule, `answer_of`, since 8 October 2026.
    let Some(r) = crate::signed_in::answer_of(r.as_ref()).answered() else {
        return Verdict::NoAnswer;
    };
    let squeezed: String = r.body.chars().filter(|c| !c.is_whitespace()).collect();
    let tool_error = squeezed.contains("\"isError\":true");
    if (200..300).contains(&r.status) && squeezed.contains("\"result\"") && !tool_error {
        Verdict::Took
    } else if r.status >= 400 || squeezed.contains("\"error\"") || tool_error {
        Verdict::Refused
    } else {
        Verdict::NoAnswer
    }
}

/// A value made for this run, so nothing an earlier run sent can stand in for it.
fn nonce() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}", now ^ (u128::from(std::process::id()) << 64))
}

/// C10.2.1: no token, a made-up one, and none inside a session the run's token started. The control
/// is the session itself, and the tools listed in it with the token.
fn token_checks(
    http: &mut dyn Http,
    section: &McpServerSection,
    path: &str,
    session: Option<&str>,
    out: &mut Outcome,
) {
    let say = |why: String, out: &mut Outcome| out.not_assessed.push(("C10.2.1".to_owned(), why));
    if section.public {
        say(
            "Whether the MCP server checks an access token: stackvet.toml says it is meant to \
             answer anyone, so it was not asked."
                .to_owned(),
            out,
        );
        return;
    }
    if let Some(name) = section
        .token_env
        .as_deref()
        .filter(|n| !sv_manifest::is_variable_name(n))
    {
        say(
            format!(
                "Whether the MCP server checks an access token: `token-env` is `{name}`, which is \
                 not an environment variable name (letters, digits, and `_`), so no token was given \
                 to the app."
            ),
            out,
        );
        return;
    }
    if section.token_env.is_none() {
        say(
            "Whether the MCP server checks an access token: if it takes one fixed token, name the \
             variable it reads it from as `token-env` under [stack.run.mcp-server]; if it is meant \
             to answer anyone, say `public = true`."
                .to_owned(),
            out,
        );
        return;
    }
    let with = |mut r: ProbeRequest, auth: &str| {
        r.headers.push(("Authorization".into(), auth.to_owned()));
        r
    };
    let made_up = format!("Bearer sv-made-up-{}", nonce());
    let none = http.send(&with(
        request(
            "mcp-no-token",
            "POST",
            path,
            Some(rpc(10, "initialize")),
            None,
            &[],
        ),
        "",
    ));
    let wrong = http.send(&with(
        request(
            "mcp-made-up-token",
            "POST",
            path,
            Some(rpc(11, "initialize")),
            None,
            &[],
        ),
        &made_up,
    ));
    let listed = session.map(|s| {
        http.send(&request(
            "mcp-list-with-token",
            "POST",
            path,
            Some(rpc(12, "tools/list")),
            Some(s),
            &[],
        ))
    });
    let bare = session.map(|s| {
        http.send(&with(
            request(
                "mcp-list-no-token",
                "POST",
                path,
                Some(rpc(13, "tools/list")),
                Some(s),
                &[],
            ),
            "",
        ))
    });
    out.steps.push(format!(
        "asked the MCP endpoint at {path} with no token ({}) and with a made-up one ({}){}",
        status(&none),
        status(&wrong),
        match &bare {
            Some(b) => format!(
                ", and for its tools with no token inside a session ({})",
                status(b)
            ),
            None => String::new(),
        }
    ));
    let mut took = Vec::new();
    let mut answers = vec![verdict(&none), verdict(&wrong)];
    if verdict(&none) == Verdict::Took {
        took.push("a request with no token started a session");
    }
    if verdict(&wrong) == Verdict::Took {
        took.push("a request with a made-up token started a session");
    }
    if let (Some(listed), Some(bare)) = (&listed, &bare)
        && verdict(listed) == Verdict::Took
    {
        answers.push(verdict(bare));
        if verdict(bare) == Verdict::Took {
            took.push("a request with no token inside a session listed its tools");
        }
    }
    if !took.is_empty() {
        out.findings.push(finding(
            &TOKEN_UNCHECKED,
            "The MCP server answers without its access token",
            Severity::High,
            format!(
                "At {path}, {}, where the server was given its own token to check.",
                took.join("; ")
            ),
        ));
    } else if answers.iter().all(|v| *v == Verdict::Refused) {
        out.verified.push(crate::Verified::new(
            TOKEN_UNCHECKED.rule_id,
            TOKEN_UNCHECKED.requirement_ids,
            format!(
                "the MCP endpoint at {path} refused a request with no token and one with a made-up \
                 token{}, where the run's own token started a session",
                if answers.len() > 2 {
                    ", and a request with no token inside a session"
                } else {
                    ""
                }
            ),
        )
        // Two or three requests, not each request C10.2.1 names (ADR-053, Later).
        .in_part());
    } else {
        say(
            "Whether the MCP server checks an access token: one of the requests without the run's \
             token got no answer, or an error of the server's own, which is not a refusal."
                .to_owned(),
            out,
        );
    }
}

/// The tool named as `probe-tool`, called with `arguments`, and with `params` added beside them.
fn call(
    id: &str,
    n: u32,
    tool: &str,
    arguments: serde_json::Value,
    extra: Option<(&str, serde_json::Value)>,
    path: &str,
    session: Option<&str>,
) -> ProbeRequest {
    let mut params = serde_json::json!({"name": tool, "arguments": arguments});
    if let Some((k, v)) = extra {
        params[k] = v;
    }
    let body =
        serde_json::json!({"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": params});
    request(id, "POST", path, Some(body.to_string()), session, &[])
}

/// C10.4.3, C10.4.4, and C10.4.5, with the owner's safe tool: called as it should be (the control),
/// with an argument it never declared, with one a megabyte long, with one of a type its schema does
/// not allow, and, last, inside a request of eight megabytes.
fn tool_checks(
    http: &mut dyn Http,
    section: &McpServerSection,
    path: &str,
    session: Option<&str>,
    out: &mut Outcome,
) {
    let say = |ids: &str, why: String, out: &mut Outcome| {
        out.not_assessed.push((ids.to_owned(), why));
    };
    let Some(tool) = &section.probe_tool else {
        say(
            "C10.4.3, C10.4.4, C10.4.5",
            "What the MCP server does with arguments it should refuse: name a tool that is safe to \
             call again and again, with arguments it accepts, as `probe-tool` under \
             [stack.run.mcp-server]."
                .to_owned(),
            out,
        );
        return;
    };
    let valid: serde_json::Map<String, serde_json::Value> = tool
        .args
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    let control = http.send(&call(
        "mcp-tool-control",
        20,
        &tool.name,
        valid.clone().into(),
        None,
        path,
        session,
    ));
    out.steps.push(format!(
        "called its tool `{}` with the arguments stackvet.toml gives ({})",
        tool.name,
        status(&control)
    ));
    if verdict(&control) != Verdict::Took {
        say(
            "C10.4.3, C10.4.4, C10.4.5",
            format!(
                "What the MCP server does with arguments it should refuse: its tool `{}`, called \
                 with the arguments stackvet.toml gives, did not answer with a result ({}), so a \
                 refusal of anything else would show nothing.",
                tool.name,
                status(&control)
            ),
            out,
        );
        return;
    }

    // C10.4.3: an argument it never declared, and one far longer than any real one.
    let mut unknown = valid.clone();
    unknown.insert(format!("sv_unknown_{}", nonce()), "x".into());
    let unknown_answer = http.send(&call(
        "mcp-tool-unknown-argument",
        21,
        &tool.name,
        unknown.into(),
        None,
        path,
        session,
    ));
    let long_answer = valid.keys().next().map(|first| {
        let mut long = valid.clone();
        long.insert(first.clone(), "a".repeat(LONG_ARGUMENT).into());
        http.send(&call(
            "mcp-tool-long-argument",
            22,
            &tool.name,
            long.into(),
            None,
            path,
            session,
        ))
    });
    out.steps.push(format!(
        "called it with an argument it never declared ({}){}",
        status(&unknown_answer),
        match &long_answer {
            Some(a) => format!(
                " and with one {LONG_ARGUMENT} characters long ({})",
                status(a)
            ),
            None => String::new(),
        }
    ));
    let mut took = Vec::new();
    if verdict(&unknown_answer) == Verdict::Took {
        took.push("an argument it never declared".to_owned());
    }
    if long_answer
        .as_ref()
        .is_some_and(|a| verdict(a) == Verdict::Took)
    {
        took.push(format!("an argument {LONG_ARGUMENT} characters long"));
    }
    let refused = verdict(&unknown_answer) == Verdict::Refused
        && long_answer
            .as_ref()
            .is_some_and(|a| verdict(a) == Verdict::Refused);
    if !took.is_empty() {
        out.findings.push(finding(
            &PARAMETERS_UNCHECKED,
            "An MCP tool runs with arguments it should refuse",
            Severity::Medium,
            format!(
                "The tool `{}` at {path} answered with a result for {}, as it did for the \
                 arguments it declares. Some libraries drop unknown arguments without saying so, \
                 which is safer than using them but is still not refusing them.",
                tool.name,
                took.join(" and for ")
            ),
        ));
    } else if refused {
        out.verified.push(crate::Verified::new(
            PARAMETERS_UNCHECKED.rule_id,
            PARAMETERS_UNCHECKED.requirement_ids,
            format!(
                "the MCP tool `{}` refused an argument it never declared and one {LONG_ARGUMENT} \
                 characters long, where the same tool answered its declared arguments; one tool",
                tool.name
            ),
        )
        // One tool stands for no other the server offers (ADR-053, Later).
        .in_part());
    } else {
        say(
            "C10.4.3",
            format!(
                "What the tool `{}` does with an unknown or over-long argument: {}.",
                tool.name,
                if long_answer.is_none() {
                    "stackvet.toml gives it no argument to make long, and an unknown one alone is \
                     not all of the question"
                        .to_owned()
                } else {
                    "one of the calls got no answer, or an error of the server's own, which is not \
                     a refusal"
                        .to_owned()
                }
            ),
            out,
        );
    }

    // C10.4.4: a value no schema could read as a string, where the schema declares a string.
    let listed = http.send(&request(
        "mcp-tool-schema",
        "POST",
        path,
        Some(rpc(23, "tools/list")),
        session,
        &[],
    ));
    let declared_string = listed.as_ref().and_then(|r| {
        let text = r.body.trim();
        let json = text
            .lines()
            .find_map(|l| l.strip_prefix("data:"))
            .unwrap_or(text);
        let value: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
        let tools = value["result"]["tools"].as_array()?;
        let schema = &tools.iter().find(|t| t["name"] == tool.name.as_str())?["inputSchema"];
        valid
            .keys()
            .find(|k| schema["properties"][k.as_str()]["type"] == "string")
            .cloned()
    });
    match declared_string {
        None => say(
            "C10.4.4",
            format!(
                "Whether the tool `{}` refuses a value of the wrong type: its listed schema declares \
                 none of the arguments stackvet.toml gives as a string, so there was no type to \
                 get wrong on purpose.",
                tool.name
            ),
            out,
        ),
        Some(name) => {
            let mut wrong = valid.clone();
            wrong.insert(name.clone(), serde_json::json!({"sv": [1, 2]}));
            let answer = http.send(&call(
                "mcp-tool-wrong-type",
                24,
                &tool.name,
                wrong.into(),
                None,
                path,
                session,
            ));
            out.steps.push(format!(
                "called it with an object where `{name}` is declared a string ({})",
                status(&answer)
            ));
            match verdict(&answer) {
                Verdict::Took => out.findings.push(finding(
                    &TYPES_UNCHECKED,
                    "An MCP tool runs with an argument of the wrong type",
                    Severity::Medium,
                    format!(
                        "The tool `{}` at {path} answered with a result when `{name}`, declared a \
                         string, was sent an object.",
                        tool.name
                    ),
                )),
                Verdict::Refused => out.verified.push(crate::Verified::new(
                    TYPES_UNCHECKED.rule_id,
                    TYPES_UNCHECKED.requirement_ids,
                    format!(
                        "the MCP tool `{}` refused an object where its schema declares `{name}` a \
                         string; one tool, one argument",
                        tool.name
                    ),
                )
                // One argument of one tool stands for no other schema (ADR-053, Later).
                .in_part()),
                Verdict::NoAnswer => say(
                    "C10.4.4",
                    format!(
                        "Whether the tool `{}` refuses a value of the wrong type: the call got no \
                         answer, or an error of the server's own, which is not a refusal.",
                        tool.name
                    ),
                    out,
                ),
            }
        }
    }

    // C10.4.5, last, since a server with no limit may not survive it: the control call inside a
    // request of eight megabytes. Only ever a finding: the requirement names no size.
    let large = http.send(&call(
        "mcp-large-request",
        25,
        &tool.name,
        valid.into(),
        Some(("sv_padding", "x".repeat(LARGE_REQUEST).into())),
        path,
        session,
    ));
    out.steps.push(format!(
        "sent it a request of {LARGE_REQUEST} bytes ({})",
        status(&large)
    ));
    match verdict(&large) {
        Verdict::Took => out.findings.push(finding(
            &NO_SIZE_LIMIT,
            "The MCP endpoint takes a request of several megabytes",
            Severity::Medium,
            format!(
                "The MCP endpoint at {path} read a request of {LARGE_REQUEST} bytes and answered it \
                 with a result."
            ),
        )),
        Verdict::Refused => say(
            "C10.4.5",
            format!(
                "The MCP endpoint at {path} refused a request of {LARGE_REQUEST} bytes ({}). The \
                 requirement names no size, and this is one size, so it is said and not credited.",
                status(&large)
            ),
            out,
        ),
        Verdict::NoAnswer => say(
            "C10.4.5",
            format!(
                "Whether the MCP endpoint limits the size of a request: a request of \
                 {LARGE_REQUEST} bytes got no answer, or an error of the server's own ({}), which \
                 is not a limit.",
                status(&large)
            ),
            out,
        ),
    }
}

/// A JSON-RPC result in the answer, plain or as a server-sent event.
fn answered(r: &Option<ProbeResponse>) -> bool {
    r.as_ref()
        .is_some_and(|r| (200..300).contains(&r.status) && r.body.contains("\"result\""))
}

/// Asks the app's MCP endpoint. `token` is the access token the run gave the app in
/// `token-env`, sent with every request unless a request says otherwise; never written anywhere.
pub fn run(http: &mut dyn Http, section: &McpServerSection, token: Option<&str>) -> Outcome {
    let mut authed = Authed {
        inner: http,
        bearer: token.map(|t| format!("Bearer {t}")),
    };
    let http: &mut dyn Http = &mut authed;
    let mut out = Outcome::default();
    let path = section.path.as_str();
    let all = asked(section);
    let say = |ids: &str, why: String, out: &mut Outcome| {
        out.not_assessed.push((ids.to_owned(), why));
    };
    if !path.starts_with('/') {
        say(
            &all,
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
            &all,
            format!(
                "The MCP endpoint at {path} did not start a session for an ordinary request ({}), \
                 so a refusal of the others would show nothing. If it takes one fixed access \
                 token, name the variable it reads it from as `token-env` under \
                 [stack.run.mcp-server]; a token from a sign-in service cannot be given to it yet.",
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

    token_checks(http, section, path, session.as_deref(), &mut out);
    where_from_and_session_end(http, path, session.clone(), &mut out);
    // The session above was ended on purpose (C10.2.6), so the tool questions start their own.
    if section.probe_tool.is_some() {
        let tools_session = start_session(http, path, "mcp-tools-initialize", 19);
        tool_checks(http, section, path, tools_session.as_deref(), &mut out);
    } else {
        tool_checks(http, section, path, None, &mut out);
    }
    out
}

/// Starts a session as any client does, and says it is ready. The session's ID, when the server
/// gives one; a server that keeps none is asked without.
fn start_session(http: &mut dyn Http, path: &str, id: &str, n: u32) -> Option<String> {
    let first = http.send(&request(
        id,
        "POST",
        path,
        Some(rpc(n, "initialize")),
        None,
        &[],
    ));
    let session = first
        .as_ref()
        .and_then(|r| r.header("mcp-session-id"))
        .map(str::to_owned);
    if let Some(session) = &session {
        let _ = http.send(&request(
            &format!("{id}-done"),
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
    session
}

/// C10.3.3 and C10.2.6, asked after the control session started.
fn where_from_and_session_end(
    http: &mut dyn Http,
    path: &str,
    session: Option<String>,
    out: &mut Outcome,
) {
    let say = |ids: &str, why: String, out: &mut Outcome| {
        out.not_assessed.push((ids.to_owned(), why));
    };
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
    } else if verdict(&from_page) != Verdict::Refused || verdict(&rebound) != Verdict::Refused {
        say(
            "C10.3.3",
            format!(
                "Whether the MCP server checks Origin and Host: the requests with a foreign one \
                 were answered {} and {}, and a crash or a rate limit is not a refusal.",
                status(&from_page),
                status(&rebound)
            ),
            out,
        );
    } else if !answered(&http.send(&request(
        "mcp-ordinary-again",
        "POST",
        path,
        Some(rpc(6, "initialize")),
        None,
        &[],
    ))) {
        // The control: an ordinary request, sent just after the two, still starts a session.
        // A server that refuses every `initialize` after its first (one session for its life) refuses
        // the foreign ones for that, not for where they came from (the review of 1 to 4 October,
        // item 4).
        say(
            "C10.3.3",
            "Whether the MCP server checks Origin and Host: an ordinary request sent just after \
             the two was refused as well, so their refusal shows nothing about Origin or Host."
                .to_owned(),
            out,
        );
    } else {
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
        )
        // One request with each foreign header, to one endpoint (ADR-053, Later).
        .in_part());
    }

    // C10.2.6: the session ended as the transport says, then used again.
    let Some(session) = session else {
        say(
            "C10.2.6",
            format!(
                "The MCP endpoint at {path} gave no `Mcp-Session-Id`, so it keeps no session a \
                 client could end, and there is nothing of one to ask about."
            ),
            out,
        );
        return;
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
            out,
        );
    } else if ended_status == 405 {
        say(
            "C10.2.6",
            "Whether an ended MCP session stays usable: the server does not let clients end a \
             session (405), which the transport allows, so what ending one leaves behind cannot be \
             asked here."
                .to_owned(),
            out,
        );
    } else if !(200..300).contains(&ended_status) {
        say(
            "C10.2.6",
            format!(
                "Whether an ended MCP session stays usable: ending it was refused ({}).",
                status(&ended)
            ),
            out,
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
    } else if verdict(&after) == Verdict::Refused {
        out.verified.push(
            crate::Verified::new(
                SESSION_KEPT.rule_id,
                SESSION_KEPT.requirement_ids,
                format!(
                    "an MCP session that listed its tools, ended with DELETE ({}), and refused \
                 afterwards ({}); this is the session ID, and files or caches it left behind were \
                 not visible",
                    status(&ended),
                    status(&after)
                ),
            )
            // One session's ID, not every artifact a session leaves (ADR-053, Later).
            .in_part(),
        );
    } else {
        say(
            "C10.2.6",
            "Whether an ended MCP session stays usable: the request after it was ended got no \
             answer, a server error, or a rate limit, none of which is a refusal."
                .to_owned(),
            out,
        );
    }
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
        /// Given a token, answers whatever token a request carries, or none.
        token_unchecked: bool,
        /// Given a token, checks it only when a session starts.
        token_at_start_only: bool,
        /// Its tool takes arguments it never declared.
        unknown_arguments_ok: bool,
        /// Its tool takes a string past its declared `maxLength`.
        long_arguments_ok: bool,
        /// Its tool takes a value of the wrong type.
        wrong_types_ok: bool,
        /// It reads a request of any size.
        no_size_limit: bool,
        /// Its tool fails with a server error whatever it is sent.
        tool_broken: bool,
        /// Its tool fails with a server error on an argument it should refuse, rather than refusing.
        crashes_on_bad_arguments: bool,
        /// Its tool refuses a bad argument as a tool error (`isError: true`), not a JSON-RPC error.
        /// Not a fault.
        refuses_in_result: bool,
        /// Keeps one session for its life: every `initialize` after the first is answered 400,
        /// whatever its headers.
        one_session_only: bool,
    }

    /// The largest request the careful fake reads, past the long argument and short of the large
    /// request.
    const FAKE_LIMIT: usize = 2_000_000;

    #[derive(Default)]
    struct FakeMcp {
        flaws: Flaws,
        /// The token it was given, as the app would read it from `token-env`.
        token: Option<String>,
        sessions: BTreeSet<String>,
        next: u32,
        sent: Vec<ProbeRequest>,
        /// Requests answered with this status whatever they ask, by id: a crash or a limiter.
        forced: Vec<(&'static str, u16)>,
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
            if let Some((_, status)) = self.forced.iter().find(|(id, _)| *id == r.id) {
                return reply(*status, Vec::new(), "{\"error\":\"forced\"}".into());
            }
            if r.path != "/mcp" {
                return reply(404, Vec::new(), String::new());
            }
            if self.flaws.needs_token {
                return reply(401, Vec::new(), "{\"error\":\"token\"}".into());
            }
            if r.body.as_ref().is_some_and(|b| b.len() > FAKE_LIMIT) && !self.flaws.no_size_limit {
                return reply(413, Vec::new(), "{\"error\":\"too large\"}".into());
            }
            if let Some(token) = &self.token {
                let carried = Self::header(r, "authorization") == Some(&format!("Bearer {token}"));
                let starting = r.body_text().contains("\"initialize\"");
                let checked =
                    !self.flaws.token_unchecked && (starting || !self.flaws.token_at_start_only);
                if checked && !carried {
                    return reply(401, Vec::new(), "{\"error\":\"token\"}".into());
                }
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
                if self.flaws.one_session_only && self.next > 0 {
                    return reply(
                        400,
                        Vec::new(),
                        "{\"error\":\"already initialized\"}".into(),
                    );
                }
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
            let tool = serde_json::json!({
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string", "maxLength": 1000}},
                    "required": ["text"],
                    "additionalProperties": false,
                },
            });
            let result = if method == "tools/call" {
                if self.flaws.tool_broken {
                    return reply(500, Vec::new(), "Internal Server Error".into());
                }
                let args = &body["params"]["arguments"];
                let fault = if args
                    .as_object()
                    .is_some_and(|a| a.keys().any(|k| k != "text"))
                    && !self.flaws.unknown_arguments_ok
                {
                    Some("unknown argument")
                } else if !args["text"].is_string() && !self.flaws.wrong_types_ok {
                    Some("text must be a string")
                } else if args["text"].as_str().is_some_and(|t| t.len() > 1000)
                    && !self.flaws.long_arguments_ok
                {
                    Some("text is too long")
                } else {
                    None
                };
                match fault {
                    Some(_) if self.flaws.crashes_on_bad_arguments => {
                        return reply(500, Vec::new(), "Internal Server Error".into());
                    }
                    Some(why) if self.flaws.refuses_in_result => serde_json::json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {"content": [{"type": "text", "text": why}], "isError": true}}),
                    Some(why) => serde_json::json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": -32602, "message": why}}),
                    None => serde_json::json!({"jsonrpc": "2.0", "id": id,
                        "result": {"content": [{"type": "text", "text": "ok"}], "isError": false}}),
                }
            } else {
                serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [tool]}})
            };
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
                ..Default::default()
            },
            None,
        );
        (out, server)
    }

    /// A run where the server takes the run's token and the owner names its safe tool.
    fn ask_all(flaws: Flaws) -> (Outcome, FakeMcp) {
        let token = "sv-test-token-1".to_owned();
        let mut server = FakeMcp {
            flaws,
            token: Some(token.clone()),
            ..Default::default()
        };
        let out = run(
            &mut server,
            &McpServerSection {
                path: "/mcp".into(),
                token_env: Some("MCP_TOKEN".into()),
                public: false,
                probe_tool: Some(sv_manifest::RecordTool {
                    name: "echo".into(),
                    args: [("text".to_owned(), "hello".to_owned())].into(),
                    read_only: false,
                }),
            },
            Some(&token),
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
            // One request with each foreign header, and one session (ADR-053, Later).
            assert!(o.verified.iter().all(|v| v.in_part), "{:?}", o.verified);
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
            &McpServerSection {
                path: "mcp".into(),
                ..Default::default()
            },
            None,
        );
        assert!(credited(&o).is_empty() && o.steps.is_empty());
        assert!(
            why(&o, "C10.3.3")
                .iter()
                .any(|w| w.contains("must begin with"))
        );
    }

    #[test]
    fn a_careful_server_is_credited_for_its_token_and_its_tools() {
        let (o, server) = ask_all(Flaws::default());
        assert!(found(&o).is_empty(), "{:?} {:?}", o.findings, o.steps);
        for rule in [&TOKEN_UNCHECKED, &PARAMETERS_UNCHECKED, &TYPES_UNCHECKED] {
            assert!(
                credited(&o).contains(&rule.rule_id),
                "{} {:?}",
                rule.rule_id,
                o.steps
            );
            // A few requests, one tool, one argument (ADR-053, Later).
            assert!(
                o.verified
                    .iter()
                    .all(|v| v.check_id != rule.rule_id || v.in_part),
                "{}",
                rule.rule_id
            );
        }
        // C10.4.5 is only ever a finding: a refusal is said.
        assert!(!credited(&o).contains(&NO_SIZE_LIMIT.rule_id));
        assert!(
            why(&o, "C10.4.5")
                .iter()
                .any(|w| w.contains("said and not credited"))
        );
        // The setup: the large request really was sent, and was the last.
        let last = server.sent.last().unwrap();
        assert_eq!(last.id, "mcp-large-request");
        assert!(last.body.as_ref().unwrap().len() > LARGE_REQUEST);
        // And the run's token went with every request but those meant to go without it.
        for r in &server.sent {
            let auth = FakeMcp::header(r, "authorization");
            match r.id.as_str() {
                "mcp-no-token" | "mcp-list-no-token" => assert_eq!(auth, None, "{}", r.id),
                "mcp-made-up-token" => assert!(auth.is_some_and(|a| a.contains("sv-made-up-"))),
                _ => assert_eq!(auth, Some("Bearer sv-test-token-1"), "{}", r.id),
            }
        }
    }

    #[test]
    fn a_server_that_answers_without_its_token_is_found() {
        for flaw in [
            Flaws {
                token_unchecked: true,
                ..Default::default()
            },
            Flaws {
                token_at_start_only: true,
                ..Default::default()
            },
        ] {
            let (o, _) = ask_all(flaw);
            assert!(
                found(&o).contains(&TOKEN_UNCHECKED.rule_id),
                "{:?}",
                o.steps
            );
            assert!(!credited(&o).contains(&TOKEN_UNCHECKED.rule_id));
        }
        // Checked only when a session starts: what is found is the request inside one.
        let (o, _) = ask_all(Flaws {
            token_at_start_only: true,
            ..Default::default()
        });
        let f = o
            .findings
            .iter()
            .find(|f| f.rule_id == TOKEN_UNCHECKED.rule_id)
            .unwrap();
        assert!(
            f.description.contains("inside a session"),
            "{}",
            f.description
        );
        assert!(
            !f.description.contains("no token started"),
            "{}",
            f.description
        );
    }

    #[test]
    fn a_tool_that_takes_what_it_should_refuse_is_found_for_each() {
        let cases: [(Flaws, &Rule, &str); 4] = [
            (
                Flaws {
                    unknown_arguments_ok: true,
                    ..Default::default()
                },
                &PARAMETERS_UNCHECKED,
                "never declared",
            ),
            (
                Flaws {
                    long_arguments_ok: true,
                    ..Default::default()
                },
                &PARAMETERS_UNCHECKED,
                "characters long",
            ),
            (
                Flaws {
                    wrong_types_ok: true,
                    ..Default::default()
                },
                &TYPES_UNCHECKED,
                "sent an object",
            ),
            (
                Flaws {
                    no_size_limit: true,
                    ..Default::default()
                },
                &NO_SIZE_LIMIT,
                "bytes and answered",
            ),
        ];
        for (flaw, rule, words) in cases {
            let (o, _) = ask_all(flaw);
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == rule.rule_id)
                .unwrap_or_else(|| panic!("{} not found: {:?}", rule.rule_id, o.steps));
            assert!(f.description.contains(words), "{}", f.description);
            assert!(!credited(&o).contains(&rule.rule_id));
        }
    }

    #[test]
    fn a_tool_that_fails_or_is_not_named_settles_nothing() {
        // Broken whatever it is sent: the control fails, and nothing is said either way.
        let (o, _) = ask_all(Flaws {
            tool_broken: true,
            ..Default::default()
        });
        for rule in [&PARAMETERS_UNCHECKED, &TYPES_UNCHECKED, &NO_SIZE_LIMIT] {
            assert!(!found(&o).contains(&rule.rule_id));
            assert!(!credited(&o).contains(&rule.rule_id));
        }
        assert!(
            why(&o, "C10.4.3")
                .iter()
                .any(|w| w.contains("did not answer with a result"))
        );
        // Not named, nor a token: the owner is told what to say.
        let (o, _) = ask(Flaws::default());
        assert!(why(&o, "C10.4.4").iter().any(|w| w.contains("probe-tool")));
        assert!(why(&o, "C10.2.1").iter().any(|w| w.contains("token-env")));
        assert!(!credited(&o).contains(&TOKEN_UNCHECKED.rule_id));
    }

    #[test]
    fn a_server_meant_for_anyone_is_not_asked_for_a_token() {
        // Said to be public, even with a token named beside it, and answering anyone: not asked,
        // not found, and the reason given is the owner's word.
        let mut server = FakeMcp {
            flaws: Flaws {
                token_unchecked: true,
                ..Default::default()
            },
            token: Some("t".into()),
            ..Default::default()
        };
        let o = run(
            &mut server,
            &McpServerSection {
                path: "/mcp".into(),
                public: true,
                token_env: Some("MCP_TOKEN".into()),
                ..Default::default()
            },
            Some("t"),
        );
        assert!(
            !found(&o).contains(&TOKEN_UNCHECKED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            why(&o, "C10.2.1")
                .iter()
                .any(|w| w.contains("stackvet.toml says it is meant to answer anyone")),
            "{:?}",
            o.not_assessed
        );
        assert!(!server.sent.iter().any(|r| r.id.starts_with("mcp-no-token")));
    }

    #[test]
    fn a_tool_error_is_a_refusal_and_a_crash_is_not() {
        // Refused as the tool's own error, `isError: true`: credited, as a JSON-RPC error is.
        let (o, _) = ask_all(Flaws {
            refuses_in_result: true,
            ..Default::default()
        });
        assert!(
            credited(&o).contains(&PARAMETERS_UNCHECKED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            credited(&o).contains(&TYPES_UNCHECKED.rule_id),
            "{:?}",
            o.steps
        );
        // A crash on each bad argument: neither found nor credited, and said.
        let (o, _) = ask_all(Flaws {
            crashes_on_bad_arguments: true,
            ..Default::default()
        });
        for rule in [&PARAMETERS_UNCHECKED, &TYPES_UNCHECKED] {
            assert!(!found(&o).contains(&rule.rule_id), "{:?}", o.steps);
            assert!(
                !credited(&o).contains(&rule.rule_id),
                "{} {:?}",
                rule.rule_id,
                o.steps
            );
        }
        assert!(
            why(&o, "C10.4.3")
                .iter()
                .any(|w| w.contains("not a refusal"))
        );
        assert!(
            why(&o, "C10.4.4")
                .iter()
                .any(|w| w.contains("not a refusal"))
        );
    }

    fn ask_forced(flaws: Flaws, forced: Vec<(&'static str, u16)>) -> Outcome {
        let mut server = FakeMcp {
            flaws,
            forced,
            ..Default::default()
        };
        run(
            &mut server,
            &McpServerSection {
                path: "/mcp".into(),
                ..Default::default()
            },
            None,
        )
    }

    #[test]
    fn a_crash_or_a_limit_is_not_a_refusal_of_where_a_request_came_from_or_of_an_ended_session() {
        // The review of 1 to 4 October, item 4. The control: a careful server is credited for both.
        let o = ask_forced(Flaws::default(), Vec::new());
        assert!(credited(&o).contains(&WHERE_FROM.rule_id), "{:?}", o.steps);
        assert!(
            credited(&o).contains(&SESSION_KEPT.rule_id),
            "{:?}",
            o.steps
        );
        for status in [500, 429] {
            let o = ask_forced(
                Flaws {
                    origin_unchecked: true,
                    host_unchecked: true,
                    session_survives: true,
                    ..Default::default()
                },
                vec![
                    ("mcp-foreign-origin", status),
                    ("mcp-foreign-host", status),
                    ("mcp-list-after", status),
                ],
            );
            assert!(
                !credited(&o).contains(&WHERE_FROM.rule_id),
                "{status} {:?}",
                o.steps
            );
            assert!(
                !credited(&o).contains(&SESSION_KEPT.rule_id),
                "{status} {:?}",
                o.steps
            );
            assert!(!why(&o, "C10.3.3").is_empty(), "{status}: not said");
            assert!(!why(&o, "C10.2.6").is_empty(), "{status}: not said");
        }
    }

    #[test]
    fn a_server_that_refuses_every_second_session_is_not_credited_for_checking_origin() {
        let o = ask_forced(
            Flaws {
                origin_unchecked: true,
                host_unchecked: true,
                one_session_only: true,
                ..Default::default()
            },
            Vec::new(),
        );
        assert!(!credited(&o).contains(&WHERE_FROM.rule_id), "{:?}", o.steps);
        assert!(
            why(&o, "C10.3.3")
                .iter()
                .any(|w| w.contains("ordinary request sent just after")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_limiter_is_not_a_refusal() {
        let limited = Some(ProbeResponse {
            id: "x".into(),
            status: 429,
            headers: Vec::new(),
            body: "{\"error\":\"slow down\"}".into(),
        });
        assert_eq!(verdict(&limited), Verdict::NoAnswer);
    }
}
