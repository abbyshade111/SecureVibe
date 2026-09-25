//! `sv mcp`: the same checks, offered to an AI coding tool over the Model Context Protocol.
//!
//! The CLI is what makes `sv` tool-agnostic; this is what makes the loop tight. An AI coding tool
//! that can call `securevibe_check` mid-conversation can work the findings without the owner leaving
//! the chat, and see what nothing examined before it says anything is done.
//!
//! # What it will and will not do
//!
//! **Only what `sv report` does, and never more of it than the owner would get at a terminal by
//! default.** `securevibe_check` is `assemble_report` — the function `sv report` calls — so what the
//! tool is told is exactly what the written report says. Starting the app (`--run`) and running
//! other people's security tools (`--tools`) are not offered at all: each runs code, and that stays
//! a decision a person makes at a terminal rather than one a model makes in a loop. The result says
//! they were not done, the same way the report does.
//!
//! **Only inside the folder it was started for.** `--root` fixes a folder when the server starts;
//! every path a tool is given is resolved against it and refused if it lands outside, `..` and
//! symlinks included. A model can be talked into asking for `~/.ssh` by text it read somewhere; the
//! answer is that this server cannot see it.
//!
//! **Nothing on stdout but protocol.** The stdio transport is one JSON-RPC message per line, and a
//! stray `println!` in anything called from here would corrupt the stream. `assemble_report`
//! prints nothing; errors go back as protocol errors or as tool results marked `isError`.
//!
//! # Protocol
//!
//! JSON-RPC 2.0 over stdin and stdout, newline-delimited, per the MCP stdio transport. `initialize`,
//! `ping`, `tools/list` and `tools/call` are answered; notifications get no reply; anything else is
//! "method not found". No dependency beyond `serde_json`: the protocol surface this needs is small,
//! and an SDK would be a large, fast-moving thing to trust for it.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Component, Path, PathBuf};

/// Protocol versions this server speaks, newest first. A client asking for one of these gets it;
/// any other gets the newest, and decides for itself whether it can go on.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "SecureVibe checks an app against OWASP ASVS 5.0, AISVS 1.0 and the \
    Secure by Design checklist. Call securevibe_spec first if the app has no securevibe.toml, and \
    write one from it. securevibe_check never says a requirement passed: read what it says was not \
    examined before anything else, and do not tell the person the app is secure. It does not start \
    the app or run other security tools; for those, ask the person to run `sv report --run --tools` \
    in a terminal.";

pub struct Server {
    /// The folder every path is resolved against, canonical.
    root: PathBuf,
}

/// Runs the server on stdin and stdout until stdin closes.
pub fn cmd_mcp(args: &[String]) -> Result<()> {
    let mut root = PathBuf::from(".");
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(rest.next().context("--root needs a folder")?),
            other => anyhow::bail!("unknown option for `sv mcp`: {other}"),
        }
    }
    let server = Server::new(&root)?;
    eprintln!(
        "sv mcp: serving {} over stdio; paths outside it are refused",
        server.root.display()
    );
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.context("reading stdin")?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = server.handle_line(&line) {
            writeln!(stdout, "{reply}").context("writing stdout")?;
            stdout.flush().context("flushing stdout")?;
        }
    }
    Ok(())
}

impl Server {
    pub fn new(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("the folder {} cannot be opened", root.display()))?;
        anyhow::ensure!(root.is_dir(), "{} is not a folder", root.display());
        Ok(Server { root })
    }

    /// One line of input to at most one line of output. Notifications get none.
    pub fn handle_line(&self, line: &str) -> Option<String> {
        let message: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    error_reply(Value::Null, -32700, &format!("not JSON: {e}")).to_string(),
                );
            }
        };
        self.handle(&message).map(|v| v.to_string())
    }

    pub fn handle(&self, message: &Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str);
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let Some(method) = method else {
            // A response to something we never asked, or a malformed request: nothing to answer
            // unless it carried an id to answer to.
            return id.map(|id| error_reply(id, -32600, "a request needs a method"));
        };
        // Notifications carry no id and are never answered, known or not.
        let id = id?;
        Some(match method {
            "initialize" => ok_reply(id, self.initialize(&params)),
            "ping" => ok_reply(id, json!({})),
            "tools/list" => ok_reply(id, json!({ "tools": tools() })),
            "tools/call" => match self.call(&params) {
                Ok(result) => ok_reply(id, result),
                Err(Refusal::UnknownTool(name)) => {
                    error_reply(id, -32602, &format!("there is no tool called {name}"))
                }
            },
            other => error_reply(id, -32601, &format!("no method called {other}")),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let asked = params.get("protocolVersion").and_then(Value::as_str);
        let version = asked
            .filter(|v| PROTOCOL_VERSIONS.contains(v))
            .unwrap_or(PROTOCOL_VERSIONS[0]);
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "securevibe", "version": env!("CARGO_PKG_VERSION") },
            "instructions": INSTRUCTIONS,
        })
    }

    fn call(&self, params: &Value) -> Result<Value, Refusal> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let result = match name {
            "securevibe_spec" => Ok(spec()),
            "securevibe_explain" => explain(&args),
            "securevibe_check" => self.check(&args),
            "securevibe_write_report" => self.write_report(&args),
            other => return Err(Refusal::UnknownTool(other.to_owned())),
        };
        // A tool that could not do its job says so as its result, which the model reads; a protocol
        // error is for a call that was malformed, which this was not.
        Ok(result.unwrap_or_else(|e| tool_error(&format!("{e:#}"))))
    }

    /// Resolves a path a tool was given against the root, and refuses anything outside it.
    ///
    /// Canonicalized, so `..` and symlinks are resolved before the check rather than after: a
    /// link inside the root that points outside it lands outside it.
    fn app_dir(&self, args: &Value) -> Result<PathBuf> {
        let asked = args.get("path").and_then(Value::as_str).unwrap_or(".");
        let joined = if Path::new(asked).is_absolute() {
            PathBuf::from(asked)
        } else {
            self.root.join(asked)
        };
        let resolved = joined
            .canonicalize()
            .with_context(|| format!("{asked} does not exist under {}", self.root.display()))?;
        anyhow::ensure!(
            resolved.starts_with(&self.root),
            "{asked} is outside {}, the folder this server was started for, so it cannot be read",
            self.root.display()
        );
        anyhow::ensure!(resolved.is_dir(), "{asked} is not a folder");
        Ok(resolved)
    }

    fn report_for(&self, app_dir: &Path) -> Result<sv_report::Report> {
        anyhow::ensure!(
            app_dir.join("securevibe.toml").exists(),
            "there is no securevibe.toml in {}. Call securevibe_spec, write the file it describes \
             into that folder, and check again.",
            app_dir.display()
        );
        crate::assemble_report(
            app_dir,
            &crate::ReportOptions {
                run_the_app: false,
                run_tools: false,
                why_not_run: "The MCP server never starts the app; the person can, with \
                              `sv report --run` in a terminal.",
                why_no_tools: "The MCP server never runs other people's tools; the person can, \
                               with `sv report --tools` in a terminal.",
            },
        )
    }

    fn check(&self, args: &Value) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        let report = self.report_for(&app_dir)?;
        Ok(json!({
            "content": [{ "type": "text", "text": summary(&report) }],
            "structuredContent": structured(&report),
            "isError": false,
        }))
    }

    fn write_report(&self, args: &Value) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        let out = args
            .get("out")
            .and_then(Value::as_str)
            .unwrap_or("securevibe-report");
        // Relative and downward only. The folder may not exist yet, so it cannot be canonicalized
        // before it is created; refusing `..` and absolute paths keeps it under the app instead.
        anyhow::ensure!(
            Path::new(out)
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
            "out has to be a folder inside the app, written without `..`: {out}"
        );
        let out_dir = app_dir.join(out);
        // Components are not enough. A symlink inside the app has only `Normal` components and is
        // followed on the way out, so `out: "elsewhere"` wrote five files wherever it pointed and
        // said it had succeeded. The folder may not exist yet, so it is created first and then
        // resolved: `create_dir_all` on an existing symlink-to-a-folder succeeds without creating
        // anything, and the resolved path is then somewhere else, which is what this catches.
        // Nothing has been written at this point, so refusing here costs nothing.
        std::fs::create_dir_all(&out_dir)
            .with_context(|| format!("{} cannot be created", out_dir.display()))?;
        let resolved = out_dir
            .canonicalize()
            .with_context(|| format!("{} cannot be opened", out_dir.display()))?;
        anyhow::ensure!(
            resolved.starts_with(&app_dir),
            "out resolves to {}, which is outside the app at {}",
            resolved.display(),
            app_dir.display()
        );
        let out_dir = resolved;
        let report = self.report_for(&app_dir)?;
        let written = crate::write_report_files(&report, &out_dir)?;
        let files: Vec<String> = written
            .iter()
            .map(|name| out_dir.join(name).display().to_string())
            .collect();
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Wrote {} files to {}: {}. report.html is the one for a person to open.\n\n{}",
                    files.len(),
                    out_dir.display(),
                    written.join(", "),
                    summary(&report)
                ),
            }],
            "structuredContent": { "files": files },
            "isError": false,
        }))
    }
}

enum Refusal {
    UnknownTool(String),
}

fn ok_reply(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

fn tools() -> Value {
    let path = json!({
        "type": "string",
        "description": "The app's folder, relative to the folder this server was started for. Defaults to that folder."
    });
    json!([
        {
            "name": "securevibe_check",
            "title": "Check an app",
            "description": "Check the app against OWASP ASVS 5.0, AISVS 1.0 and the Secure by Design checklist: credentials in the code, configuration, rules that read the code, dependencies, and which requirements apply. Reads files only; never starts the app. The result lists what was NOT examined first, then what needs attention with the file, line and fix. It never says a requirement passed, and nothing in it means the app is secure.",
            "inputSchema": { "type": "object", "properties": { "path": path.clone() } },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "securevibe_write_report",
            "title": "Write the full report",
            "description": "Write the full reports into a folder inside the app (securevibe-report by default): report.html for a person, compliance.md, security.md, findings.sarif and report.json. Same checks as securevibe_check.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path,
                    "out": { "type": "string", "description": "Folder inside the app to write to. No `..`." }
                }
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": false }
        },
        {
            "name": "securevibe_explain",
            "title": "Explain a requirement",
            "description": "What a requirement asks for, in its framework's own words, with its level and where the level comes from. Takes an id such as V1.2.4, C9.5.4, AC.4.1 or SBD-AC-05.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string", "description": "The requirement id." } },
                "required": ["id"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "securevibe_spec",
            "title": "How to describe the app",
            "description": "The securevibe.toml the app needs before it can be checked, with instructions for filling it in. Write it into the app's folder from what the app really does; a claim the code contradicts is reported, and requirements only ever apply more because of it, never less.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        }
    ])
}

fn spec() -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!("{}\n{}", sv_manifest::spec::STARTER_MANIFEST, sv_manifest::spec::INSTRUCTIONS),
        }],
        "isError": false,
    })
}

fn explain(args: &Value) -> Result<Value> {
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .context("securevibe_explain needs an id")?;
    let data = crate::data_dir()?;
    let frameworks = crate::load_frameworks(&data)?;
    let r = frameworks
        .get(id)
        .with_context(|| format!("{id} is not a requirement in any loaded framework"))?;
    let mut text = format!(
        "{id} ({}), level {}{}\n\n{}",
        r.chapter_name,
        r.level,
        r.level_basis
            .as_deref()
            .map(|b| format!(" — {b}"))
            .unwrap_or_default(),
        r.description
    );
    if !r.counterparts.is_empty() {
        text.push_str(&format!(
            "\n\nASVS requirements that ask the same thing: {}. Evidence about them is shown \
             beside this one as supporting, never as checking it.",
            r.counterparts.join(", ")
        ));
    }
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": {
            "id": id,
            "chapter": r.chapter_name,
            "level": r.level,
            "levelBasis": r.level_basis,
            "description": r.description,
            "counterparts": r.counterparts,
        },
        "isError": false,
    }))
}

/// The report as a model should read it: what was not examined first, then what needs attention.
fn summary(report: &sv_report::Report) -> String {
    let c = &report.counts;
    let mut out = format!(
        "{}: {} requirements apply at ASVS level {}. {} need attention, {} were checked by an \
         automated check, {} were not verified by anything. {} more could not be placed because \
         nobody has answered the question that decides them. Nothing here says a requirement \
         passed.\n",
        report.app_name,
        c.applicable,
        report.target_level,
        c.needs_attention,
        c.checked,
        c.not_verified,
        c.not_assessed
    );
    if !report.gaps.is_empty() {
        out.push_str("\nNOT EXAMINED — read these before anything below:\n");
        for gap in &report.gaps {
            out.push_str(&format!("- {}: {}\n", gap.what, gap.why));
        }
    }
    let contradicted: Vec<&sv_report::ClaimLine> = report
        .claims
        .iter()
        .filter(|c| c.state == "contradicted")
        .collect();
    if !contradicted.is_empty() {
        out.push_str("\nsecurevibe.toml says one thing and the code another (the code wins):\n");
        for claim in contradicted {
            out.push_str(&format!("- {}: {}\n", claim.name, claim.note));
        }
    }
    if !report.tests_to_write.is_empty() {
        const SHOWN: usize = 30;
        out.push_str(&format!(
            "\nTESTS TO WRITE — {} applicable requirements have no evidence and no test naming \
             them. A test that really checks one, with its id in the test's name, is how it gets \
             evidence. Lowest level first:\n",
            report.tests_to_write.len()
        ));
        for t in report.tests_to_write.iter().take(SHOWN) {
            out.push_str(&format!(
                "- {} (level {}): {}\n",
                t.id, t.level, t.description
            ));
        }
        if report.tests_to_write.len() > SHOWN {
            out.push_str(&format!(
                "- and {} more, in compliance.md\n",
                report.tests_to_write.len() - SHOWN
            ));
        }
    }
    if report.findings.is_empty() {
        out.push_str("\nNo findings. That is not the same as secure: see what was not examined.\n");
    } else {
        out.push_str(&format!("\n{} FINDINGS:\n", report.findings.len()));
        for f in &report.findings {
            out.push_str(&format!(
                "- [{}] {} — {}:{}{}\n  fix: {}\n",
                f.severity.name(),
                f.title,
                f.location.file,
                f.location.line,
                if f.requirement_ids.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", f.requirement_ids.join(", "))
                },
                f.fix
            ));
        }
    }
    out
}

/// The same, as data, for a client that reads structured results.
fn structured(report: &sv_report::Report) -> Value {
    json!({
        "app": report.app_name,
        "targetLevel": report.target_level,
        "counts": report.counts,
        "notExamined": report.gaps,
        "findings": report.findings,
        "needsAttention": report
            .requirements
            .iter()
            .filter(|l| l.status == sv_report::Status::NeedsAttention)
            .map(|l| &l.id)
            .collect::<Vec<_>>(),
        "claims": report.claims,
        "undecided": report.undecided,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
    }

    fn call(server: &Server, name: &str, args: Value) -> Value {
        server
            .handle(&json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": { "name": name, "arguments": args }
            }))
            .expect("a request is answered")["result"]
            .clone()
    }

    fn text(result: &Value) -> &str {
        result["content"][0]["text"].as_str().unwrap_or("")
    }

    #[test]
    fn a_path_outside_the_root_is_refused_however_it_is_written() {
        // The fence. Each of these reaches the folder next to the example app.
        let server = Server::new(&examples().join("tested-notes")).unwrap();
        for path in [
            "..",
            "../flask-booking",
            examples().join("flask-booking").to_str().unwrap(),
            "/",
        ] {
            let result = call(&server, "securevibe_check", json!({ "path": path }));
            assert_eq!(result["isError"], true, "{path} was not refused");
            assert!(
                text(&result).contains("outside"),
                "{path}: {}",
                text(&result)
            );
        }
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        // Resolved before the check, so a link inside the root pointing outside it lands outside.
        let root = std::env::temp_dir().join(format!("sv-mcp-link-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(examples().join("tested-notes"), root.join("elsewhere"))
            .unwrap();
        let server = Server::new(&root).unwrap();
        let result = call(&server, "securevibe_check", json!({ "path": "elsewhere" }));
        std::fs::remove_dir_all(&root).ok();
        #[cfg(unix)]
        assert_eq!(result["isError"], true, "{}", text(&result));
    }

    #[test]
    fn a_report_is_not_written_through_a_symlink_out_of_the_app() {
        // `out` is checked by its components — no `..`, nothing absolute — and then joined. A
        // symlink inside the app has only Normal components and is followed on the way out.
        // Named for this test, not just for the process. `a_report_is_written_only_below_the_app`
        // uses `sv-mcp-escaped-<pid>` too, and these run in parallel threads of one process: its
        // cleanup deleted the evidence this test was about to look for, so this passed while the
        // guard it checks was broken. A test that another test can quietly satisfy is worse than
        // no test.
        let root = std::env::temp_dir().join(format!("sv-mcp-symlink-{}", std::process::id()));
        let escaped =
            std::env::temp_dir().join(format!("sv-mcp-symlink-target-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&escaped).ok();
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::create_dir_all(&escaped).unwrap();
        std::fs::copy(
            examples().join("tested-notes").join("securevibe.toml"),
            root.join("app").join("securevibe.toml"),
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&escaped, root.join("app").join("elsewhere")).unwrap();

        let server = Server::new(&root).unwrap();
        let result = call(
            &server,
            "securevibe_write_report",
            json!({ "path": "app", "out": "elsewhere" }),
        );
        let landed_outside = escaped.join("report.html").exists();
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&escaped).ok();
        #[cfg(unix)]
        assert!(
            !landed_outside,
            "the report was written outside the app through a symlink: {}",
            text(&result)
        );
        #[cfg(unix)]
        assert_eq!(result["isError"], true, "{}", text(&result));
    }

    #[test]
    fn an_ordinary_out_folder_still_gets_the_report() {
        // The other half. A guard that refuses everything is worse than the hole it closed, and
        // this one runs on a path that does not exist yet, which is the case most easily broken.
        let root = std::env::temp_dir().join(format!("sv-mcp-ok-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::copy(
            examples().join("tested-notes").join("securevibe.toml"),
            root.join("app").join("securevibe.toml"),
        )
        .unwrap();
        let server = Server::new(&root).unwrap();
        let result = call(
            &server,
            "securevibe_write_report",
            json!({ "path": "app", "out": "reports/today" }),
        );
        let wrote = root
            .join("app")
            .join("reports")
            .join("today")
            .join("report.html");
        let landed = wrote.exists();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(result["isError"], false, "{}", text(&result));
        assert!(
            landed,
            "a plain nested out folder has to work: {}",
            text(&result)
        );
    }

    #[test]
    fn the_check_says_what_was_not_examined_before_what_was_found() {
        let server = Server::new(&examples()).unwrap();
        let result = call(
            &server,
            "securevibe_check",
            json!({ "path": "tested-notes" }),
        );
        assert_eq!(result["isError"], false, "{}", text(&result));
        let t = text(&result);
        let gaps = t.find("NOT EXAMINED").expect("the gaps are listed");
        let findings = t
            .find("FINDINGS")
            .or_else(|| t.find("No findings"))
            .unwrap();
        assert!(gaps < findings, "the gaps come first:\n{t}");
        assert!(t.contains("never starts the app"), "{t}");
        assert!(t.contains("Nothing here says a requirement passed"), "{t}");
        assert!(
            result["structuredContent"]["counts"]["applicable"]
                .as_u64()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn the_check_is_the_report_and_not_a_summary_of_it() {
        // One function builds both, so the counts a model is told are the counts a person reads.
        let server = Server::new(&examples()).unwrap();
        let result = call(
            &server,
            "securevibe_check",
            json!({ "path": "tested-notes" }),
        );
        let report = crate::assemble_report(
            &examples().join("tested-notes").canonicalize().unwrap(),
            &crate::ReportOptions {
                run_the_app: false,
                run_tools: false,
                why_not_run: "",
                why_no_tools: "",
            },
        )
        .unwrap();
        assert_eq!(
            result["structuredContent"]["counts"],
            serde_json::to_value(&report.counts).unwrap()
        );
    }

    #[test]
    fn an_app_with_no_manifest_is_pointed_at_the_spec() {
        let root = std::env::temp_dir().join(format!("sv-mcp-empty-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let server = Server::new(&root).unwrap();
        let result = call(&server, "securevibe_check", json!({}));
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(result["isError"], true);
        assert!(
            text(&result).contains("securevibe_spec"),
            "{}",
            text(&result)
        );
    }

    #[test]
    fn a_report_is_written_only_below_the_app() {
        let root = std::env::temp_dir().join(format!("sv-mcp-write-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        for f in ["securevibe.toml", "app.py"] {
            std::fs::copy(examples().join("tested-notes").join(f), root.join(f)).unwrap();
        }
        let server = Server::new(&root).unwrap();
        // Named per run and cleared first, so a folder left by an earlier run cannot decide this.
        let escaped_name = format!("sv-mcp-escaped-{}", std::process::id());
        let escaped = root.parent().unwrap().join(&escaped_name);
        std::fs::remove_dir_all(&escaped).ok();
        let refused = call(
            &server,
            "securevibe_write_report",
            json!({ "out": format!("../{escaped_name}") }),
        );
        let wrote_outside = escaped.exists();
        std::fs::remove_dir_all(&escaped).ok();
        assert_eq!(refused["isError"], true);
        assert!(!wrote_outside, "a report was written outside the app");
        let written = call(&server, "securevibe_write_report", json!({}));
        assert_eq!(written["isError"], false, "{}", text(&written));
        assert!(root.join("securevibe-report/report.html").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_absolute_report_folder_is_refused_too() {
        // The second shape of the same escape: not climbing with `..`, but naming a folder outright.
        let server = Server::new(&examples()).unwrap();
        let target = std::env::temp_dir().join(format!("sv-mcp-absolute-{}", std::process::id()));
        std::fs::remove_dir_all(&target).ok();
        let refused = call(
            &server,
            "securevibe_write_report",
            json!({ "path": "tested-notes", "out": target.to_str().unwrap() }),
        );
        let wrote = target.exists();
        std::fs::remove_dir_all(&target).ok();
        assert_eq!(refused["isError"], true, "{}", text(&refused));
        assert!(!wrote, "a report was written to an absolute folder");
    }

    #[test]
    fn the_protocol_basics() {
        let server = Server::new(&examples()).unwrap();
        let init = server
            .handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}))
            .unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert!(init["result"]["capabilities"]["tools"].is_object());
        // An unknown version gets the newest this server speaks.
        let init = server
            .handle(&json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}))
            .unwrap();
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
        // Notifications are never answered.
        assert!(
            server
                .handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .is_none()
        );
        let list = server
            .handle(&json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}))
            .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "securevibe_check",
                "securevibe_write_report",
                "securevibe_explain",
                "securevibe_spec"
            ]
        );
        let unknown = server
            .handle(&json!({"jsonrpc":"2.0","id":4,"method":"resources/list"}))
            .unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
        assert_eq!(
            server
                .handle_line("{not json")
                .map(|l| serde_json::from_str::<Value>(&l).unwrap()["error"]["code"].clone()),
            Some(json!(-32700))
        );
        let no_tool = server
            .handle(
                &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"rm_rf"}}),
            )
            .unwrap();
        assert_eq!(no_tool["error"]["code"], -32602);
    }

    #[test]
    fn explain_gives_the_frameworks_own_words_and_the_level_basis() {
        let result = explain(&json!({ "id": "SBD-DM-01" })).unwrap();
        let t = text(&result);
        assert!(t.contains("level 2, as V14.1.1"), "{t}");
        assert!(t.contains("V14.1.2"), "{t}");
        assert!(explain(&json!({"id": "not-a-requirement"})).is_err());
    }
}
