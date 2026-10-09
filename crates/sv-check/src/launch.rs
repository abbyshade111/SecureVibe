//! How the app is started where it is deployed, and how it starts the MCP servers it uses.
//!
//! Two checks that read the lines that start programs, not the programs themselves. Both can only
//! ever show a fault: a production start command `sv` can read is not the only way an app can be
//! started, and a pinned package version is not the cryptographic check C10.1.1 asks for. So a clean
//! reading credits no requirement, and says what it read.
//!
//! - V15.2.3 asks that production includes nothing it does not need, development functionality
//!   among it. A development server (`flask run`, `next dev`, `uvicorn --reload`) as the command a
//!   Dockerfile or Procfile starts is exactly that, and one line to fix.
//! - C10.1.1 asks that MCP components come only from trusted sources and are verified. A server
//!   started with `npx -y some-package` or `uvx some-package` with no version downloads whatever is
//!   newest at every start; nothing ties it to the code anyone reviewed.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;
use regex::Regex;
use std::sync::LazyLock;
use sv_scan::files::{Entry, Listing};

pub const DEV_SERVER: &str = "config.development-server-started";
pub const MCP_UNPINNED: &str = "config.mcp-server-unpinned";
pub const MCP_PLAIN_HTTP: &str = "config.mcp-transport-unencrypted";

/// Runs both checks over the app's files.
pub fn check(listing: &Listing, report: &mut ConfigReport) {
    development_server(listing, report);
    mcp_servers(listing, report);
}

// ---------------------------------------------------------------------------------------------
// V15.2.3: a development server as the production start command.

/// Commands that start a development server or an automatic reloader, with what each is in words.
///
/// Each is a server its own documentation says not to use in production. `vite` alone, `vite dev`,
/// and `vite serve` are its development server; `vite build` and `vite preview` are not matched.
static DEV_COMMANDS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (
            r"\bflask\s+run\b",
            "Flask's development server (`flask run`)",
        ),
        (
            r"\bmanage\.py\s+runserver\b",
            "Django's development server (`manage.py runserver`)",
        ),
        (
            r"\b(uvicorn|gunicorn|hypercorn)\b[^;&|]*\s--reload\b",
            "automatic reloading (`--reload`)",
        ),
        (
            r"\b(next|nuxt|nuxi|astro|remix)\s+dev\b",
            "a framework's development server (`dev`)",
        ),
        (
            r"\bvite(\s+(dev|serve)\b|\s*$|\s+--)",
            "Vite's development server",
        ),
        (
            r"\bng\s+serve\b",
            "Angular's development server (`ng serve`)",
        ),
        (
            r"\breact-scripts\s+start\b",
            "Create React App's development server (`react-scripts start`)",
        ),
        (
            r"\bwebpack(-dev-server\b|\s+serve\b)",
            "webpack's development server",
        ),
        (
            r"\bnodemon\b",
            "`nodemon`, which restarts the app whenever a file changes",
        ),
        (
            r"\bts-node-dev\b|\btsx\s+watch\b|\bnode\s+--watch\b",
            "a file watcher that restarts the app",
        ),
        (
            r"\bphp\s+artisan\s+serve\b",
            "Laravel's development server (`php artisan serve`)",
        ),
        (
            r"\bphp\s+-S\b",
            "PHP's built-in development server (`php -S`)",
        ),
        (
            r"\bdotnet\s+watch\b",
            "`dotnet watch`, which rebuilds and restarts on every change",
        ),
        (
            r"\bpython3?\s+-m\s+http\.server\b",
            "Python's `http.server`, which its documentation says is not for production",
        ),
        (
            r"\b(npm|yarn|pnpm|bun)\s+(run\s+)?dev\b",
            "the `dev` script, by convention the development server",
        ),
    ]
    .into_iter()
    .map(|(pattern, what)| (Regex::new(pattern).expect("a fixed pattern"), what))
    .collect()
});

/// Settings in a Dockerfile's final stage that put a framework in development mode.
static DEV_SETTINGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(NODE_ENV|FLASK_ENV|RAILS_ENV|RACK_ENV|APP_ENV|ASPNETCORE_ENVIRONMENT)["']?(\s*=\s*|\s+)["']?(development|local)\b|\bFLASK_DEBUG["']?(\s*=\s*|\s+)["']?(1|true)\b"#,
    )
    .expect("a fixed pattern")
});

/// `npm start`, `yarn start`, `npm run web`: a command that hands over to a package.json script.
static RUNS_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(npm|yarn|pnpm|bun)\s+(run\s+)?([\w:.-]+)").expect("a fixed pattern")
});

/// A command that runs one of the app's own files: whether that starts a development server, or turns
/// a framework's debug mode on, is in the file, not the command.
static RUNS_OWN_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:python3?|node|ruby|php|deno run|bun)\s+(?:-\S+\s+)*([\w./-]+\.(?:py|js|mjs|cjs|ts|rb|php))\b")
        .expect("a fixed pattern")
});

/// Words in a file or folder name that say the file is for development, not production.
pub(crate) fn for_development(relative: &str) -> bool {
    let lower = relative.to_lowercase();
    let (dirs, name) = lower.rsplit_once('/').unwrap_or(("", lower.as_str()));
    let named = ["dev", "develop", "development", "local", "test", "debug"]
        .iter()
        .any(|w| name.split(['.', '-', '_']).any(|part| part == *w));
    let folder = dirs.split('/').any(|d| {
        matches!(
            d,
            ".devcontainer"
                | "dev"
                | "development"
                | "test"
                | "tests"
                | "e2e"
                | "example"
                | "examples"
        )
    });
    named || folder
}

fn is_dockerfile(name: &str) -> bool {
    name == "Dockerfile"
        || name == "Containerfile"
        || name.starts_with("Dockerfile.")
        || name.ends_with(".Dockerfile")
        || name.ends_with(".dockerfile")
}

/// A start command found in a file, with where it is.
struct Start {
    file: String,
    line: usize,
    command: String,
    /// A development setting in the same stage, as written.
    setting: Option<(usize, String)>,
}

/// The command a Dockerfile's last stage runs, and any development setting in that stage.
fn dockerfile_start(relative: &str, text: &str) -> Option<Start> {
    let mut entrypoint: Option<(usize, String)> = None;
    let mut cmd: Option<(usize, String)> = None;
    let mut setting = None;
    let mut logical = String::new();
    let mut first_line = 0;
    let lines: Vec<&str> = text.lines().collect();
    for (index, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim();
        if logical.is_empty() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            first_line = index + 1;
        }
        if let Some(head) = trimmed.strip_suffix('\\') {
            logical.push_str(head);
            logical.push(' ');
            continue;
        }
        logical.push_str(trimmed);
        let instruction = std::mem::take(&mut logical);
        let (word, rest) = instruction
            .split_once(char::is_whitespace)
            .unwrap_or((instruction.as_str(), ""));
        match word.to_uppercase().as_str() {
            // A new stage: what the earlier one said is not what runs.
            "FROM" => {
                entrypoint = None;
                cmd = None;
                setting = None;
            }
            "ENTRYPOINT" => entrypoint = Some((first_line, exec_form(rest))),
            "CMD" => cmd = Some((first_line, exec_form(rest))),
            "ENV" | "ARG" if DEV_SETTINGS.is_match(rest) => {
                setting = Some((first_line, rest.trim().to_owned()));
            }
            _ => {}
        }
    }
    let line = cmd.as_ref().or(entrypoint.as_ref())?.0;
    let command = [entrypoint, cmd]
        .into_iter()
        .flatten()
        .map(|(_, c)| c)
        .collect::<Vec<_>>()
        .join(" ");
    Some(Start {
        file: relative.to_owned(),
        line,
        command,
        setting,
    })
}

/// `["npm", "run", "dev"]` as `npm run dev`; the shell form unchanged.
fn exec_form(rest: &str) -> String {
    match serde_json::from_str::<Vec<String>>(rest.trim()) {
        Ok(words) => words.join(" "),
        Err(_) => rest.trim().to_owned(),
    }
}

/// The `web:` process in a Procfile.
fn procfile_start(relative: &str, text: &str) -> Option<Start> {
    text.lines().enumerate().find_map(|(index, line)| {
        let command = line.trim().strip_prefix("web:")?;
        Some(Start {
            file: relative.to_owned(),
            line: index + 1,
            command: command.trim().to_owned(),
            setting: None,
        })
    })
}

/// The package.json scripts in the same folder as `relative`, or at the top of the app.
fn scripts_beside(
    listing: &Listing,
    relative: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let dir = relative.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let beside = if dir.is_empty() {
        "package.json".to_owned()
    } else {
        format!("{dir}/package.json")
    };
    [beside, "package.json".to_owned()].iter().find_map(|path| {
        let entry = listing.app_files().find(|f| &f.relative == path)?;
        let text = entry.read_text().ok()?;
        let json: serde_json::Value = serde_json::from_str(&text).ok()?;
        json.get("scripts")?.as_object().cloned()
    })
}

/// What in this command is a development server, following one hand-over to a package.json script.
fn development_part(listing: &Listing, start: &Start) -> Option<String> {
    let direct = |command: &str| {
        DEV_COMMANDS
            .iter()
            .find(|(pattern, _)| pattern.is_match(command))
            .map(|(_, what)| (*what).to_owned())
    };
    if let Some(what) = direct(&start.command) {
        return Some(what);
    }
    let script = RUNS_SCRIPT.captures(&start.command)?;
    let name = script.get(3)?.as_str();
    // `npm install` and `npm ci` are not scripts.
    if matches!(name, "install" | "ci" | "i" | "add" | "exec" | "x") {
        return None;
    }
    let scripts = scripts_beside(listing, &start.file)?;
    let body = scripts.get(name)?.as_str()?;
    direct(body)
        .map(|what| format!("{what}, through the `{name}` script in package.json (`{body}`)"))
}

fn development_server(listing: &Listing, report: &mut ConfigReport) {
    let mut read = Vec::new();
    let mut unread = Vec::new();
    let mut starts = Vec::new();
    let candidates = listing.app_files().filter(|f| {
        (is_dockerfile(f.file_name()) || f.file_name() == "Procfile")
            && !for_development(&f.relative)
    });
    for entry in candidates {
        match entry.read_text() {
            Ok(text) => {
                read.push(entry.relative.clone());
                let start = if entry.file_name() == "Procfile" {
                    procfile_start(&entry.relative, &text)
                } else {
                    dockerfile_start(&entry.relative, &text)
                };
                starts.extend(start);
            }
            Err(why) => unread.push(format!("`{}` ({})", entry.relative, why.explain())),
        }
    }
    let mut found = false;
    for start in &starts {
        let part = development_part(listing, start);
        let (line, what) = match (&part, &start.setting) {
            (Some(what), _) => (start.line, what.clone()),
            (None, Some((line, setting))) => {
                (*line, format!("a development setting (`{setting}`)"))
            }
            (None, None) => continue,
        };
        found = true;
        report
            .findings
            .push(dev_server_finding(&start.file, line, &what, &start.command));
    }
    if found {
        return;
    }
    if !unread.is_empty() {
        report.not_assessed.push((
            DEV_SERVER.to_owned(),
            format!(
                "`sv` could not read {}, so how the app is started there is not known.",
                unread.join(", ")
            ),
        ));
    } else if read.is_empty() {
        report.not_assessed.push((
            DEV_SERVER.to_owned(),
            "There is no Dockerfile or Procfile (other than ones named for development), so `sv` \
             cannot see what command starts the app where it is deployed."
                .to_owned(),
        ));
    } else {
        // Until 7 October 2026 a command such as `python app.py` read as "none starts a development
        // server", when `app.py` could start Flask's debugger (gap analysis 1.9).
        let mut own: Vec<String> = starts
            .iter()
            .filter_map(|s| RUNS_OWN_FILE.captures(&s.command))
            .filter_map(|c| c.get(1).map(|f| format!("`{}`", f.as_str())))
            .collect();
        own.dedup();
        let own = if own.is_empty() {
            String::new()
        } else {
            format!(
                "; {} {} the app's own code, which decides for itself whether it starts a development \
                 server or a debug mode (`ast.debug-mode-on` reads Python's)",
                own.join(", "),
                if own.len() == 1 { "runs" } else { "run" }
            )
        };
        report.passed.push(Verified::new(
            DEV_SERVER,
            &[],
            format!(
                "{}: no command starts a development server{own}; how the host starts the app when it \
                 does not use these files is not in any file",
                read.iter().map(|r| format!("`{r}`")).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
}

#[track_caller]
fn dev_server_finding(file: &str, line: usize, what: &str, command: &str) -> Finding {
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "config.development-server-started".into(),
        title: "The app is started with a development server".into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        location: Location {
            file: file.to_owned(),
            line,
        },
        secret: None,
        requirement_ids: vec!["V15.2.3".into()],
        cwe: vec!["CWE-489".into()],
        description: format!(
            "`{file}` starts the app with {what}. The command it runs is `{command}`. Development \
             servers are built for one person on their own computer: they reload code as it changes, \
             and many show a detailed error page or a debugging console."
        ),
        impact: "Development functionality in production is what V15.2.3 asks to leave out: a debug \
                 page can show your code, settings, and keys to whoever triggers an error, and some \
                 development consoles run whatever code they are sent."
            .into(),
        fix: "Start the app with a production server instead: `gunicorn` or `uvicorn` without \
              `--reload` for Python, `next start` after `next build`, `node server.js` rather than \
              `nodemon`, and set `NODE_ENV=production` (or your framework's equivalent). If this file is \
              only for development, name it so (`Dockerfile.dev`) and `sv` will leave it out."
            .into(),
    })
}

// ---------------------------------------------------------------------------------------------
// C10.3.1: an MCP link to another computer over plain HTTP (ADR-068).

/// An MCP client transport opened with a plain-HTTP address as its first argument, in the ways
/// the official SDKs and the common agent libraries write one: TypeScript's
/// `new StreamableHTTPClientTransport(new URL("http://…"))`, Python's `streamablehttp_client("http://…")`.
static TRANSPORT_OPENED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:StreamableHTTPClientTransport|SSEClientTransport|streamablehttp_client|streamable_http_client|sse_client|MCPServerStreamableHttp|MCPServerSse)\s*\(\s*(?:new\s+URL\s*\(\s*)?["'](http://[^"'\s]+)["']"#,
    )
    .expect("a fixed pattern")
});

/// An MCP server's address given as a `url` (or `serverUrl`, `server_url`), as configuration files
/// and the agent libraries' server tables write one. Counted only with MCP named shortly before it.
static ADDRESS_GIVEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']?\b(?:url|serverUrl|server_url)["']?\s*[:=]\s*["'](http://[^"'\s]+)["']"#)
        .expect("a fixed pattern")
});

/// Whether a plain-HTTP address names a computer other than this one or one on its own network:
/// loopback, private and link-local addresses, `.localhost`, `.local` and `.internal` names, and a
/// name with no dot never leave it. A name with no dot is `localhost`, a service on the same Docker
/// network, or one built at run time (`${HOST}`), which is not judged.
fn leaves_the_network(address: &str) -> bool {
    // Only plain HTTP: the patterns match nothing else, and this holds even if one is widened.
    let Some(rest) = address.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    }
    .to_ascii_lowercase();
    if !host.contains(['.', ':']) {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified())
            }
            std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified()),
        };
    }
    !(host.ends_with(".localhost") || host.ends_with(".local") || host.ends_with(".internal"))
}

/// Every plain-HTTP MCP link to another computer in one file's text, with its line.
fn plain_mcp_links_in(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let line_of = |at: usize| text[..at].matches('\n').count() + 1;
    for found in TRANSPORT_OPENED.captures_iter(text) {
        let address = found.get(1).expect("the address");
        out.push((line_of(address.start()), address.as_str().to_owned()));
    }
    for found in ADDRESS_GIVEN.captures_iter(text) {
        let address = found.get(1).expect("the address");
        let before = text
            .get(address.start().saturating_sub(400)..address.start())
            .unwrap_or("")
            .to_ascii_lowercase();
        if before.contains("mcp") {
            out.push((line_of(address.start()), address.as_str().to_owned()));
        }
    }
    out.retain(|(_, address)| leaves_the_network(address));
    out.sort();
    out.dedup();
    out
}

#[track_caller]
fn plain_http_finding(file: &str, line: usize, address: &str) -> Finding {
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "config.mcp-transport-unencrypted".into(),
        title: "An MCP server on another computer is reached over plain HTTP".into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        location: Location {
            file: file.to_owned(),
            line,
        },
        secret: None,
        requirement_ids: vec!["C10.3.1".into()],
        cwe: vec!["CWE-319".into()],
        description: format!(
            "The app connects to an MCP server at `{address}`, which is plain HTTP to another \
             computer: nothing on the link is encrypted."
        ),
        impact: "Every tool call, every result, and the token the link is opened with can be read \
                 and changed by anybody on the network between the app and the server."
            .into(),
        fix: "Reach the server at an `https://` address over the streamable HTTP transport, and \
              have it ask for a token on every request (OAuth 2.1, as the MCP specification \
              describes); if the server is yours and runs beside the app, keep it on the app's own \
              network instead."
            .into(),
    })
}

// ---------------------------------------------------------------------------------------------
// C10.1.1: MCP servers started from a package or image with no pinned version.

/// Files and folders that configure a developer's own AI tools, not the app. What they start runs
/// on the developer's computer, which C10.1.1 is not about.
pub(crate) fn developer_tool_config(relative: &str) -> bool {
    let first = relative.split('/').next().unwrap_or("");
    matches!(
        first,
        ".cursor"
            | ".claude"
            | ".windsurf"
            | ".gemini"
            | ".roo"
            | ".continue"
            | ".vscode"
            | ".idea"
    ) || relative == ".mcp.json"
        || relative.ends_with("claude_desktop_config.json")
}

/// A `command` naming a program that downloads what it runs.
static LAUNCHER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']?\bcommand["']?\s*[:=]\s*["'](npx|bunx|pnpx|uvx|pipx|pnpm|yarn|docker)((?:\s[^"']*)?)["']"#)
        .expect("a fixed pattern")
});

/// An `args` list, in any of the ways JSON, YAML flow style, TOML, Python, or JavaScript write one.
static ARGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']?\bargs["']?\s*[:=]\s*\[([^\]]*)\]"#).expect("a fixed pattern")
});

static QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"]*)"|'([^']*)'"#).expect("a fixed pattern"));

/// What an MCP server is started from, and whether that names one exact version.
#[derive(Debug, PartialEq, Eq)]
struct Launch {
    launcher: String,
    package: String,
    pinned: bool,
}

/// Reads the package or image out of a launcher and its arguments. `None` when the arguments name
/// nothing downloaded: a local file, or a subcommand that is not a one-off run.
fn launch_of(launcher: &str, args: &[String]) -> Option<Launch> {
    let mut args: Vec<&str> = args.iter().map(String::as_str).collect();
    let launcher = match launcher {
        // `pnpm dlx` and `yarn dlx` are npx; anything else they run is a script of the app's own.
        "pnpm" | "yarn" => {
            if args.first() != Some(&"dlx") {
                return None;
            }
            args.remove(0);
            "npx"
        }
        "pipx" => {
            if args.first() != Some(&"run") {
                return None;
            }
            args.remove(0);
            "uvx"
        }
        "bunx" | "pnpx" => "npx",
        other => other,
    };
    let package = match launcher {
        "npx" => named_after(&args, &["-p", "--package"], &[]),
        "uvx" => named_after(
            &args,
            &["--from", "--spec"],
            &["--with", "--python", "-p", "--index-url"],
        ),
        "docker" => {
            let run = args.iter().position(|a| *a == "run")?;
            named_after(
                &args[run + 1..],
                &[],
                &[
                    "-e",
                    "--env",
                    "-v",
                    "--volume",
                    "--name",
                    "-p",
                    "--publish",
                    "--network",
                    "--mount",
                    "-w",
                    "--workdir",
                    "-u",
                    "--user",
                    "--entrypoint",
                    "--env-file",
                    "-l",
                    "--label",
                    "--platform",
                    "--add-host",
                    "--cpus",
                    "-m",
                    "--memory",
                    "--pull",
                ],
            )
        }
        _ => None,
    }?;
    if package.starts_with(['.', '/', '~', '$'])
        || !package.chars().any(|c| c.is_ascii_alphabetic())
    {
        return None;
    }
    let pinned = match launcher {
        "docker" => DIGEST.is_match(package),
        "npx" => package
            .rfind('@')
            .filter(|at| *at > 0)
            .is_some_and(|at| EXACT.is_match(&package[at + 1..])),
        _ => package
            .split_once("==")
            .or_else(|| package.split_once('@'))
            .is_some_and(|(_, version)| EXACT.is_match(version)),
    };
    Some(Launch {
        launcher: launcher.to_owned(),
        package: package.to_owned(),
        pinned,
    })
}

static EXACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$").expect("a fixed pattern")
});
static DIGEST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@sha256:[0-9a-f]{64}$").expect("a fixed pattern"));

/// The value of the first of `naming` flags, or else the first argument that is not a flag,
/// skipping the value after each of `valued`.
fn named_after<'a>(args: &[&'a str], naming: &[&str], valued: &[&str]) -> Option<&'a str> {
    for (i, arg) in args.iter().enumerate() {
        if naming.contains(arg) {
            return args.get(i + 1).copied();
        }
        if let Some((flag, value)) = arg.split_once('=')
            && naming.contains(&flag)
        {
            return Some(value);
        }
    }
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if arg.starts_with('-') {
            skip = valued.contains(arg) || naming.contains(arg);
            continue;
        }
        return Some(arg);
    }
    None
}

/// Every MCP server start in one file's text, with its line.
/// The packages or images `text` starts an MCP server from with no exact version, as
/// `config.mcp-server-unpinned` judges them: for the AI coding tool's own files (`ai_tool`), which
/// that check leaves out.
pub(crate) fn unpinned_in(text: &str) -> Vec<String> {
    launches_in(text)
        .into_iter()
        .filter(|(_, launch)| !launch.pinned)
        .map(|(_, launch)| launch.package)
        .collect()
}

fn launches_in(text: &str) -> Vec<(usize, Launch)> {
    let mut out = Vec::new();
    for found in LAUNCHER.captures_iter(text) {
        let whole = found.get(0).expect("the whole match");
        let launcher = &found[1];
        // A command written as one string, `"npx -y pkg"`, carries its own first arguments.
        let mut args: Vec<String> = found[2].split_whitespace().map(str::to_owned).collect();
        // The `args` list nearest the command, after it or, failing that, before it, within the same
        // few lines an object literal spans.
        let after = &text[whole.end()..(whole.end() + 400).min(text.len())];
        let before_start = whole.start().saturating_sub(400);
        let before = text.get(before_start..whole.start()).unwrap_or("");
        let list = ARGS
            .captures(after)
            .or_else(|| ARGS.captures_iter(before).last())
            .map(|c| c[1].to_owned());
        if let Some(list) = list {
            args.extend(
                QUOTED
                    .captures_iter(&list)
                    .map(|q| q.get(1).or(q.get(2)).map_or("", |m| m.as_str()).to_owned()),
            );
        }
        if let Some(launch) = launch_of(launcher, &args) {
            let line = text[..whole.start()].matches('\n').count() + 1;
            out.push((line, launch));
        }
    }
    out
}

/// Files an MCP server's start can be written in: configuration files and code.
fn may_start_servers(entry: &Entry) -> bool {
    entry.language.is_some()
        || matches!(
            entry.extension.as_deref(),
            Some("json" | "jsonc" | "yaml" | "yml" | "toml")
        )
}

fn mcp_servers(listing: &Listing, report: &mut ConfigReport) {
    let mut read = 0usize;
    let mut unread = Vec::new();
    let mut pinned = Vec::new();
    let mut found = false;
    for entry in listing
        .app_files()
        .filter(|f| may_start_servers(f) && !developer_tool_config(&f.relative))
    {
        let text = match entry.read_text() {
            Ok(text) => text,
            // A file over 2 MB is almost always data. Read in pieces, it counts as read unless a
            // piece sets `command` to one of the programs this check follows (`npx`, `uvx`, `docker`,
            // and the rest), the same pattern every other file is judged by. Until 29 September 2026
            // the word `command` anywhere was enough, and NIST's 10 MB catalog, whose prose uses the
            // word, kept this check from running on cato-pipeline. A file that does set one stays
            // unread and named, since the server's arguments may lie across pieces.
            Err(sv_scan::files::Unread::TooLarge) => {
                let mut starts_one = false;
                let pieces = entry.in_pieces(1024 * 1024, 4096, |piece| {
                    starts_one = starts_one || LAUNCHER.is_match(piece.text);
                });
                match pieces {
                    Ok(()) if !starts_one => {
                        read += 1;
                        continue;
                    }
                    Ok(()) => {
                        unread.push(format!(
                            "`{}` (larger than 2 MB, and it sets `command` to a program that \
                             downloads what it runs)",
                            entry.relative
                        ));
                        continue;
                    }
                    Err(why) => {
                        unread.push(format!("`{}` ({})", entry.relative, why.explain()));
                        continue;
                    }
                }
            }
            Err(why) => {
                unread.push(format!("`{}` ({})", entry.relative, why.explain()));
                continue;
            }
        };
        read += 1;
        for (line, address) in plain_mcp_links_in(&text) {
            report
                .findings
                .push(plain_http_finding(&entry.relative, line, &address));
        }
        if !text.contains("command") {
            continue;
        }
        for (line, launch) in launches_in(&text) {
            if launch.pinned {
                pinned.push(format!("`{}`", launch.package));
                continue;
            }
            found = true;
            report
                .findings
                .push(mcp_finding(&entry.relative, line, &launch));
        }
    }
    if found {
        return;
    }
    let scope = if pinned.is_empty() {
        format!(
            "{read} files: no MCP server started with npx, uvx, or docker from a package or image \
             named in them"
        )
    } else {
        format!(
            "{read} files: every MCP server started from a package names an exact version ({}); a \
             pinned version is not the cryptographic check C10.1.1 asks for",
            pinned.join(", ")
        )
    };
    if !unread.is_empty() {
        report.not_assessed.push((
            MCP_UNPINNED.to_owned(),
            format!(
                "`sv` could not read {}, so an MCP server started there would not be seen.",
                unread.join(", ")
            ),
        ));
    } else {
        report.passed.push(Verified::new(MCP_UNPINNED, &[], scope));
    }
}

#[track_caller]
fn mcp_finding(file: &str, line: usize, launch: &Launch) -> Finding {
    let (how, fix) = if launch.launcher == "docker" {
        (
            format!("the Docker image `{}` with no digest", launch.package),
            "Name the image by its digest (`image@sha256:…`, from `docker buildx imagetools inspect` \
             or the registry page), and change it on purpose when you upgrade.",
        )
    } else {
        (
            format!(
                "`{}` with no exact version, through `{}`",
                launch.package, launch.launcher
            ),
            "Name an exact version (`package@1.2.3` for npx, `package==1.2.3` for uvx), or better, \
             add the server to the app's own dependencies and lockfile so its version and checksum \
             are recorded and checked on install.",
        )
    };
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "config.mcp-server-unpinned".into(),
        title:
            "An MCP server is downloaded fresh, at whatever version is newest, every time it starts"
                .into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        location: Location {
            file: file.to_owned(),
            line,
        },
        secret: None,
        requirement_ids: vec!["C10.1.1".into()],
        cwe: vec!["CWE-494".into(), "CWE-829".into()],
        description: format!(
            "This starts an MCP server from {how}. Each start downloads whatever was published last, \
             and nothing checks it is the code that was reviewed."
        ),
        impact:
            "If the package or image is taken over or replaced, the next start runs the new code \
                 with the app's access to its tools and data, and nothing records that it changed."
                .into(),
        fix: fix.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-launch-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(dir: &std::path::Path) -> ConfigReport {
        let mut report = ConfigReport::default();
        check(&Listing::of(dir), &mut report);
        report
    }

    fn found<'a>(report: &'a ConfigReport, id: &str) -> Vec<&'a Finding> {
        report.findings.iter().filter(|f| f.rule_id == id).collect()
    }

    #[test]
    fn a_command_that_runs_the_apps_own_python_file_says_the_file_decides() {
        // Gap analysis 1.9: `python app.py` passed as "none starts a development server" when
        // `app.py` could start Flask's debugger.
        let dir = scratch("own-file");
        fs::write(
            dir.join("Dockerfile"),
            "FROM python:3.12-slim\nCMD [\"python\", \"-u\", \"app.py\"]\n",
        )
        .unwrap();
        let report = run(&dir);
        assert!(
            found(&report, DEV_SERVER).is_empty(),
            "{:?}",
            report.findings
        );
        let passed = report
            .passed
            .iter()
            .find(|v| v.check_id == DEV_SERVER)
            .expect("a reading");
        assert!(passed.requirement_ids.is_empty());
        assert!(
            passed.scope.contains("`app.py` runs the app's own code")
                && passed.scope.contains("ast.debug-mode-on"),
            "{}",
            passed.scope
        );
    }

    #[test]
    fn a_development_server_in_the_last_stage_is_found_and_a_production_one_is_not() {
        let dir = scratch("dev-server");
        // The control: a production server, in a Dockerfile whose build stage ran the dev tools.
        fs::write(
            dir.join("Dockerfile"),
            "FROM node:22 AS build\nENV NODE_ENV=development\nRUN npm ci && npm run build\nCMD [\"npm\", \"run\", \"dev\"]\n\n\
             FROM node:22-slim\n# the server\nCMD [\"node\", \"server.js\"]\n",
        )
        .unwrap();
        let clean = run(&dir);
        assert!(found(&clean, DEV_SERVER).is_empty(), "{:?}", clean.findings);
        let passed = clean
            .passed
            .iter()
            .find(|v| v.check_id == DEV_SERVER)
            .expect("a clean reading");
        assert!(
            passed.requirement_ids.is_empty(),
            "a clean reading credits nothing"
        );
        // `node server.js` runs the app's own file, which decides for itself; the reading says so
        // rather than that nothing starts a development server (gap analysis 1.9).
        assert!(
            passed.scope.contains("`server.js` runs the app's own code"),
            "{}",
            passed.scope
        );
        assert!(!passed.scope.contains("none starts"), "{}", passed.scope);

        for (dockerfile, line, words) in [
            (
                "FROM python:3.12\nCMD flask run --host 0.0.0.0\n",
                2,
                "flask run",
            ),
            (
                "FROM python:3.12\nCMD [\"uvicorn\", \"app:app\", \\\n  \"--reload\"]\n",
                2,
                "--reload",
            ),
            (
                "FROM python:3.12\nENTRYPOINT [\"python\"]\nCMD [\"manage.py\", \"runserver\", \"0:8000\"]\n",
                3,
                "runserver",
            ),
            (
                "FROM node:22\nENV NODE_ENV development\nCMD [\"node\", \"server.js\"]\n",
                2,
                "NODE_ENV",
            ),
            ("FROM node:22\nCMD npx \\\n  next dev\n", 2, "next dev"),
        ] {
            fs::write(dir.join("Dockerfile"), dockerfile).unwrap();
            let report = run(&dir);
            let hits = found(&report, DEV_SERVER);
            assert_eq!(hits.len(), 1, "{dockerfile}: {:?}", report.findings);
            assert_eq!(hits[0].location.line, line, "{dockerfile}");
            assert!(
                hits[0].description.contains(words),
                "{dockerfile}: {}",
                hits[0].description
            );
            assert_eq!(hits[0].requirement_ids, ["V15.2.3"]);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn npm_start_is_followed_into_package_json() {
        let dir = scratch("npm-start");
        fs::write(
            dir.join("Procfile"),
            "release: npm run migrate\nweb: npm start\n",
        )
        .unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"scripts": {"start": "next start", "dev": "next dev"}}"#,
        )
        .unwrap();
        assert!(
            found(&run(&dir), DEV_SERVER).is_empty(),
            "`next start` is the production server"
        );
        fs::write(
            dir.join("package.json"),
            r#"{"scripts": {"start": "nodemon index.js"}}"#,
        )
        .unwrap();
        let report = run(&dir);
        let hits = found(&report, DEV_SERVER);
        assert_eq!(hits.len(), 1, "{:?}", report.findings);
        assert_eq!(
            (hits[0].location.file.as_str(), hits[0].location.line),
            ("Procfile", 2)
        );
        assert!(
            hits[0].description.contains("`start` script"),
            "{}",
            hits[0].description
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_named_for_development_is_left_out_and_nothing_to_read_is_not_a_pass() {
        let dir = scratch("dev-named");
        fs::create_dir_all(dir.join(".devcontainer")).unwrap();
        fs::write(
            dir.join("Dockerfile.dev"),
            "FROM node:22\nCMD npm run dev\n",
        )
        .unwrap();
        fs::write(
            dir.join(".devcontainer/Dockerfile"),
            "FROM node:22\nCMD npm run dev\n",
        )
        .unwrap();
        let report = run(&dir);
        assert!(
            found(&report, DEV_SERVER).is_empty(),
            "{:?}",
            report.findings
        );
        assert!(report.passed.iter().all(|v| v.check_id != DEV_SERVER));
        assert!(
            report
                .not_assessed
                .iter()
                .any(|(id, why)| id == DEV_SERVER && why.contains("no Dockerfile")),
            "{:?}",
            report.not_assessed
        );
        // The control: the same file under a production name is found.
        fs::write(dir.join("Dockerfile"), "FROM node:22\nCMD npm run dev\n").unwrap();
        assert_eq!(found(&run(&dir), DEV_SERVER).len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn what_each_launcher_starts_and_whether_it_is_pinned() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        type Case<'a> = (&'a str, &'a str, Option<(&'a str, bool)>);
        let cases: &[Case] = &[
            (
                "npx",
                "-y @modelcontextprotocol/server-github",
                Some(("@modelcontextprotocol/server-github", false)),
            ),
            (
                "npx",
                "-y @modelcontextprotocol/server-github@2025.4.8",
                Some(("@modelcontextprotocol/server-github@2025.4.8", true)),
            ),
            (
                "npx",
                "-y mcp-remote@latest https://example.com/mcp",
                Some(("mcp-remote@latest", false)),
            ),
            (
                "npx",
                "--yes --package=mcp-server@1.2.3 mcp-server",
                Some(("mcp-server@1.2.3", true)),
            ),
            (
                "npx",
                "-y mcp-server@^1.2.0",
                Some(("mcp-server@^1.2.0", false)),
            ),
            ("npx", "./servers/local.js", None),
            ("pnpm", "dlx mcp-server", Some(("mcp-server", false))),
            ("pnpm", "run mcp", None),
            ("uvx", "mcp-server-fetch", Some(("mcp-server-fetch", false))),
            (
                "uvx",
                "mcp-server-fetch==2025.1.17",
                Some(("mcp-server-fetch==2025.1.17", true)),
            ),
            (
                "uvx",
                "--from mcp-server-git==1.0.0 mcp-server-git",
                Some(("mcp-server-git==1.0.0", true)),
            ),
            (
                "uvx",
                "--python 3.12 mcp-server-time",
                Some(("mcp-server-time", false)),
            ),
            (
                "pipx",
                "run mcp-server-time",
                Some(("mcp-server-time", false)),
            ),
            (
                "docker",
                "run -i --rm -e GITHUB_TOKEN ghcr.io/github/github-mcp-server",
                Some(("ghcr.io/github/github-mcp-server", false)),
            ),
            (
                "docker",
                &format!(
                    "run -i --rm ghcr.io/github/github-mcp-server@sha256:{}",
                    "a".repeat(64)
                ),
                Some(("", true)),
            ),
            ("docker", "ps", None),
        ];
        for (launcher, line, want) in cases {
            let got = launch_of(launcher, &args(line));
            match want {
                None => assert_eq!(got, None, "{launcher} {line}"),
                Some((package, pinned)) => {
                    let got = got.unwrap_or_else(|| panic!("{launcher} {line} started nothing"));
                    if !package.is_empty() {
                        assert_eq!(got.package, *package, "{launcher} {line}");
                    }
                    assert_eq!(got.pinned, *pinned, "{launcher} {line}");
                }
            }
        }
    }

    fn large_data(dir: &std::path::Path, name: &str, extra: &str) {
        fs::write(
            dir.join(name),
            format!("{{\"text\": \"{}{extra}\"}}\n", "y".repeat(3 * 1024 * 1024)),
        )
        .unwrap();
    }

    #[test]
    fn a_large_data_file_that_never_says_command_does_not_block_the_mcp_check() {
        // cato-pipeline's catalog: 10 MB of standards text in a JSON file. Before, the check could
        // not read it, and so could never pass for the whole app.
        let dir = scratch("mcp-large");
        fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
        large_data(&dir, "catalog.json", "");
        let listing = Listing::of(&dir);
        assert!(
            listing
                .files
                .iter()
                .any(|f| f.relative == "catalog.json" && f.too_large()),
            "the setup: the catalog is over the limit"
        );
        let report = run(&dir);
        assert!(
            !report.not_assessed.iter().any(|(id, _)| id == MCP_UNPINNED),
            "{:?}",
            report.not_assessed
        );
        let passed = report
            .passed
            .iter()
            .find(|v| v.check_id == MCP_UNPINNED)
            .expect("a clean reading");
        assert!(
            passed.scope.starts_with("2 files"),
            "both files count: {}",
            passed.scope
        );

        // The word in prose, as the NIST catalog uses it: still read, and still clean.
        large_data(
            &dir,
            "catalog.json",
            " the command and control of the system ",
        );
        let report = run(&dir);
        assert!(
            !report.not_assessed.iter().any(|(id, _)| id == MCP_UNPINNED),
            "the word alone kept the check from running: {:?}",
            report.not_assessed
        );
        assert!(report.passed.iter().any(|v| v.check_id == MCP_UNPINNED));

        // A command that starts a server: the file stays unread and says why.
        large_data(&dir, "catalog.json", r#"", "command": "npx"#);
        let report = run(&dir);
        let (_, why) = report
            .not_assessed
            .iter()
            .find(|(id, _)| id == MCP_UNPINNED)
            .expect("not assessed, and named");
        assert!(
            why.contains("`catalog.json` (larger than 2 MB, and it sets `command` to a program"),
            "{why}"
        );

        // And a large data file beside the app's own unpinned server hides nothing.
        large_data(&dir, "catalog.json", "");
        fs::write(
            dir.join("mcp_config.json"),
            r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}"#,
        )
        .unwrap();
        let report = run(&dir);
        fs::remove_dir_all(&dir).ok();
        assert_eq!(
            found(&report, MCP_UNPINNED).len(),
            1,
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn a_plain_http_mcp_link_to_another_computer_is_found_and_nothing_local_is() {
        // ADR-068, C10.3.1.
        let dir = scratch("mcp-plain");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("docs")).unwrap();
        // Found: a transport opened in TypeScript and in Python, and a server's address in the
        // app's configuration, each written its own way.
        fs::write(
            dir.join("src/client.ts"),
            "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n\
             const transport = new StreamableHTTPClientTransport(new URL(\"http://tools.example.com/mcp\"));\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/agent.py"),
            "async with streamablehttp_client('http://203.0.113.5:8000/mcp') as (read, write, _):\n    pass\n",
        )
        .unwrap();
        fs::write(
            dir.join("mcp_config.json"),
            "{\"mcpServers\": {\n  \"remote\": {\"serverUrl\": \"http://mcp.example.org/mcp\"}\n}}\n",
        )
        .unwrap();
        // Not found: encrypted; this computer; a service on the app's own network; a private
        // address; an address built at run time; a link in a file that says nothing of MCP; and the
        // AI coding tool's own file, which is ADR-049's.
        fs::write(
            dir.join("src/fine.ts"),
            "const a = new StreamableHTTPClientTransport(new URL('https://tools.example.com/mcp'));\n\
             const b = new StreamableHTTPClientTransport(new URL('http://localhost:3001/mcp'));\n\
             const c = new SSEClientTransport(new URL('http://mcp-server:8080/sse'));\n\
             const d = new StreamableHTTPClientTransport(new URL('http://192.168.1.4/mcp'));\n\
             const e = new StreamableHTTPClientTransport(new URL('http://${MCP_HOST}/mcp'));\n\
             const f = new StreamableHTTPClientTransport(new URL('http://127.0.0.1:9000/mcp'));\n\
             const g = new StreamableHTTPClientTransport(new URL('http://tools.localhost/mcp'));\n\
             const h = new StreamableHTTPClientTransport(new URL('http://host.docker.internal/mcp'));\n",
        )
        .unwrap();
        fs::write(
            dir.join("docs/links.json"),
            "{\"homepage\": {\"url\": \"http://example.com/about\"}}\n",
        )
        .unwrap();
        fs::write(
            dir.join(".mcp.json"),
            "{\"mcpServers\": {\"x\": {\"url\": \"http://tools.example.com/mcp\"}}}\n",
        )
        .unwrap();
        let report = run(&dir);
        let mut hits: Vec<(String, usize)> = found(&report, MCP_PLAIN_HTTP)
            .iter()
            .map(|f| (f.location.file.clone(), f.location.line))
            .collect();
        hits.sort();
        assert_eq!(
            hits,
            [
                ("mcp_config.json".to_owned(), 2),
                ("src/agent.py".to_owned(), 1),
                ("src/client.ts".to_owned(), 2)
            ],
            "{:?}",
            report.findings
        );
        let f = found(&report, MCP_PLAIN_HTTP)[0];
        assert_eq!(f.requirement_ids, ["C10.3.1"]);
        // Only ever a finding: a clean reading credits nothing.
        for f in ["src/client.ts", "src/agent.py", "mcp_config.json"] {
            fs::remove_file(dir.join(f)).unwrap();
        }
        let clean = run(&dir);
        assert!(
            found(&clean, MCP_PLAIN_HTTP).is_empty(),
            "{:?}",
            clean.findings
        );
        assert!(
            !clean.passed.iter().any(|v| v.check_id == MCP_PLAIN_HTTP
                || v.requirement_ids.iter().any(|q| q == "C10.3.1")),
            "{:?}",
            clean.passed
        );
    }

    #[test]
    fn mcp_servers_are_read_from_configuration_and_code_and_not_from_developer_tools() {
        let dir = scratch("mcp");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join(".cursor")).unwrap();
        // The developer's own tools: not the app.
        let unpinned = r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}"#;
        fs::write(dir.join(".mcp.json"), unpinned).unwrap();
        fs::write(dir.join(".cursor/mcp.json"), unpinned).unwrap();
        // The app's own, pinned.
        fs::write(
            dir.join("src/agent.py"),
            "params = StdioServerParameters(\n    command=\"uvx\",\n    args=[\"mcp-server-fetch==2025.1.17\"],\n)\n",
        )
        .unwrap();
        let clean = run(&dir);
        assert!(
            found(&clean, MCP_UNPINNED).is_empty(),
            "{:?}",
            clean.findings
        );
        let passed = clean
            .passed
            .iter()
            .find(|v| v.check_id == MCP_UNPINNED)
            .expect("a clean reading");
        assert!(
            passed.requirement_ids.is_empty(),
            "a pinned version is not C10.1.1's verification"
        );
        assert!(
            passed.scope.contains("mcp-server-fetch==2025.1.17"),
            "{}",
            passed.scope
        );

        // Unpinned, in the app's own configuration and code, each written its own way.
        fs::write(dir.join("mcp_config.json"), unpinned).unwrap();
        fs::write(
            dir.join("src/client.ts"),
            "const transport = new StdioClientTransport({\n  args: ['mcp-server-time'],\n  command: 'uvx',\n});\n",
        )
        .unwrap();
        fs::write(
            dir.join("servers.toml"),
            "[servers.web]\ncommand = \"npx -y mcp-remote@latest\"\n",
        )
        .unwrap();
        let report = run(&dir);
        let mut hits: Vec<(String, usize)> = found(&report, MCP_UNPINNED)
            .iter()
            .map(|f| (f.location.file.clone(), f.location.line))
            .collect();
        hits.sort();
        assert_eq!(
            hits,
            [
                ("mcp_config.json".to_owned(), 1),
                ("servers.toml".to_owned(), 2),
                ("src/client.ts".to_owned(), 3)
            ],
            "{:?}",
            report.findings
        );
        assert!(
            found(&report, MCP_UNPINNED)
                .iter()
                .all(|f| f.requirement_ids == ["C10.1.1"])
        );
        fs::remove_dir_all(&dir).ok();
    }
}
