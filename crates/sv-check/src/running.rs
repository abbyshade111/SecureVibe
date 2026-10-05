//! Four more questions for the running app, from the partial-check review of 28 September 2026
//! (`docs/PARTIAL-CHECKS.md`). Each can show its requirement failing and never settle it, so a
//! clean answer credits nothing and says what was asked.
//!
//! - V10.4.4: the sign-in server's published settings offer the password or implicit grant, which
//!   the requirement says must no longer be used. Which grants each client may use is not published,
//!   so nothing is claimed about that.
//! - V8.4.2: an admin page that is shut to a stranger opens when the request says it came from the
//!   app's own computer (`X-Forwarded-For: 127.0.0.1`). Network location is then the only thing
//!   guarding it, which is what the requirement says it must not be.
//! - V13.4.7: files that are in the app's folder and should never be served (settings, keys,
//!   source code, databases, backups) handed back when asked for by name. Judged by the file's own
//!   contents, so a page that answers every address is not mistaken for one.
//! - V16.5.4: the app stopped, restarted, or stopped answering during the questions, so something
//!   it was sent took the whole process down and no last-resort error handler caught it.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::probes::{ProbeRequest, ProbeResponse};
use crate::verified::Verified;
use sv_scan::files::Listing;

pub const GRANTS: &str = "probe.retired-grants-offered";
pub const ADMIN_BY_ADDRESS: &str = "probe.admin-opened-by-address";
pub const PRIVATE_FILES: &str = "probe.private-files-served";
pub const STAYED_UP: &str = "probe.app-stopped-during-questions";

/// Where a sign-in server publishes its settings (OpenID Connect Discovery, RFC 8414).
const DISCOVERY: &[(&str, &str)] = &[
    ("discovery-openid", "/.well-known/openid-configuration"),
    ("discovery-oauth", "/.well-known/oauth-authorization-server"),
];

/// Headers a proxy sets to say where a request came from, each saying "this computer".
const FROM_HERE: &[(&str, &str)] = &[
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1"),
];

/// At most this many admin pages are asked about, and this many private files.
const ADMIN_PAGES: usize = 5;
const FILES: usize = 16;

/// Folders a web server is commonly pointed at, so a file inside one is also asked for without it.
const SERVED_FOLDERS: &[&str] = &[
    "public", "static", "www", "wwwroot", "htdocs", "dist", "build",
];

/// A file in the app's folder that should never be served, and the addresses it is asked for at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateFile {
    /// The file, from the app folder.
    pub file: String,
    /// What kind of file it is, in words.
    pub kind: &'static str,
    /// Whether serving it hands out keys or passwords.
    pub secret: bool,
    /// The probe id and path of each request for it.
    pub asked: Vec<(String, String)>,
    /// The start of the file, which a response must contain to count as serving it. Never shown.
    head: String,
}

/// What the app looked like after a stage of the questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Liveness {
    /// Which questions had been asked by then, in words: "the questions asked as somebody not
    /// signed in".
    pub after: String,
    /// `docker inspect`'s state: `running`, `exited`, `restarting`, and so on. Empty when it could
    /// not be read.
    pub status: String,
    pub restarts: u32,
    pub exit_code: i32,
    /// Stopped by the computer for using too much memory, which says nothing about error handling.
    pub out_of_memory: bool,
    /// Whether the health path answered.
    pub answered: bool,
}

/// What kind of private file a path is, or `None` for a file that may be meant to be served.
fn private_kind(relative: &str) -> Option<(&'static str, bool, u8)> {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    let lower = name.to_lowercase();
    let extension = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if (lower == ".env" || lower.starts_with(".env."))
        && !["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|w| lower.contains(w))
    {
        return Some((
            "a settings file of the kind that holds keys and passwords",
            true,
            0,
        ));
    }
    if matches!(extension, "pem" | "key") {
        return Some(("a key or certificate file", true, 0));
    }
    if matches!(extension, "sql" | "bak" | "old" | "orig" | "swp" | "log") || lower.ends_with('~') {
        return Some(("a database dump, backup, or log", false, 1));
    }
    if matches!(
        lower.as_str(),
        "securevibe.toml"
            | "package.json"
            | "composer.json"
            | "requirements.txt"
            | "pyproject.toml"
            | "gemfile"
            | "dockerfile"
            | "docker-compose.yml"
            | "compose.yaml"
            | "settings.py"
            | "config.php"
            | "wp-config.php"
            | "appsettings.json"
            | "web.config"
    ) {
        return Some(("a file describing how the app is built or set up", false, 2));
    }
    if matches!(
        extension,
        "py" | "rb" | "php" | "go" | "java" | "cs" | "rs" | "kt" | "ex" | "exs" | "pl"
    ) {
        return Some(("the app's server code", false, 3));
    }
    None
}

/// A path that can go in a request line as it is.
fn plain_path(relative: &str) -> bool {
    relative
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'/'))
}

/// The private files to ask for: settings and keys first, then dumps and backups, then build
/// files, then server code, shallow paths before deep ones, at most `FILES`.
///
/// A file whose start is too short or too plain to recognize in an answer is left out: a match on
/// ten characters could be anything.
pub fn private_files(listing: &Listing) -> Vec<PrivateFile> {
    let mut candidates: Vec<(u8, usize, &str, &'static str, bool)> = listing
        .app_files()
        .filter(|f| plain_path(&f.relative) && !f.too_large())
        .filter_map(|f| {
            let (kind, secret, rank) = private_kind(&f.relative)?;
            Some((
                rank,
                f.relative.matches('/').count(),
                f.relative.as_str(),
                kind,
                secret,
            ))
        })
        .collect();
    candidates.sort();
    let mut out = Vec::new();
    for (_, _, relative, kind, secret) in candidates {
        if out.len() == FILES {
            break;
        }
        let Some(entry) = listing.app_files().find(|f| f.relative == relative) else {
            continue;
        };
        let Ok(text) = entry.read_text() else {
            continue;
        };
        let head: String = text
            .replace("\r\n", "\n")
            .trim()
            .chars()
            .take(200)
            .collect();
        if head.chars().filter(|c| !c.is_whitespace()).count() < 24 {
            continue;
        }
        let n = out.len();
        let mut asked = vec![(format!("private-{n}"), format!("/{relative}"))];
        if let Some((folder, rest)) = relative.split_once('/')
            && SERVED_FOLDERS.contains(&folder)
        {
            asked.push((format!("private-{n}-served"), format!("/{rest}")));
        }
        out.push(PrivateFile {
            file: relative.to_owned(),
            kind,
            secret,
            asked,
            head,
        });
    }
    out
}

fn get(id: String, path: String, headers: Vec<(String, String)>) -> ProbeRequest {
    ProbeRequest {
        id,
        method: "GET".into(),
        path,
        headers,
        body: None,
    }
}

/// The requests these four checks make, all as somebody not signed in.
pub fn requests(admin_pages: &[String], private: &[PrivateFile]) -> Vec<ProbeRequest> {
    let mut out: Vec<ProbeRequest> = DISCOVERY
        .iter()
        .map(|(id, path)| get((*id).to_owned(), (*path).to_owned(), Vec::new()))
        .collect();
    for (i, page) in admin_pages.iter().take(ADMIN_PAGES).enumerate() {
        out.push(get(format!("admin-{i}"), page.clone(), Vec::new()));
        out.push(get(
            format!("admin-{i}-from-here"),
            page.clone(),
            FROM_HERE
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
        ));
    }
    for file in private {
        for (id, path) in &file.asked {
            out.push(get(id.clone(), path.clone(), Vec::new()));
        }
    }
    out
}

/// What these checks found, what they looked at and found nothing, and what they could not judge.
#[derive(Debug, Default)]
pub struct Evidence {
    pub findings: Vec<Finding>,
    pub verified: Vec<Verified>,
    pub not_assessed: Vec<(String, String)>,
}

pub fn evaluate(
    responses: &[ProbeResponse],
    admin_pages: &[String],
    private: &[PrivateFile],
    liveness: &[Liveness],
) -> Evidence {
    let mut out = Evidence::default();
    grants(responses, &mut out);
    admin_by_address(responses, admin_pages, &mut out);
    private_files_served(responses, private, &mut out);
    stayed_up(liveness, &mut out);
    out
}

/// What is fixed about a check: everything except the words describing this answer.
struct About {
    rule_id: &'static str,
    requirement: &'static str,
    cwe: &'static [&'static str],
    impact: &'static str,
    fix: &'static str,
}

fn finding(about: &About, title: &str, severity: Severity, description: String) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        rule_id: about.rule_id.to_owned(),
        title: title.to_owned(),
        severity,
        confidence: Confidence::High,
        location: Location::running_app(),
        secret: None,
        requirement_ids: vec![about.requirement.to_owned()],
        cwe: about.cwe.iter().map(|c| (*c).to_owned()).collect(),
        description,
        impact: about.impact.to_owned(),
        fix: about.fix.to_owned(),
    }
}

const RETIRED_GRANTS_OFFERED_ABOUT: About = About {
    rule_id: "probe.retired-grants-offered",
    requirement: "V10.4.4",
    cwe: &["CWE-522", "CWE-598"],
    impact: "An app using the password grant sees every user's password, and a token sent the implicit \
         way can be read by anything that sees the address. Both are why V10.4.4 says they must no \
         longer be used.",
    fix: "Turn both off in the sign-in server's settings and use the authorization code grant with \
         PKCE instead, for every client. If a client still needs one of them, move it off first.",
};

const ADMIN_OPENED_BY_ADDRESS_ABOUT: About = About {
    rule_id: "probe.admin-opened-by-address",
    requirement: "V8.4.2",
    cwe: &["CWE-290", "CWE-348"],
    impact: "Anyone on the internet can add those headers, so the admin pages are open to anyone who \
         thinks to. Where the request came from is the only thing guarding them.",
    fix: "Require an admin to be signed in, and checked as an admin, on every admin page, whatever \
         address the request says it came from. If the app sits behind a proxy, trust the \
         forwarding headers only from that proxy (for example Express's `trust proxy` set to its \
         address, or Werkzeug's `ProxyFix` with the number of proxies).",
};

const PRIVATE_FILES_SERVED_ABOUT: About = About {
    rule_id: "probe.private-files-served",
    requirement: "V13.4.7",
    cwe: &["CWE-538", "CWE-552"],
    impact: "Anyone can download them. A settings file or key hands over the passwords and keys in it; \
         server code shows exactly where to look for weaknesses; a dump or backup can hold every \
         user's data.",
    fix: "Serve one folder that holds only the files meant for the browser (for example `public/`), \
         not the app's own folder, and keep settings, keys, and code outside it. If a key was served, \
         treat it as known to others: replace it.",
};

const APP_STOPPED_DURING_QUESTIONS_ABOUT: About = About {
    rule_id: "probe.app-stopped-during-questions",
    requirement: "V16.5.4",
    cwe: &["CWE-248", "CWE-755"],
    impact: "Anyone who sends the same request can stop the app for everyone, as often as they like, \
         and the error that did it may never reach the logs.",
    fix: "Add a last-resort error handler that catches every error a request raises, logs it, and \
         answers with a plain error page (Express: an error middleware with four arguments; Flask: \
         `@app.errorhandler(Exception)`; FastAPI: `@app.exception_handler(Exception)`; Node.js: \
         `process.on('uncaughtException')` to log before exiting). Then find the request that \
         stopped it and fix that too.",
};

fn found<'a>(responses: &'a [ProbeResponse], id: &str) -> Option<&'a ProbeResponse> {
    responses.iter().find(|r| r.id == id)
}

// V10.4.4 -----------------------------------------------------------------------------------------

fn words(document: &serde_json::Value, field: &str) -> Vec<String> {
    document
        .get(field)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn grants(responses: &[ProbeResponse], out: &mut Evidence) {
    let mut published = Vec::new();
    let mut retired = Vec::new();
    for (id, path) in DISCOVERY {
        let Some(r) = found(responses, id) else {
            continue;
        };
        if !(200..300).contains(&r.status) {
            continue;
        }
        let Ok(document) = serde_json::from_str::<serde_json::Value>(r.body.trim()) else {
            continue;
        };
        // A sign-in server's settings name who issues its tokens; any other JSON at this address
        // is not one.
        if document.get("issuer").and_then(|v| v.as_str()).is_none() {
            continue;
        }
        published.push(*path);
        for grant in words(&document, "grant_types_supported") {
            if grant == "password" || grant == "implicit" {
                retired.push(format!("`{grant}` in `grant_types_supported` at {path}"));
            }
        }
        for response_type in words(&document, "response_types_supported") {
            if response_type.split_whitespace().any(|w| w == "token") {
                retired.push(format!(
                    "`{response_type}` in `response_types_supported` at {path}"
                ));
            }
        }
    }
    if published.is_empty() {
        return;
    }
    retired.dedup();
    if retired.is_empty() {
        out.verified.push(Verified::new(
            GRANTS,
            &[],
            format!(
                "the sign-in settings the app publishes at {}: neither the password grant nor the \
                 implicit grant is offered; which grants each client may use is not published, and \
                 a settings file that leaves `grant_types_supported` out says nothing either way",
                published.join(" and ")
            ),
        ));
        return;
    }
    out.findings.push(finding(
        &RETIRED_GRANTS_OFFERED_ABOUT,
        "The app's sign-in server offers sign-in methods that must no longer be used",
        Severity::High,
        format!(
            "The app publishes the settings of a sign-in server (OAuth or OpenID Connect), and they \
             offer {}. The password grant has each app collect people's passwords itself; the \
             implicit grant sends access tokens in the address bar, where browser history, logs, \
             and other pages can read them.",
            retired.join("; ")
        ),
    ));
}

// V8.4.2 ------------------------------------------------------------------------------------------

fn admin_by_address(responses: &[ProbeResponse], admin_pages: &[String], out: &mut Evidence) {
    let mut asked = 0;
    let mut opened = Vec::new();
    for (i, page) in admin_pages.iter().take(ADMIN_PAGES).enumerate() {
        let (Some(plain), Some(from_here)) = (
            found(responses, &format!("admin-{i}")),
            found(responses, &format!("admin-{i}-from-here")),
        ) else {
            continue;
        };
        asked += 1;
        let shut = !(200..300).contains(&plain.status);
        let open = (200..300).contains(&from_here.status);
        if shut && open {
            opened.push(format!(
                "{page} ({} without, {} with)",
                plain.status, from_here.status
            ));
        }
    }
    if asked == 0 {
        return;
    }
    if opened.is_empty() {
        out.verified.push(Verified::new(
            ADMIN_BY_ADDRESS,
            &[],
            format!(
                "{asked} admin page{} asked for as a stranger, with and without headers saying \
                 the request came from the app's own computer: the headers opened none; what else \
                 guards them is not something a request shows",
                if asked == 1 { "" } else { "s" }
            ),
        ));
        return;
    }
    out.findings.push(finding(
        &ADMIN_OPENED_BY_ADDRESS_ABOUT,
        "An admin page opens for anyone who says they are on the app's own computer",
        Severity::High,
        format!(
            "Asked for by somebody not signed in, {} refused; asked again with `X-Forwarded-For`, \
             `X-Real-IP`, and `Forwarded` headers saying the request came from 127.0.0.1, it \
             answered. Those headers are written by whoever sends the request.",
            opened.join(", ")
        ),
    ));
}

// V13.4.7 -----------------------------------------------------------------------------------------

fn private_files_served(responses: &[ProbeResponse], private: &[PrivateFile], out: &mut Evidence) {
    let mut answered = 0;
    let mut served = Vec::new();
    for file in private {
        let mut any = false;
        for (id, path) in &file.asked {
            let Some(r) = found(responses, id) else {
                continue;
            };
            any = true;
            // The file's own opening, in the answer: a page that answers every address with the
            // same thing does not contain it.
            if (200..300).contains(&r.status) && r.body.replace("\r\n", "\n").contains(&file.head) {
                served.push((file, path.as_str()));
                break;
            }
        }
        if any {
            answered += 1;
        }
    }
    if answered == 0 {
        return;
    }
    if served.is_empty() {
        out.verified.push(Verified::new(
            PRIVATE_FILES,
            &[],
            format!(
                "{answered} file{} from the app's folder that should never be served, asked for by \
                 name: none was handed back; other files, and other names for them, were not asked for",
                if answered == 1 { "" } else { "s" }
            ),
        ));
        return;
    }
    let secret = served.iter().any(|(f, _)| f.secret);
    out.findings.push(finding(
        &PRIVATE_FILES_SERVED_ABOUT,
        "The app hands out files from its folder that should never be served",
        if secret { Severity::Critical } else { Severity::Medium },
        format!(
            "Asked for by name by somebody not signed in, the app answered with the contents of {}. \
             What they hold is not repeated here.",
            served
                .iter()
                .map(|(f, path)| format!("`{}` ({}) at {path}", f.file, f.kind))
                .collect::<Vec<_>>()
                .join("; ")
        ),
    ));
}

// V16.5.4 -----------------------------------------------------------------------------------------

fn stayed_up(liveness: &[Liveness], out: &mut Evidence) {
    if liveness.is_empty() {
        return;
    }
    if let Some(l) = liveness.iter().find(|l| l.status.is_empty()) {
        out.not_assessed.push((
            STAYED_UP.to_owned(),
            format!(
                "After {}, `sv` could not read whether the app's container was still running.",
                l.after
            ),
        ));
        return;
    }
    let Some(stopped) = liveness
        .iter()
        .find(|l| l.status != "running" || l.restarts > 0 || !l.answered)
    else {
        out.verified.push(Verified::new(
            STAYED_UP,
            &[],
            format!(
                "the app was still running and answering after {}; questions it was not asked may \
                 still stop it",
                liveness.last().map_or("", |l| l.after.as_str())
            ),
        ));
        return;
    };
    if stopped.out_of_memory {
        out.not_assessed.push((
            STAYED_UP.to_owned(),
            format!(
                "The app's container was stopped for using too much memory during {}. That says \
                 how much memory it was given, not how it handles errors.",
                stopped.after
            ),
        ));
        return;
    }
    let what = if stopped.status != "running" && stopped.status != "restarting" {
        format!(
            "had stopped (its container is `{}`, exit code {})",
            stopped.status, stopped.exit_code
        )
    } else if stopped.restarts > 0 || stopped.status == "restarting" {
        format!("had restarted {} time(s)", stopped.restarts.max(1))
    } else {
        "was running and no longer answered its health path".to_owned()
    };
    out.findings.push(finding(
        &APP_STOPPED_DURING_QUESTIONS_ABOUT,
        "Something the app was sent stopped it",
        Severity::Medium,
        format!(
            "The app answered when the run began, and after {} it {what}. One of the requests in \
             that stage raised an error nothing caught, and it took the whole app down. The app's \
             own output (`sv run` shows where) says which.",
            stopped.after
        ),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn answer(id: &str, status: u16, body: &str) -> ProbeResponse {
        ProbeResponse {
            id: id.to_owned(),
            status,
            headers: Vec::new(),
            body: body.to_owned(),
        }
    }

    fn ids(evidence: &Evidence) -> Vec<&str> {
        evidence
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect()
    }

    fn verified(evidence: &Evidence, id: &str) -> bool {
        evidence
            .verified
            .iter()
            .any(|v| v.check_id == id && v.requirement_ids.is_empty())
    }

    #[test]
    fn a_published_password_or_implicit_grant_is_found_and_a_code_only_server_is_not() {
        let code_only = r#"{"issuer": "http://app", "grant_types_supported": ["authorization_code", "refresh_token"], "response_types_supported": ["code", "id_token"]}"#;
        let clean = evaluate(&[answer("discovery-openid", 200, code_only)], &[], &[], &[]);
        assert!(clean.findings.is_empty(), "{:?}", clean.findings);
        assert!(verified(&clean, GRANTS));

        for document in [
            r#"{"issuer": "http://app", "grant_types_supported": ["authorization_code", "password"]}"#,
            r#"{"issuer": "http://app", "grant_types_supported": ["implicit"]}"#,
            r#"{"issuer": "http://app", "response_types_supported": ["code", "id_token token"]}"#,
        ] {
            let found = evaluate(&[answer("discovery-oauth", 200, document)], &[], &[], &[]);
            assert_eq!(ids(&found), [GRANTS], "{document}");
            assert_eq!(found.findings[0].requirement_ids, ["V10.4.4"]);
            assert!(found.verified.is_empty());
        }
        // Not a sign-in server's settings: JSON with no issuer, or a page that answers everything.
        for (status, body) in [
            (200, r#"{"grant_types_supported": ["password"]}"#),
            (200, "<html>app</html>"),
            (404, ""),
        ] {
            let other = evaluate(&[answer("discovery-openid", status, body)], &[], &[], &[]);
            assert!(
                other.findings.is_empty() && other.verified.is_empty(),
                "{body}"
            );
        }
    }

    #[test]
    fn an_admin_page_opened_by_a_forwarding_header_is_found_and_one_shut_either_way_is_not() {
        let pages = vec!["/admin".to_owned(), "/admin/users".to_owned()];
        let asked = requests(&pages, &[]);
        let from_here = asked.iter().find(|r| r.id == "admin-0-from-here").unwrap();
        assert!(
            from_here
                .headers
                .iter()
                .any(|(n, v)| n == "X-Forwarded-For" && v == "127.0.0.1")
        );
        assert!(
            asked
                .iter()
                .find(|r| r.id == "admin-0")
                .unwrap()
                .headers
                .is_empty()
        );

        let shut = [
            answer("admin-0", 302, ""),
            answer("admin-0-from-here", 302, ""),
            answer("admin-1", 403, ""),
            answer("admin-1-from-here", 403, ""),
        ];
        let clean = evaluate(&shut, &pages, &[], &[]);
        assert!(clean.findings.is_empty());
        assert!(verified(&clean, ADMIN_BY_ADDRESS));

        let mut opened = shut.to_vec();
        opened[3] = answer("admin-1-from-here", 200, "<h1>Users</h1>");
        let found = evaluate(&opened, &pages, &[], &[]);
        assert_eq!(ids(&found), [ADMIN_BY_ADDRESS]);
        assert_eq!(found.findings[0].requirement_ids, ["V8.4.2"]);
        assert!(
            found.findings[0]
                .description
                .contains("/admin/users (403 without, 200 with)")
        );

        // Open to everyone: not this check's finding, since the header decided nothing.
        let open = [
            answer("admin-0", 200, "x"),
            answer("admin-0-from-here", 200, "x"),
        ];
        assert!(evaluate(&open, &pages[..1], &[], &[]).findings.is_empty());
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-running-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn private_files_are_chosen_from_the_folder_and_found_only_by_their_own_contents() {
        let dir = scratch("private");
        fs::create_dir_all(dir.join("public")).unwrap();
        // Built from pieces, so this file holds no key-shaped text.
        let settings = format!(
            "DATABASE_URL=postgres://app:{}@db/app\nSESSION_SECRET={}\n",
            "p".repeat(12),
            "s".repeat(24)
        );
        fs::write(dir.join(".env"), &settings).unwrap();
        fs::write(
            dir.join(".env.example"),
            "DATABASE_URL=postgres://user:password@localhost/app\n",
        )
        .unwrap();
        fs::write(
            dir.join("app.py"),
            "from flask import Flask\napp = Flask(__name__, static_folder='.')\n",
        )
        .unwrap();
        fs::write(
            dir.join("public/backup.sql"),
            "CREATE TABLE users (id integer primary key);\nINSERT INTO users VALUES (1);\n",
        )
        .unwrap();
        fs::write(
            dir.join("public/app.js"),
            "console.log('meant to be served, and long enough');\n",
        )
        .unwrap();
        fs::write(dir.join("notes.log"), "short\n").unwrap();
        let files = private_files(&Listing::of(&dir));
        let chosen: Vec<&str> = files.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(
            chosen,
            [".env", "public/backup.sql", "app.py"],
            "{chosen:?}"
        );
        let backup = files
            .iter()
            .find(|f| f.file == "public/backup.sql")
            .unwrap();
        let paths: Vec<&str> = backup.asked.iter().map(|(_, p)| p.as_str()).collect();
        assert_eq!(paths, ["/public/backup.sql", "/backup.sql"]);

        // An app that answers every address with its home page serves none of them.
        let everything: Vec<ProbeResponse> = requests(&[], &files)
            .iter()
            .map(|r| answer(&r.id, 200, "<!doctype html><title>App</title>"))
            .collect();
        let clean = evaluate(&everything, &[], &files, &[]);
        assert!(clean.findings.is_empty(), "{:?}", clean.findings);
        assert!(verified(&clean, PRIVATE_FILES));

        // The settings file handed back, at the root.
        let mut leaked = everything.clone();
        let env_id = &files[0].asked[0].0;
        leaked.iter_mut().find(|r| &r.id == env_id).unwrap().body = settings.clone();
        let found = evaluate(&leaked, &[], &files, &[]);
        assert_eq!(ids(&found), [PRIVATE_FILES]);
        let f = &found.findings[0];
        assert_eq!(f.requirement_ids, ["V13.4.7"]);
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.description.contains("`.env`"), "{}", f.description);
        assert!(
            !f.description.contains(&"s".repeat(24)),
            "the contents are never repeated"
        );

        // The dump, at the address a server pointed at `public/` gives it, with Windows line ends.
        let mut dumped = everything.clone();
        let served_id = &backup.asked[1].0;
        dumped.iter_mut().find(|r| &r.id == served_id).unwrap().body =
            "CREATE TABLE users (id integer primary key);\r\nINSERT INTO users VALUES (1);\r\n"
                .into();
        let found = evaluate(&dumped, &[], &files, &[]);
        assert_eq!(ids(&found), [PRIVATE_FILES]);
        assert_eq!(found.findings[0].severity, Severity::Medium);
        fs::remove_dir_all(&dir).ok();
    }

    fn up(after: &str) -> Liveness {
        Liveness {
            after: after.to_owned(),
            status: "running".into(),
            restarts: 0,
            exit_code: 0,
            out_of_memory: false,
            answered: true,
        }
    }

    #[test]
    fn an_app_that_stopped_restarted_or_went_quiet_is_found_and_one_that_stayed_up_is_not() {
        let clean = evaluate(
            &[],
            &[],
            &[],
            &[up("the first questions"), up("all the questions")],
        );
        assert!(clean.findings.is_empty());
        assert!(verified(&clean, STAYED_UP));

        let stopped = Liveness {
            status: "exited".into(),
            exit_code: 1,
            answered: false,
            ..up("all the questions")
        };
        let restarted = Liveness {
            restarts: 2,
            ..up("all the questions")
        };
        let quiet = Liveness {
            answered: false,
            ..up("all the questions")
        };
        for (l, words) in [
            (stopped, "exit code 1"),
            (restarted, "restarted 2"),
            (quiet, "no longer answered"),
        ] {
            let found = evaluate(&[], &[], &[], &[up("the first questions"), l]);
            assert_eq!(ids(&found), [STAYED_UP]);
            assert_eq!(found.findings[0].requirement_ids, ["V16.5.4"]);
            assert!(
                found.findings[0].description.contains(words),
                "{}",
                found.findings[0].description
            );
            assert!(found.verified.is_empty());
        }

        // Stopped for memory, or not readable: nothing said about error handling either way.
        let memory = Liveness {
            status: "exited".into(),
            exit_code: 137,
            out_of_memory: true,
            answered: false,
            ..up("x")
        };
        let unread = Liveness {
            status: String::new(),
            ..up("x")
        };
        for l in [memory, unread] {
            let e = evaluate(&[], &[], &[], &[l]);
            assert!(e.findings.is_empty() && e.verified.is_empty());
            assert!(e.not_assessed.iter().any(|(id, _)| id == STAYED_UP));
        }
    }
}
