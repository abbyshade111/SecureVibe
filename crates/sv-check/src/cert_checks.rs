//! V12.3.2 and V12.3.4, read from the files: one setting that switches off certificate checking for
//! every connection the app makes.
//!
//! V12.3.2 asks that the app check the certificate of every server it connects to, and V12.3.4 that
//! services inside one system trust only their own certificates. A line of code such as
//! `requests.get(url, verify=False)` breaks that for one call, and the code-reading rules and the
//! outside tools look for those. Some settings break it for every call at once, from outside the
//! code, and those are what this reads:
//!
//! - `NODE_TLS_REJECT_UNAUTHORIZED=0`: Node.js (and Bun, which honors it) then accepts any
//!   certificate on every HTTPS connection, and prints a warning saying so;
//! - `PYTHONHTTPSVERIFY=0`: Python's standard library then makes unchecked connections by default
//!   (PEP 476), for `urllib` and everything built on it;
//! - in the code, Python's `ssl._create_default_https_context = ssl._create_unverified_context`
//!   and Node's `https.globalAgent.options.rejectUnauthorized = false`, which do the same from
//!   inside;
//! - Deno's `--unsafely-ignore-certificate-errors` with no list of addresses after it.
//!
//! Each is looked for wherever it can be set: a Dockerfile, a compose file, a Kubernetes manifest, a
//! `.env` file, a workflow, a script, a `package.json` script, or the code. A setting written as a
//! name on one line and a value on the next (`- name: NODE_TLS_REJECT_UNAUTHORIZED`, then
//! `value: "0"`) is read as one. A commented-out line is not a setting, prose (Markdown, plain text)
//! is not read, and files named or kept for development or tests are left out, as the check of the
//! production start command leaves them out.
//!
//! Only ever a finding: the setting can also be made on the server the app runs on, which no file
//! shows, so finding none credits nothing. `CURL_CA_BUNDLE=""`, which the proposal lists, is not
//! looked for: whether today's `requests` skips checking for an empty value was not confirmed.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;
use regex::Regex;
use std::sync::LazyLock;
use sv_scan::files::{Listing, Unread};

pub const CHECKS_OFF: &str = "config.certificate-checks-off";

/// The environment settings that switch checking off when set to `0`.
const SETTINGS: &[(&str, &str)] = &[
    (
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "Node.js then accepts any certificate on every HTTPS connection the app makes",
    ),
    (
        "PYTHONHTTPSVERIFY",
        "Python's standard library then connects without checking certificates by default",
    ),
];

/// A setting given the value `0`, in any of the ways files write one: `NAME=0`, `ENV NAME 0`,
/// `NAME: "0"`, `process.env.NAME = '0'`, `os.environ["NAME"] = "0"`.
static SET_TO_ZERO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY)["'\]]*\s*(?:=|:|\s)\s*["']?0["']?(?:\s|$|[,;})\]])"#,
    )
    .expect("a fixed pattern")
});

/// The name on its own, as Kubernetes and some compose files write it: `- name: NAME`.
static NAME_ALONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^-?\s*name:\s*["']?(NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY)["']?\s*$"#)
        .expect("a fixed pattern")
});

/// The value line that follows it: `value: "0"`.
static VALUE_ZERO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^value:\s*["']?0["']?\s*$"#).expect("a fixed pattern"));

/// The switches written in code or on a command line, with what each does.
static SWITCHES: LazyLock<Vec<(Regex, &'static str, &'static str)>> = LazyLock::new(|| {
    [
        (
            r"\bssl\._create_default_https_context\s*=\s*(?:ssl\.)?_create_unverified_context\b",
            "`ssl._create_default_https_context = ssl._create_unverified_context`",
            "Python's standard library then connects without checking certificates by default",
        ),
        (
            r"\bhttps\.globalAgent\.options\.rejectUnauthorized\s*=\s*false\b",
            "`https.globalAgent.options.rejectUnauthorized = false`",
            "Node.js then accepts any certificate on every connection made through its default agent",
        ),
        (
            r#"--unsafely-ignore-certificate-errors(?:\s|$|["',\]])"#,
            "`--unsafely-ignore-certificate-errors` with no list of addresses",
            "Deno then accepts any certificate from any server",
        ),
    ]
    .into_iter()
    .map(|(pattern, what, does)| (Regex::new(pattern).expect("a fixed pattern"), what, does))
    .collect()
});

/// Files of prose, where a setting is described rather than made.
const PROSE: &[&str] = &["md", "markdown", "rst", "txt", "adoc"];

/// A line that is a comment in the languages and formats these settings are written in.
fn commented(line: &str) -> bool {
    let t = line.trim_start();
    ["#", "//", "/*", "*", ";", "<!--", "REM ", "rem "]
        .iter()
        .any(|p| t.starts_with(p))
}

/// Each switch-off in `text`: the line it is on (counted from `first_line`), what was written, and
/// what it does.
fn switches_in(text: &str, first_line: usize) -> Vec<(usize, String, &'static str)> {
    let mut out = Vec::new();
    let mut named: Option<&str> = None;
    for (i, line) in text.lines().enumerate() {
        let number = first_line + i;
        if commented(line) {
            continue;
        }
        let trimmed = line.trim();
        // `- name: NAME` then `value: "0"`, as a Kubernetes manifest writes it.
        if let Some(name) = named.take()
            && VALUE_ZERO.is_match(trimmed)
        {
            let does = SETTINGS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, d)| *d)
                .unwrap_or_default();
            out.push((number, format!("`{name}` set to `0`"), does));
            continue;
        }
        if let Some(c) = NAME_ALONE.captures(trimmed) {
            named = SETTINGS
                .iter()
                .map(|(n, _)| *n)
                .find(|n| *n == c.get(1).map_or("", |m| m.as_str()));
            continue;
        }
        if let Some(c) = SET_TO_ZERO.captures(line) {
            let name = c.get(1).map_or("", |m| m.as_str());
            let does = SETTINGS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, d)| *d)
                .unwrap_or_default();
            out.push((number, format!("`{name}` set to `0`"), does));
            continue;
        }
        if let Some((_, what, does)) = SWITCHES.iter().find(|(re, ..)| re.is_match(line)) {
            out.push((number, (*what).to_owned(), *does));
        }
    }
    out
}

/// Reads the app's files for the switch-offs above.
pub fn check(listing: &Listing, report: &mut ConfigReport) {
    let mut read = 0usize;
    let mut unread = Vec::new();
    let mut found = false;
    let candidates = listing.app_files().filter(|f| {
        !crate::launch::for_development(&f.relative)
            && !crate::launch::developer_tool_config(&f.relative)
            && !f
                .extension
                .as_deref()
                .is_some_and(|e| PROSE.contains(&e.to_lowercase().as_str()))
    });
    for entry in candidates {
        let mut here = Vec::new();
        match entry.read_text() {
            Ok(text) => {
                read += 1;
                here = switches_in(&text, 1);
            }
            // A file larger than 2 MB is read in pieces; a setting is one line, or two.
            Err(Unread::TooLarge) => {
                let pieces = entry.in_pieces(1024 * 1024, 4096, |piece| {
                    let own = &piece.text[..piece.keep.end];
                    for (line, what, does) in switches_in(own, piece.first_line) {
                        let start_of_own = piece.text[..piece.keep.start].lines().count();
                        if line >= piece.first_line + start_of_own
                            && !here.iter().any(|(l, ..)| *l == line)
                        {
                            here.push((line, what, does));
                        }
                    }
                });
                match pieces {
                    Ok(()) => read += 1,
                    Err(why) => {
                        unread.push(format!("`{}` ({})", entry.relative, why.explain()));
                        continue;
                    }
                }
            }
            // A file that is not text holds no setting.
            Err(Unread::NotText | Unread::NoWrittenText(_)) => continue,
            Err(why) => {
                unread.push(format!("`{}` ({})", entry.relative, why.explain()));
                continue;
            }
        }
        for (line, what, does) in here {
            found = true;
            report
                .findings
                .push(finding(&entry.relative, line, &what, does));
        }
    }
    if found {
        return;
    }
    if !unread.is_empty() {
        report.not_assessed.push((
            CHECKS_OFF.to_owned(),
            format!(
                "`sv` could not read {}, so a setting there that switches off certificate checking \
                 would not be seen.",
                unread.join(", ")
            ),
        ));
    } else {
        report.passed.push(Verified::new(
            CHECKS_OFF,
            &[],
            format!(
                "{read} files: none sets `NODE_TLS_REJECT_UNAUTHORIZED` or `PYTHONHTTPSVERIFY` to `0` \
                 or switches certificate checking off for the whole app in code; the same setting \
                 made on the server itself is in no file"
            ),
        ));
    }
}

#[track_caller]
fn finding(file: &str, line: usize, what: &str, does: &str) -> Finding {
    crate::finding::found(Finding {
        evidence: Vec::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: CHECKS_OFF.into(),
        title: "Certificate checking is switched off for every connection the app makes".into(),
        severity: Severity::High,
        confidence: Confidence::High,
        location: Location {
            file: file.to_owned(),
            line,
        },
        secret: None,
        requirement_ids: vec!["V12.3.2".into(), "V12.3.4".into()],
        cwe: vec!["CWE-295".into()],
        description: format!(
            "`{file}` has {what}: {does}. A certificate is how the app knows it is talking to the \
             real server and not someone in between, and this one line turns that check off for \
             every server at once, whatever the rest of the code asks for."
        ),
        impact: "Anyone who can get between the app and a server it calls (on a shared network, a \
                 compromised router, or inside the hosting provider) can pose as that server: read \
                 the keys and data the app sends to it, and send back whatever answers they like."
            .into(),
        fix: "Take the setting out. If it was added to reach one server with a certificate of its \
              own (an internal service, a self-signed test server), trust that certificate for that \
              server only: `NODE_EXTRA_CA_CERTS=/path/ca.pem` in Node.js, `verify=\"/path/ca.pem\"` \
              in Python's `requests`, or the CA added to that one client. If it is only for local \
              development, keep it in a file named for development (`.env.development`, \
              `Dockerfile.dev`), which `sv` leaves out."
            .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-certs-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(dir: &std::path::Path) -> ConfigReport {
        let mut report = ConfigReport::default();
        check(&Listing::of(dir), &mut report);
        report
    }

    fn lines_found(report: &ConfigReport) -> Vec<(String, usize)> {
        report
            .findings
            .iter()
            .filter(|f| f.rule_id == CHECKS_OFF)
            .map(|f| (f.location.file.clone(), f.location.line))
            .collect()
    }

    #[test]
    fn each_way_of_switching_checking_off_is_found_where_it_is_written() {
        let dir = scratch("found");
        let files: &[(&str, &str, usize)] = &[
            (
                "Dockerfile",
                "FROM node:22\nENV NODE_TLS_REJECT_UNAUTHORIZED=0\nCMD [\"node\", \"server.js\"]\n",
                2,
            ),
            (
                "api.Dockerfile",
                "FROM python:3.12\nENV PYTHONHTTPSVERIFY 0\n",
                2,
            ),
            (
                "docker-compose.yml",
                "services:\n  web:\n    environment:\n      NODE_TLS_REJECT_UNAUTHORIZED: \"0\"\n",
                4,
            ),
            (
                "compose.yaml",
                "services:\n  web:\n    environment:\n      - NODE_TLS_REJECT_UNAUTHORIZED=0\n",
                4,
            ),
            (
                "k8s/deploy.yaml",
                "env:\n  - name: NODE_TLS_REJECT_UNAUTHORIZED\n    value: \"0\"\n",
                3,
            ),
            (".env", "PORT=3000\nNODE_TLS_REJECT_UNAUTHORIZED=0\n", 2),
            (
                ".github/workflows/deploy.yml",
                "jobs:\n  d:\n    env:\n      PYTHONHTTPSVERIFY: '0'\n",
                4,
            ),
            (
                "start.sh",
                "#!/bin/sh\nexport NODE_TLS_REJECT_UNAUTHORIZED=0\nnode server.js\n",
                2,
            ),
            (
                "package.json",
                "{\n  \"scripts\": {\n    \"start\": \"NODE_TLS_REJECT_UNAUTHORIZED=0 node server.js\"\n  }\n}\n",
                3,
            ),
            (
                "server.js",
                "const https = require('https');\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
                2,
            ),
            (
                "agent.js",
                "const https = require('https');\nhttps.globalAgent.options.rejectUnauthorized = false;\n",
                2,
            ),
            (
                "app.py",
                "import os, ssl\nos.environ[\"PYTHONHTTPSVERIFY\"] = \"0\"\n",
                2,
            ),
            (
                "fetch.py",
                "import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n",
                2,
            ),
            (
                "Procfile",
                "web: deno run --allow-net --unsafely-ignore-certificate-errors main.ts\n",
                1,
            ),
        ];
        for (name, text, _) in files {
            let path = dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let report = run(&dir);
        fs::remove_dir_all(&dir).ok();
        let mut found = lines_found(&report);
        found.sort();
        let mut wanted: Vec<(String, usize)> = files
            .iter()
            .map(|(n, _, l)| ((*n).to_owned(), *l))
            .collect();
        wanted.sort();
        assert_eq!(found, wanted, "{report:?}");
        let one = report
            .findings
            .iter()
            .find(|f| f.location.file == "k8s/deploy.yaml")
            .unwrap();
        assert_eq!(one.requirement_ids, ["V12.3.2", "V12.3.4"]);
        assert!(
            one.description
                .contains("`NODE_TLS_REJECT_UNAUTHORIZED` set to `0`")
        );
        assert!(report.passed.iter().all(|p| p.check_id != CHECKS_OFF));
    }

    #[test]
    fn checking_left_on_described_or_kept_for_development_is_not_a_finding_and_credits_nothing() {
        let dir = scratch("quiet");
        let files: &[(&str, &str)] = &[
            // Left on, or set to anything but 0.
            (
                "Dockerfile",
                "FROM node:22\nENV NODE_TLS_REJECT_UNAUTHORIZED=1\nENV NODE_TLS_REJECT_UNAUTHORIZED_LOG=0\n",
            ),
            (
                "k8s/deploy.yaml",
                "env:\n  - name: NODE_TLS_REJECT_UNAUTHORIZED\n    value: \"1\"\n  - name: PORT\n    value: \"0\"\n",
            ),
            (
                "deno.Procfile",
                "web: deno run --unsafely-ignore-certificate-errors=internal.example main.ts\n",
            ),
            (
                "client.js",
                "const agent = new https.Agent({ ca: fs.readFileSync('ca.pem') });\n",
            ),
            // Commented out.
            (".env", "# NODE_TLS_REJECT_UNAUTHORIZED=0\nPORT=3000\n"),
            (
                "app.py",
                "# ssl._create_default_https_context = ssl._create_unverified_context\n",
            ),
            // Described, not made.
            (
                "README.md",
                "Never set NODE_TLS_REJECT_UNAUTHORIZED=0 in production.\n",
            ),
            // Kept for development and tests.
            ("Dockerfile.dev", "ENV NODE_TLS_REJECT_UNAUTHORIZED=0\n"),
            (".env.development", "NODE_TLS_REJECT_UNAUTHORIZED=0\n"),
            (
                "tests/conftest.py",
                "import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n",
            ),
            (
                ".claude/settings.json",
                "{\"env\": {\"NODE_TLS_REJECT_UNAUTHORIZED\": \"0\"}}\n",
            ),
        ];
        for (name, text) in files {
            let path = dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        // The setup: the developer tool's folder is one the listing reads, so leaving it out is
        // this check's doing.
        assert!(
            Listing::of(&dir)
                .app_files()
                .any(|f| f.relative == ".claude/settings.json"),
            "the listing does not reach the developer tool's folder"
        );
        let report = run(&dir);
        fs::remove_dir_all(&dir).ok();
        assert!(lines_found(&report).is_empty(), "{report:?}");
        let clean = report
            .passed
            .iter()
            .find(|p| p.check_id == CHECKS_OFF)
            .expect("a clean reading is said");
        assert!(
            clean.requirement_ids.is_empty(),
            "a clean reading credits nothing"
        );
        assert!(clean.scope.contains("files: none sets"), "{}", clean.scope);
    }

    #[test]
    fn a_setting_in_a_file_over_two_megabytes_is_found_on_its_own_line() {
        let dir = scratch("large");
        let mut text = String::new();
        while text.len() < 3 * 1024 * 1024 {
            text.push_str("PADDING_VALUE=some ordinary configuration line here\n");
        }
        let before = text.lines().count();
        text.push_str("NODE_TLS_REJECT_UNAUTHORIZED=0\n");
        fs::write(dir.join("big.env"), &text).unwrap();
        // The setup: the file really is over the limit read whole.
        assert!(text.len() > 2 * 1024 * 1024);
        let report = run(&dir);
        fs::remove_dir_all(&dir).ok();
        assert_eq!(
            lines_found(&report),
            [("big.env".to_owned(), before + 1)],
            "{:?}",
            report.not_assessed
        );
    }
}
