//! V10.4.4, read from the code: a sign-in server in the app that switches on the password grant or the
//! implicit grant, which the requirement says must no longer be used.
//!
//! The running half (`probe.retired-grants-offered`) reads the settings the app publishes; this reads
//! the switches themselves, in the four libraries whose own source was read on 29 September 2026 to
//! learn each one's names for the two grants: django-oauth-toolkit 3.4.1 (`GRANT_PASSWORD` and
//! `GRANT_IMPLICIT` on its application model), Doorkeeper 5.9.9 (`grant_flows`, whose flows are
//! named `password` and `implicit`), fosite 0.49.0 (the compose factories for each, and
//! `ComposeAllEnabled`, which turns on both), and node-oauth2-server 5.3.0 (a client's `grants`,
//! which may hold `password`; its implicit response type throws "Not implemented"). league's
//! oauth2-server is not here: its source could not be fetched from this session to read.
//!
//! Only ever a finding. Settings kept in a database, or in a library not listed, are not seen, so
//! finding nothing credits nothing. A line that names a grant to refuse it (`if grant ==
//! GRANT_PASSWORD: raise`) is read as switching it on, which is why the confidence is medium.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use crate::sbom::Sbom;
use crate::verified::Verified;
use regex::Regex;
use std::sync::LazyLock;
use sv_scan::files::Listing;

pub const RETIRED_GRANT: &str = "config.retired-grant-enabled";

/// One library: its package, the words that show a file uses it, the files it is written in, and
/// what switches either grant on.
struct Library {
    name: &'static str,
    ecosystem: &'static str,
    packages: &'static [&'static str],
    marker: &'static str,
    extensions: &'static [&'static str],
    comment: &'static str,
    switches: &'static LazyLock<Regex>,
}

static DJANGO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\bGRANT_(PASSWORD|IMPLICIT)\b|\bauthorization_grant_type["']?\s*[:=]\s*["'](password|implicit)["']"#,
    )
    .unwrap()
});
static DOORKEEPER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*grant_flows\b[ \t]*(?:\(|%[wWiI][\[(]|\[)([^\])]*)").unwrap()
});
static FOSITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(OAuth2ResourceOwnerPasswordCredentialsFactory|OAuth2AuthorizeImplicitFactory|OpenIDConnectImplicitFactory|ComposeAllEnabled)\b",
    )
    .unwrap()
});
static NODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bgrants\s*:\s*\[([^\]]*)\]"#).unwrap());
static FLOW_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s,'"\[(:])(password|implicit)(?:$|[\s,'"\])])"#).unwrap()
});
static QUOTED_PASSWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"`]password['"`]"#).unwrap());

const LIBRARIES: &[Library] = &[
    Library {
        name: "django-oauth-toolkit",
        ecosystem: "Python",
        packages: &["django-oauth-toolkit"],
        marker: "oauth2_provider",
        extensions: &["py", "json", "yaml", "yml"],
        comment: "#",
        switches: &DJANGO,
    },
    Library {
        name: "Doorkeeper",
        ecosystem: "Ruby",
        packages: &["doorkeeper"],
        marker: "Doorkeeper",
        extensions: &["rb"],
        comment: "#",
        switches: &DOORKEEPER,
    },
    Library {
        name: "fosite",
        ecosystem: "Go",
        packages: &["github.com/ory/fosite"],
        marker: "github.com/ory/fosite",
        extensions: &["go"],
        comment: "//",
        switches: &FOSITE,
    },
    Library {
        name: "node-oauth2-server",
        ecosystem: "npm",
        packages: &[
            "@node-oauth/oauth2-server",
            "@node-oauth/express-oauth-server",
            "oauth2-server",
            "express-oauth-server",
        ],
        marker: "oauth2-server",
        extensions: &["js", "mjs", "cjs", "ts", "mts", "cts"],
        comment: "//",
        switches: &NODE,
    },
];

/// Python package names compare with `_`, `.`, and `-` alike and in any case.
fn same_package(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem == "Python" {
        let norm = |s: &str| s.to_lowercase().replace(['_', '.'], "-");
        norm(a) == norm(b)
    } else {
        a == b
    }
}

/// The text with every line that is only a comment blanked, so line numbers still hold and a
/// setting shown in a comment (as Doorkeeper's own generated file does) is not read as switched on.
fn without_comment_lines(text: &str, marker: &str) -> String {
    text.lines()
        .map(|l| {
            if l.trim_start().starts_with(marker) {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Which grant a match switches on, or `None` when it names neither.
fn grants_in(library: &Library, found: &regex::Captures) -> Vec<&'static str> {
    let whole = found.get(0).map_or("", |m| m.as_str());
    let listed = found.get(1).map_or("", |m| m.as_str());
    match library.name {
        "Doorkeeper" => {
            let mut out: Vec<&'static str> = FLOW_WORD
                .captures_iter(listed)
                .filter_map(|c| match c.get(1)?.as_str() {
                    "password" => Some("password"),
                    "implicit" => Some("implicit"),
                    _ => None,
                })
                .collect();
            out.dedup();
            out
        }
        "node-oauth2-server" => {
            if QUOTED_PASSWORD.is_match(listed) {
                vec!["password"]
            } else {
                vec![]
            }
        }
        "fosite" if whole == "ComposeAllEnabled" => vec!["password", "implicit"],
        _ => {
            let lower = whole.to_lowercase();
            if lower.contains("password") {
                vec!["password"]
            } else {
                vec!["implicit"]
            }
        }
    }
}

/// Every place in the app's files where a listed library switches on either grant: the file, the
/// line, the library, and the grants.
fn switched_on(
    listing: &Listing,
    sbom: &Sbom,
) -> (Vec<(String, usize, &'static str, Vec<&'static str>)>, bool) {
    let mut found = Vec::new();
    let mut any_library = false;
    for library in LIBRARIES {
        let installed = sbom.components.iter().any(|c| {
            c.ecosystem == library.ecosystem
                && library
                    .packages
                    .iter()
                    .any(|p| same_package(library.ecosystem, p, &c.name))
        });
        for entry in listing.app_files().filter(|f| {
            f.extension
                .as_deref()
                .is_some_and(|e| library.extensions.contains(&e))
        }) {
            let Ok(text) = entry.read_text() else {
                continue;
            };
            // A settings file for django-oauth-toolkit names its own key, which is the marker.
            let uses = installed
                || text.contains(library.marker)
                || (library.name == "django-oauth-toolkit"
                    && text.contains("authorization_grant_type"));
            if !uses {
                continue;
            }
            any_library = true;
            let code = without_comment_lines(&text, library.comment);
            for captures in library.switches.captures_iter(&code) {
                let grants = grants_in(library, &captures);
                if grants.is_empty() {
                    continue;
                }
                let at = captures.get(0).map_or(0, |m| m.start());
                let line = code[..at].matches('\n').count() + 1;
                found.push((entry.relative.clone(), line, library.name, grants));
            }
        }
        any_library |= installed;
    }
    (found, any_library)
}

pub fn check(listing: &Listing, sbom: &Sbom, report: &mut ConfigReport) {
    let (found, any_library) = switched_on(listing, sbom);
    let Some((file, line, _, _)) = found.first() else {
        report.passed.push(Verified::new(
            RETIRED_GRANT,
            &[],
            if any_library {
                "a sign-in server library `sv` knows, and nothing in the app's files switching on the \
                 password or implicit grant; settings kept in a database are not seen"
                    .to_owned()
            } else {
                "no sign-in server library `sv` knows (django-oauth-toolkit, Doorkeeper, fosite, \
                 node-oauth2-server) is used in the app's files"
                    .to_owned()
            },
        ));
        return;
    };
    let places: Vec<String> = found
        .iter()
        .map(|(file, line, library, grants)| {
            format!(
                "`{file}` line {line} ({library}: {})",
                grants
                    .iter()
                    .map(|g| format!("the {g} grant"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            )
        })
        .collect();
    report.findings.push(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        marked_test_code: false,
        rule_id: "config.retired-grant-enabled".into(),
        title: "The app's sign-in server switches on a grant that must no longer be used".into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        location: Location {
            file: file.clone(),
            line: *line,
        },
        secret: None,
        requirement_ids: vec!["V10.4.4".into()],
        cwe: vec!["CWE-522".into()],
        description: format!(
            "The app's own sign-in server turns on the password grant (an app asks for a person's \
             password and trades it for a token) or the implicit grant (a token handed back in the \
             address bar), at {}.",
            places.join("; ")
        ),
        impact: "The password grant teaches people to type their password into any app that asks and \
                 gives every such app the password itself; the implicit grant puts the token where the \
                 browser's history, other scripts on the page, and referring links can read it. Both \
                 were retired for those reasons."
            .into(),
        fix: "Turn both off and have every client use the authorization code grant with PKCE (and the \
              client credentials grant for a service with no person behind it). If a line only names \
              a grant in order to refuse it, this does not apply and can be set aside."
            .into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-grants-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(dir: &std::path::Path) -> ConfigReport {
        let listing = Listing::of(dir);
        let sbom = crate::sbom::build_in(&listing);
        let mut report = ConfigReport::default();
        check(&listing, &sbom, &mut report);
        report
    }

    fn found(report: &ConfigReport) -> Option<&Finding> {
        report.findings.iter().find(|f| f.rule_id == RETIRED_GRANT)
    }

    /// Each library's switch, written as its own documentation or generated file writes it, with
    /// the grant each one turns on, and beside it the same setting with only the grants still in
    /// use, as the control.
    const CASES: &[(&str, &str, &str, &str, &str)] = &[
        (
            "oauth/models.py",
            "from oauth2_provider.models import Application\n\nApplication.objects.create(\n    name=\"mobile\",\n    client_type=Application.CLIENT_CONFIDENTIAL,\n    authorization_grant_type=Application.GRANT_PASSWORD,\n)\n",
            "from oauth2_provider.models import Application\n\nApplication.objects.create(\n    name=\"mobile\",\n    client_type=Application.CLIENT_CONFIDENTIAL,\n    authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,\n)\n",
            "password",
            "line 6",
        ),
        (
            "fixtures/clients.json",
            "[{\"model\": \"oauth2_provider.application\", \"fields\": {\"name\": \"spa\", \"authorization_grant_type\": \"implicit\"}}]\n",
            "[{\"model\": \"oauth2_provider.application\", \"fields\": {\"name\": \"spa\", \"authorization_grant_type\": \"authorization-code\"}}]\n",
            "implicit",
            "line 1",
        ),
        (
            "config/initializers/doorkeeper.rb",
            "Doorkeeper.configure do\n  orm :active_record\n  # grant_flows %w[authorization_code client_credentials]\n  grant_flows %w[\n    authorization_code\n    implicit\n    password\n  ]\nend\n",
            "Doorkeeper.configure do\n  orm :active_record\n  # grant_flows %w[authorization_code password implicit]\n  grant_flows %w[authorization_code client_credentials]\nend\n",
            "implicit grant and the password",
            "line 4",
        ),
        (
            "auth/provider.go",
            "package auth\n\nimport (\n\t\"github.com/ory/fosite\"\n\t\"github.com/ory/fosite/compose\"\n)\n\nvar Provider = compose.Compose(config, store, strategy,\n\tcompose.OAuth2AuthorizeExplicitFactory,\n\tcompose.OAuth2ResourceOwnerPasswordCredentialsFactory,\n)\n\nvar _ fosite.OAuth2Provider = Provider\n",
            "package auth\n\nimport (\n\t\"github.com/ory/fosite\"\n\t\"github.com/ory/fosite/compose\"\n)\n\nvar Provider = compose.Compose(config, store, strategy,\n\tcompose.OAuth2AuthorizeExplicitFactory,\n\t// compose.OAuth2ResourceOwnerPasswordCredentialsFactory,\n)\n\nvar _ fosite.OAuth2Provider = Provider\n",
            "password",
            "line 10",
        ),
        (
            "auth/all.go",
            "package auth\n\nimport \"github.com/ory/fosite/compose\"\n\nvar Provider = compose.ComposeAllEnabled(config, store, key)\n",
            "package auth\n\nimport \"github.com/ory/fosite/compose\"\n\nvar Provider = compose.Compose(config, store, strategy, compose.OAuth2AuthorizeExplicitFactory)\n",
            "password grant and the implicit",
            "line 5",
        ),
        (
            "oauth/model.js",
            "const OAuth2Server = require('@node-oauth/oauth2-server');\n\nmodule.exports = {\n  getClient: async (id) => ({\n    id,\n    grants: ['authorization_code', 'password', 'refresh_token'],\n    redirectUris: ['https://app.example/cb'],\n  }),\n};\n",
            "const OAuth2Server = require('@node-oauth/oauth2-server');\n\nmodule.exports = {\n  getClient: async (id) => ({\n    id,\n    grants: ['authorization_code', 'refresh_token'],\n    redirectUris: ['https://app.example/cb'],\n  }),\n};\n",
            "password",
            "line 6",
        ),
    ];

    #[test]
    fn each_library_s_switch_for_a_retired_grant_is_found_and_the_same_setting_without_it_is_not() {
        for (file, on, off, grant, line) in CASES {
            let dir = scratch("case");
            let path = dir.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, on).unwrap();
            let report = run(&dir);
            let finding = found(&report).unwrap_or_else(|| panic!("{file}: {report:?}"));
            assert_eq!(finding.requirement_ids, vec!["V10.4.4"], "{file}");
            assert!(
                finding.description.contains(&format!("`{file}` {line}"))
                    && finding.description.contains(grant),
                "{file}: {}",
                finding.description
            );

            fs::write(&path, off).unwrap();
            let report = run(&dir);
            assert!(found(&report).is_none(), "{file}: {report:?}");
            // The control ran as a library the check knows, not as an app with none.
            let passed = report
                .passed
                .iter()
                .find(|p| p.check_id == RETIRED_GRANT)
                .unwrap_or_else(|| panic!("{file}: {report:?}"));
            assert!(
                passed.scope.contains("a sign-in server library"),
                "{file}: {}",
                passed.scope
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn the_same_words_without_the_library_are_not_read() {
        // A client of someone else's server that lists `grants`, a Rails app with its own
        // `grant_flows` method, and Go code with its own `ComposeAllEnabled`: none uses a library
        // this knows, so none is its sign-in server.
        let dir = scratch("none");
        fs::write(
            dir.join("client.js"),
            "export const settings = { grants: ['password'] };\n",
        )
        .unwrap();
        fs::write(dir.join("flows.rb"), "grant_flows %w[password]\n").unwrap();
        fs::write(
            dir.join("main.go"),
            "package main\n\nfunc ComposeAllEnabled() {}\n",
        )
        .unwrap();
        let report = run(&dir);
        assert!(found(&report).is_none(), "{report:?}");
        let passed = report
            .passed
            .iter()
            .find(|p| p.check_id == RETIRED_GRANT)
            .expect("a clean run is recorded");
        assert!(
            passed.scope.contains("no sign-in server library"),
            "{}",
            passed.scope
        );
        assert!(
            passed.requirement_ids.is_empty(),
            "finding nothing credits nothing"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_library_among_the_packages_counts_where_no_file_names_it() {
        // node-oauth2-server's clients are often defined in a model file that never requires it.
        let dir = scratch("sbom");
        fs::write(
            dir.join("package.json"),
            "{\"name\": \"x\", \"dependencies\": {\"@node-oauth/oauth2-server\": \"5.3.0\"}}",
        )
        .unwrap();
        fs::write(
            dir.join("package-lock.json"),
            "{\"lockfileVersion\": 3, \"packages\": {\"\": {}, \"node_modules/@node-oauth/oauth2-server\": {\"version\": \"5.3.0\"}}}",
        )
        .unwrap();
        fs::write(
            dir.join("clients.js"),
            "module.exports = [{ id: 'cli', grants: [\"password\"] }];\n",
        )
        .unwrap();
        let report = run(&dir);
        assert!(found(&report).is_some(), "{report:?}");
        fs::remove_dir_all(&dir).ok();
    }
}
