//! A server's key under a name the build hands to the browser (gap analysis, item 10, its third part).
//!
//! Next.js, Vite, Expo, and Create React App copy every variable whose name starts `NEXT_PUBLIC_`,
//! `VITE_`, `EXPO_PUBLIC_`, or `REACT_APP_` into the JavaScript every visitor downloads. That is how
//! an app built with Lovable, Bolt, and the like gives the browser its Supabase address and public
//! key, and it is easy to put the other key beside them: Supabase's service-role key, which passes
//! every row-level security policy, or a Stripe or OpenAI secret key. Under such a name it is public,
//! wherever the file that holds it is kept.
//!
//! Two things are read, and either is a finding:
//! - a public name that says it holds a secret (`NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`,
//!   `VITE_STRIPE_SECRET_KEY`), wherever it is written, since code that reads it puts it in the page;
//! - a value given to any public name that is, by its shape, a key only a server should hold.
//!
//! The value is never quoted, not even its first characters: the finding names the variable and what
//! kind of key it holds. This only ever finds. A public name that says nothing of a secret may still
//! hold one this does not recognize, so nothing is credited.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;
use sv_scan::files::Listing;

pub const SECRET_UNDER_PUBLIC_NAME: &str = "config.secret-under-public-name";

/// The prefixes the four builds hand to the browser.
const PUBLIC_PREFIXES: &[&str] = &["NEXT_PUBLIC_", "VITE_", "EXPO_PUBLIC_", "REACT_APP_"];

/// Reads every file of the app, and adds what it finds to `report`.
pub fn check(listing: &Listing, report: &mut ConfigReport) {
    for entry in listing.app_files() {
        if is_prose(entry.file_name()) {
            continue;
        }
        let Ok(text) = entry.read_text() else {
            continue;
        };
        report.findings.extend(findings_in(&entry.relative, &text));
    }
}

/// Documents that talk about a variable without making the app use it.
fn is_prose(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".md", ".mdx", ".txt", ".rst"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// One finding for each public name in a file that says it holds a secret or is given one, at the
/// first line it does so.
fn findings_in(file: &str, text: &str) -> Vec<Finding> {
    static NAME: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)[A-Z0-9_]+\b")
            .expect("static pattern")
    });
    static VALUE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^\s*[=:]\s*["']?([^\s"'`,;#]+)"#).expect("static pattern"));
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if is_comment(line) {
            continue;
        }
        for m in NAME.find_iter(line) {
            let name = m.as_str();
            if seen.contains(name) {
                continue;
            }
            let held = VALUE
                .captures(&line[m.end()..])
                .and_then(|c| server_key_kind(&c[1]));
            if held.is_none() && !names_a_secret(name) {
                continue;
            }
            seen.insert(name.to_owned());
            out.push(finding(file, index + 1, name, held));
        }
    }
    out
}

/// A line that is only a comment, in the languages these variables are written in.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    ["//", "#", "/*", "*", "<!--"]
        .iter()
        .any(|c| t.starts_with(c))
}

/// Whether a public name says it holds a secret: a word for one, and a last word for a key, or
/// Supabase's service role. `NEXT_PUBLIC_ADMIN_EMAIL` is an address, not a key, and
/// `VITE_STRIPE_PUBLISHABLE_KEY` is meant to be public.
fn names_a_secret(name: &str) -> bool {
    let rest = PUBLIC_PREFIXES
        .iter()
        .find_map(|p| name.strip_prefix(p))
        .unwrap_or(name);
    let words: Vec<&str> = rest.split('_').filter(|w| !w.is_empty()).collect();
    if words.windows(2).any(|w| w == ["SERVICE", "ROLE"]) {
        return true;
    }
    let secret_word = words
        .iter()
        .any(|w| matches!(*w, "SECRET" | "PRIVATE" | "ADMIN" | "PASSWORD" | "PASSWD"));
    let key_word = words.last().is_some_and(|w| {
        matches!(
            *w,
            "KEY" | "TOKEN" | "SECRET" | "PASSWORD" | "PASSWD" | "JWT" | "CREDENTIALS"
        )
    });
    secret_word && key_word
}

/// What kind of server key a value is, by its shape, or `None`. Only shapes that are never public.
fn server_key_kind(value: &str) -> Option<&'static str> {
    let long_tail = |prefix: &str| {
        value.strip_prefix(prefix).is_some_and(|rest| {
            rest.len() >= 16
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
    };
    if ["sk_live_", "sk_test_", "rk_live_", "rk_test_"]
        .iter()
        .any(|p| long_tail(p))
    {
        Some("a Stripe secret key")
    } else if long_tail("sk-ant-") {
        Some("an Anthropic API key")
    } else if long_tail("sk-") {
        Some("an OpenAI API key")
    } else if long_tail("sb_secret_") {
        Some("a Supabase secret key")
    } else if long_tail("ghp_") || long_tail("github_pat_") {
        Some("a GitHub token")
    } else if jwt_role(value).as_deref() == Some("service_role") {
        Some("a Supabase service-role key")
    } else {
        None
    }
}

/// The `role` a JSON Web Token's payload claims, as Supabase's keys carry it.
fn jwt_role(value: &str) -> Option<String> {
    let mut parts = value.split('.');
    let (Some(head), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if !head.starts_with("eyJ") {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&base64url(payload)?).ok()?;
    json.get("role")?.as_str().map(str::to_owned)
}

/// Base64url without padding, as a token's parts are written.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut bits = 0u32;
    let mut count = 0;
    for b in text.bytes() {
        let six = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(six);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

#[track_caller]
fn finding(file: &str, line: usize, name: &str, held: Option<&str>) -> Finding {
    let what = match held {
        Some(kind) => format!("is given {kind}"),
        None => "is named as a secret".to_owned(),
    };
    crate::finding::found(Finding {
        evidence: Vec::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: SECRET_UNDER_PUBLIC_NAME.to_owned(),
        title: "A server's key is under a name the browser is given".to_owned(),
        severity: Severity::High,
        confidence: if held.is_some() {
            Confidence::High
        } else {
            Confidence::Medium
        },
        location: Location {
            file: file.to_owned(),
            line,
        },
        secret: None,
        requirement_ids: vec!["V13.3.1".into(), "SBD-AC-05".into()],
        cwe: vec!["CWE-200".into()],
        description: format!(
            "`{name}` {what} in `{file}`. The build copies every variable whose name starts this \
             way into the JavaScript each visitor downloads, so the key is public, wherever the \
             file that holds it is kept."
        ),
        impact:
            "Anybody who opens the app can read the key from the page and use it as the server \
                 would. A Supabase service-role key passes every row-level security policy; a \
                 payment or AI provider's secret key spends the owner's money."
                .into(),
        fix:
            "Rename the variable without the public prefix and use it only in server code (an API \
              route, a server action, or a Supabase Edge Function). Then make a new key at the \
              provider and revoke this one: it has already been in the page."
                .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(file: &str, text: &str) -> Vec<(String, usize, Confidence)> {
        let dir = std::env::temp_dir().join(format!(
            "sv-public-keys-{}-{}",
            file.replace('/', "-"),
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        let mut report = ConfigReport::default();
        check(&Listing::of(&dir), &mut report);
        std::fs::remove_dir_all(&dir).ok();
        assert!(report.passed.is_empty(), "this check never credits");
        report
            .findings
            .into_iter()
            .map(|f| {
                assert!(
                    !f.description.contains(&key_tail()),
                    "the value is never quoted"
                );
                (f.description, f.location.line, f.confidence)
            })
            .collect()
    }

    /// The random part of every key below, made at run time so no file holds a key's shape.
    fn key_tail() -> String {
        ["Qv7r", "Lm2x", "Pd9k", "Ze4w", "Ht6n"].concat()
    }

    fn b64url(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    fn supabase_key(role: &str) -> String {
        let head = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
        let body =
            b64url(format!(r#"{{"iss":"supabase","ref":"abc","role":"{role}"}}"#).as_bytes());
        format!("{head}.{body}.{}", key_tail())
    }

    #[test]
    fn the_configuration_checks_read_it() {
        // The path `sv check` takes, so a check written here and never called is caught.
        let dir = std::env::temp_dir().join(format!("sv-public-keys-wired-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("supabase.ts"),
            "export const admin = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);\n",
        )
        .unwrap();
        let report = crate::config::check_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();
        let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&SECRET_UNDER_PUBLIC_NAME), "{ids:?}");
    }

    #[test]
    fn a_public_name_that_says_it_holds_a_secret_is_found_wherever_it_is_written() {
        for (file, text) in [
            (
                "src/lib/supabase.ts",
                "const url = import.meta.env.VITE_SUPABASE_URL;\nconst key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;\n",
            ),
            (
                ".env.example",
                "NEXT_PUBLIC_URL=\nNEXT_PUBLIC_STRIPE_SECRET_KEY=\n",
            ),
            (
                "app.config.js",
                "extra: {\n  token: process.env.EXPO_PUBLIC_ADMIN_TOKEN,\n}\n",
            ),
        ] {
            let got = found(file, text);
            assert_eq!(got.len(), 1, "{file}: {got:?}");
            assert_eq!(got[0].1, 2, "{file}");
            assert_eq!(got[0].2, Confidence::Medium, "{file}");
            assert!(got[0].0.contains("is named as a secret"), "{file}");
        }
        // Named twice in one file, it is one finding, at the first line.
        let twice =
            "a = process.env.REACT_APP_CLIENT_SECRET;\nb = process.env.REACT_APP_CLIENT_SECRET;\n";
        assert_eq!(found("a.js", twice).len(), 1);
    }

    #[test]
    fn public_names_meant_to_be_public_are_left_alone() {
        let text = [
            "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co",
            &format!("NEXT_PUBLIC_SUPABASE_ANON_KEY={}", supabase_key("anon")),
            "VITE_STRIPE_PUBLISHABLE_KEY=pk_live_abc",
            "VITE_FIREBASE_API_KEY=AIzaSyExampleValue",
            "NEXT_PUBLIC_ADMIN_EMAIL=owner@example.com",
            "VITE_SECRET_SANTA_ENABLED=true",
            "SUPABASE_SERVICE_ROLE_KEY=kept-on-the-server",
            "# NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY must never be set",
            "",
        ]
        .join("\n");
        assert!(
            found(".env", &text).is_empty(),
            "{:?}",
            found(".env", &text)
        );
        // A document that warns against it is not the app using it.
        assert!(
            found(
                "README.md",
                "Never set NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY.\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_server_key_given_to_any_public_name_is_found_by_its_shape() {
        let tail = key_tail();
        for (value, kind) in [
            (supabase_key("service_role"), "a Supabase service-role key"),
            (format!("sk_{}_{tail}", "live"), "a Stripe secret key"),
            (format!("sk-{}-{tail}", "proj"), "an OpenAI API key"),
            (format!("sk-{}-{tail}", "ant"), "an Anthropic API key"),
            (format!("sb_{}_{tail}", "secret"), "a Supabase secret key"),
            (format!("ghp_{tail}"), "a GitHub token"),
        ] {
            for line in [
                format!("VITE_SUPABASE_KEY={value}"),
                format!("VITE_SUPABASE_KEY = \"{value}\""),
                format!("  VITE_SUPABASE_KEY: '{value}'"),
            ] {
                let got = found(
                    ".env.local",
                    &format!("VITE_SUPABASE_URL=https://abc.supabase.co\n{line}\n"),
                );
                assert_eq!(got.len(), 1, "{line}: {got:?}");
                assert_eq!((got[0].1, got[0].2), (2, Confidence::High), "{line}");
                assert!(got[0].0.contains(&format!("is given {kind}")), "{line}");
            }
        }
        // A placeholder too short to be a key is not one.
        assert!(found(".env", "VITE_OPENAI_KEY=sk-your-key\n").is_empty());
    }
}
