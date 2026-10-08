//! The access rules of the hosted backends AI-built apps use: Firebase's rules files and Supabase's
//! migrations (gap analysis, item 10).
//!
//! An app built with Lovable, Bolt, and the like often has no server code of its own between the
//! browser and the database: the browser talks to Firebase or Supabase directly, and these rules are
//! the whole of its access control. Nothing read them, so `allow read, write: if true;` and a table
//! with no row-level security drew no finding.
//!
//! Each check here only ever finds. A rules file that holds none of these shapes may still let one
//! user read another's data in a way a file cannot show, so a clean reading credits nothing.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use sv_scan::files::Listing;

pub const FIREBASE_OPEN: &str = "config.firebase-rules-open";
pub const TABLE_WITHOUT_RLS: &str = "config.supabase-table-without-rls";
pub const POLICY_ALLOWS_ALL: &str = "config.supabase-policy-allows-all";

/// Reads every rules file and migration in the app, and adds what it finds to `report`.
pub fn check(listing: &Listing, report: &mut ConfigReport) {
    let mut tables: BTreeMap<String, (String, usize)> = BTreeMap::new();
    let mut protected: Vec<String> = Vec::new();
    for entry in listing.app_files() {
        let name = entry.file_name();
        let firebase = name.ends_with(".rules");
        let realtime = name.ends_with("database.rules.json");
        let migration = name.ends_with(".sql") && in_migrations(&entry.relative);
        if !(firebase || realtime || migration) {
            continue;
        }
        let Ok(text) = entry.read_text() else {
            continue;
        };
        if firebase && is_firebase_rules(&text) {
            report
                .findings
                .extend(firebase_open(&entry.relative, &text));
        } else if realtime {
            report
                .findings
                .extend(realtime_open(&entry.relative, &text));
        } else if migration {
            let sql = without_sql_comments(&text);
            for (table, line) in created_tables(&sql) {
                tables
                    .entry(table)
                    .or_insert((entry.relative.clone(), line));
            }
            protected.extend(tables_with_rls(&sql));
            report
                .findings
                .extend(policies_allowing_all(&entry.relative, &sql));
        }
    }
    for (table, (file, line)) in tables {
        if !protected.contains(&table) {
            report.findings.push(table_without_rls(&file, line, &table));
        }
    }
}

/// Whether a path is in a Supabase project's migrations folder, as the Supabase CLI lays it out.
fn in_migrations(path: &str) -> bool {
    path.starts_with("supabase/migrations/") || path.contains("/supabase/migrations/")
}

/// Whether a `.rules` file is Firebase's: it names the service it guards.
fn is_firebase_rules(text: &str) -> bool {
    text.contains("service cloud.firestore") || text.contains("service firebase.storage")
}

/// The text with its comments made spaces, so every position and line is where it was.
fn blank(text: &str, pattern: &Regex) -> String {
    let mut out = text.to_owned();
    for m in pattern.find_iter(text) {
        let spaces: String = m
            .as_str()
            .chars()
            .map(|c| if c == '\n' { '\n' } else { ' ' })
            .collect();
        out.replace_range(m.range(), &spaces);
    }
    out
}

fn without_c_comments(text: &str) -> String {
    static COMMENT: OnceLock<Regex> = OnceLock::new();
    let comment =
        COMMENT.get_or_init(|| Regex::new(r"(?s)//[^\n]*|/\*.*?\*/").expect("a fixed pattern"));
    blank(text, comment)
}

fn without_sql_comments(text: &str) -> String {
    static COMMENT: OnceLock<Regex> = OnceLock::new();
    let comment =
        COMMENT.get_or_init(|| Regex::new(r"(?s)--[^\n]*|/\*.*?\*/").expect("a fixed pattern"));
    blank(text, comment)
}

fn line_at(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// Each `allow` in a Firestore or Storage rules file that lets anybody in: one with no condition,
/// `if true`, or only the date "test mode" sets (`request.time < timestamp.date(...)`), which lets
/// everybody in until that day.
fn firebase_open(file: &str, text: &str) -> Vec<Finding> {
    static ALLOW: OnceLock<Regex> = OnceLock::new();
    static TEST_MODE: OnceLock<Regex> = OnceLock::new();
    let allow = ALLOW.get_or_init(|| {
        Regex::new(r"(?s)\ballow\s+([a-z, ]+?)\s*(?::\s*if\s+([^;]*?))?\s*;")
            .expect("a fixed pattern")
    });
    let test_mode = TEST_MODE.get_or_init(|| {
        Regex::new(r"^request\.time\s*<\s*timestamp\.date\([0-9,\s]*\)$").expect("a fixed pattern")
    });
    let code = without_c_comments(text);
    allow
        .captures_iter(&code)
        .filter_map(|c| {
            let what = c[1].trim().to_owned();
            let condition = c.get(2).map(|m| m.as_str().split_whitespace().collect::<Vec<_>>().join(" "));
            let how = match condition.as_deref() {
                None => "with no condition at all".to_owned(),
                Some("true") => "with `if true`".to_owned(),
                Some(cond) if test_mode.is_match(cond) => format!(
                    "with only a date as its condition (`if {cond}`), as Firebase's test mode writes it"
                ),
                Some(_) => return None,
            };
            let at = c.get(0).map_or(0, |m| m.start());
            Some(open_rule(file, line_at(&code, at), &format!("`allow {what}` {how}")))
        })
        .collect()
}

/// Each `.read` or `.write` set to `true` in a Realtime Database rules file.
fn realtime_open(file: &str, text: &str) -> Vec<Finding> {
    static OPEN: OnceLock<Regex> = OnceLock::new();
    let open = OPEN.get_or_init(|| {
        Regex::new(r#""\.(read|write)"\s*:\s*(true|"true")"#).expect("a fixed pattern")
    });
    let code = without_c_comments(text);
    open.captures_iter(&code)
        .map(|c| {
            let at = c.get(0).map_or(0, |m| m.start());
            open_rule(file, line_at(&code, at), &format!("`\".{}\": true`", &c[1]))
        })
        .collect()
}

/// A table's name as one key: lowercase, quotes taken off, `public.` taken off. `None` for a table in
/// another schema (`auth.users`, a `private` schema), which the browser does not reach.
fn table_key(name: &str) -> Option<String> {
    let name = name.replace('"', "").to_lowercase();
    match name.split_once('.') {
        None => Some(name),
        Some(("public", table)) => Some(table.to_owned()),
        Some(_) => None,
    }
}

const TABLE_NAME: &str = r#"((?:"?[A-Za-z_][\w$]*"?\.)?"?[A-Za-z_][\w$]*"?)"#;

/// Each table a migration creates in the `public` schema, with its line.
fn created_tables(sql: &str) -> Vec<(String, usize)> {
    static CREATE: OnceLock<Regex> = OnceLock::new();
    let create = CREATE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?{TABLE_NAME}"
        ))
        .expect("a fixed pattern")
    });
    create
        .captures_iter(sql)
        .filter_map(|c| {
            let at = c.get(0).map_or(0, |m| m.start());
            table_key(&c[1]).map(|t| (t, line_at(sql, at)))
        })
        .collect()
}

/// Each table a migration turns row-level security on for.
fn tables_with_rls(sql: &str) -> Vec<String> {
    static ENABLE: OnceLock<Regex> = OnceLock::new();
    let enable = ENABLE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{TABLE_NAME}\s+(?:force|enable)\s+row\s+level\s+security"
        ))
        .expect("a fixed pattern")
    });
    enable
        .captures_iter(sql)
        .filter_map(|c| table_key(&c[1]))
        .collect()
}

/// Each policy that lets rows be added, changed, or deleted on no condition at all: `using (true)`
/// or `with check (true)` on a policy for `all`, `insert`, `update`, or `delete`. A policy that lets
/// everybody read (`for select using (true)`) is left alone: a public list is often meant to be one.
fn policies_allowing_all(file: &str, sql: &str) -> Vec<Finding> {
    static POLICY: OnceLock<Regex> = OnceLock::new();
    static FOR: OnceLock<Regex> = OnceLock::new();
    static TO: OnceLock<Regex> = OnceLock::new();
    static TRUE: OnceLock<Regex> = OnceLock::new();
    let policy = POLICY
        .get_or_init(|| Regex::new(r"(?is)\bcreate\s+policy\b[^;]*;").expect("a fixed pattern"));
    let for_ = FOR.get_or_init(|| {
        Regex::new(r"(?i)\bfor\s+(all|select|insert|update|delete)\b").expect("a fixed pattern")
    });
    let to = TO.get_or_init(|| {
        Regex::new(r"(?i)\bto\s+([\w\s,]+?)\s*(?:\busing\b|\bwith\b|;|$)").expect("a fixed pattern")
    });
    let always = TRUE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:using|with\s+check)\s*\(\s*true\s*\)").expect("a fixed pattern")
    });
    policy
        .find_iter(sql)
        .filter_map(|m| {
            let text = m.as_str();
            let command = for_
                .captures(text)
                .map_or("all".to_owned(), |c| c[1].to_lowercase());
            if command == "select" || !always.is_match(text) {
                return None;
            }
            let roles = to
                .captures(text)
                .map_or("public".to_owned(), |c| c[1].trim().to_lowercase());
            let who = if roles.contains("anon") || roles.contains("public") {
                "anybody, signed in or not,"
            } else if roles.contains("authenticated") {
                "anybody signed in"
            } else {
                "everybody in the role it names"
            };
            Some(policy_allows_all(
                file,
                line_at(sql, m.start()),
                who,
                &command,
            ))
        })
        .collect()
}

fn base(rule_id: &str, title: &str, file: &str, line: usize, description: String) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: rule_id.to_owned(),
        title: title.to_owned(),
        severity: Severity::High,
        confidence: Confidence::High,
        location: Location {
            file: file.to_owned(),
            line,
        },
        secret: None,
        // Data-level access first: these rules decide whose records anybody can reach.
        requirement_ids: vec!["V8.2.2".into(), "V8.2.1".into()],
        cwe: vec!["CWE-284".into()],
        description,
        impact: String::new(),
        fix: String::new(),
    }
}

fn open_rule(file: &str, line: usize, what: &str) -> Finding {
    let mut f = base(
        FIREBASE_OPEN,
        "The Firebase rules let anybody in",
        file,
        line,
        format!(
            "`{file}` has {what}. These rules are the app's access control: the browser reads and \
             writes the database directly, and this rule lets anybody do so, signed in or not."
        ),
    );
    f.impact = "Anybody who finds the app's Firebase project (its settings are in the page every \
                visitor loads) can read every record it guards, and change or delete them."
        .into();
    f.fix =
        "Write a condition for each `allow`: that somebody is signed in (`request.auth != null`), \
             and that the record is theirs (`request.auth.uid == resource.data.owner`, or the \
             document's id). Firebase's rules simulator checks a rule before it is published."
            .into();
    f
}

fn table_without_rls(file: &str, line: usize, table: &str) -> Finding {
    let mut f = base(
        TABLE_WITHOUT_RLS,
        "A Supabase table has no row-level security",
        file,
        line,
        format!(
            "`{file}` creates the table `{table}`, and no migration turns row-level security on for \
             it (`alter table {table} enable row level security`). Without it, the key every visitor's \
             browser holds can read and change every row."
        ),
    );
    f.impact = "Supabase gives the browser a public key, and row-level security is what stops that \
                key reaching other people's rows. A table without it is open to anybody who opens the \
                app."
        .into();
    f.fix = "Add a migration that enables row-level security on the table, then write a policy for \
             each thing the app does with it, such as letting people see and change only rows whose \
             `user_id` is `auth.uid()`."
        .into();
    f
}

fn policy_allows_all(file: &str, line: usize, who: &str, command: &str) -> Finding {
    let mut f = base(
        POLICY_ALLOWS_ALL,
        "A Supabase policy lets anybody change rows",
        file,
        line,
        format!(
            "`{file}` has a policy for `{command}` whose condition is `true`, so {who} can \
             {} any row of the table, not only their own.",
            match command {
                "insert" => "add",
                "update" => "change",
                "delete" => "delete",
                _ => "add, change, or delete",
            }
        ),
    );
    f.impact =
        "Row-level security is switched on, and this policy switches it back off for changing \
                the data: one person can change or delete another's records."
            .into();
    f.fix = "Give the policy a condition that ties the row to the person, such as \
             `using (auth.uid() = user_id) with check (auth.uid() = user_id)`."
        .into();
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(file: &str, text: &str) -> Vec<(String, usize)> {
        let dir = std::env::temp_dir().join(format!(
            "sv-hosted-rules-{}-{}",
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
        assert!(report.passed.is_empty(), "these checks never credit");
        report
            .findings
            .into_iter()
            .map(|f| (f.rule_id, f.location.line))
            .collect()
    }

    #[test]
    fn the_configuration_checks_read_them() {
        // The path `sv check` takes, so a check written here and never called is caught.
        let dir =
            std::env::temp_dir().join(format!("sv-hosted-rules-wired-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("supabase/migrations")).unwrap();
        std::fs::write(
            dir.join("firestore.rules"),
            "service cloud.firestore {\n  match /{doc=**} {\n    allow read, write: if true;\n  }\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("supabase/migrations/1.sql"),
            "create table notes (id int);\n",
        )
        .unwrap();
        let report = crate::config::check_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();
        let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&FIREBASE_OPEN), "{ids:?}");
        assert!(ids.contains(&TABLE_WITHOUT_RLS), "{ids:?}");
    }

    #[test]
    fn firebase_rules_that_let_anybody_in_are_found_at_their_line() {
        let head = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n";
        for allow in [
            "allow read, write: if true;",
            "allow read, write;",
            "allow read, write: if request.time < timestamp.date(2026, 11, 7);",
            "allow write:\n      if true;",
        ] {
            let text =
                format!("{head}    match /notes/{{id}} {{\n      {allow}\n    }}\n  }}\n}}\n");
            assert_eq!(
                found("firestore.rules", &text),
                [(FIREBASE_OPEN.to_owned(), 5)],
                "{allow}"
            );
        }
        // Storage is the same language.
        let storage = "service firebase.storage {\n  match /b/{bucket}/o {\n    allow read, write: if true;\n  }\n}\n";
        assert_eq!(
            found("storage.rules", storage),
            [(FIREBASE_OPEN.to_owned(), 3)]
        );
        // What a careful rule looks like is left alone, and so is a commented-out open one.
        for allow in [
            "allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;",
            "// allow read, write: if true;",
            "/* allow read, write: if true; */",
            "allow read: if isOwner();",
        ] {
            let text =
                format!("{head}    match /notes/{{id}} {{\n      {allow}\n    }}\n  }}\n}}\n");
            assert!(found("firestore.rules", &text).is_empty(), "{allow}");
        }
        // A `.rules` file that is not Firebase's is not read as one.
        assert!(found("app.rules", "allow read, write: if true;\n").is_empty());
    }

    #[test]
    fn realtime_database_rules_set_to_true_are_found() {
        let text = "{\n  \"rules\": {\n    \".read\": true,\n    \".write\": \"true\"\n  }\n}\n";
        assert_eq!(
            found("database.rules.json", text),
            [(FIREBASE_OPEN.to_owned(), 3), (FIREBASE_OPEN.to_owned(), 4)]
        );
        let careful =
            "{\n  \"rules\": {\n    \".read\": \"auth != null\",\n    \".write\": false\n  }\n}\n";
        assert!(found("database.rules.json", careful).is_empty());
    }

    #[test]
    fn a_supabase_table_without_row_level_security_is_found() {
        let without = "create table public.notes (\n  id uuid primary key,\n  body text\n);\n";
        assert_eq!(
            found("supabase/migrations/20260101_notes.sql", without),
            [(TABLE_WITHOUT_RLS.to_owned(), 1)]
        );
        // Turned on, in any of the ways it is written, it is not.
        for enable in [
            "alter table public.notes enable row level security;",
            "ALTER TABLE \"notes\" ENABLE ROW LEVEL SECURITY;",
            "alter table only notes force row level security;",
        ] {
            let text = format!("{without}{enable}\n");
            assert!(
                found("supabase/migrations/1_notes.sql", &text).is_empty(),
                "{enable}"
            );
        }
        // A table in another schema, a commented-out table, and SQL outside the migrations are not
        // read as the browser's.
        assert!(
            found(
                "supabase/migrations/2.sql",
                "create table private.keys (id int);\n"
            )
            .is_empty()
        );
        assert!(
            found(
                "supabase/migrations/3.sql",
                "-- create table notes (id int);\n"
            )
            .is_empty()
        );
        assert!(found("db/schema.sql", without).is_empty());
    }

    #[test]
    fn a_supabase_policy_that_lets_anybody_change_rows_is_found() {
        let table = "create table notes (id int);\nalter table notes enable row level security;\n";
        for policy in [
            "create policy \"edit\" on notes for update to anon using (true);",
            "create policy \"all\" on notes using (true) with check (true);",
            "create policy \"add\" on notes for insert to authenticated with check (true);",
        ] {
            let text = format!("{table}{policy}\n");
            assert_eq!(
                found("supabase/migrations/1.sql", &text),
                [(POLICY_ALLOWS_ALL.to_owned(), 3)],
                "{policy}"
            );
        }
        for policy in [
            "create policy \"read\" on notes for select using (true);",
            "create policy \"own\" on notes for update using (auth.uid() = user_id);",
        ] {
            let text = format!("{table}{policy}\n");
            assert!(
                found("supabase/migrations/1.sql", &text).is_empty(),
                "{policy}"
            );
        }
    }
}
