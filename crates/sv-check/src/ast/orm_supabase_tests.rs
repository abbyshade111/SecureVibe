//! `ast.sql-built-by-hand` reading the filter text Supabase's clients pass through to the database
//! (the gap analysis of 7 October 2026, finding 1, first half): `.or(...)` and `.filter(...)` on npm,
//! `.or_(...)` and `.filter(...)` in Python. Both clients came off the rule's `unreadPackages` list,
//! the last there, so each form has a case that must be found and one that must not, and an array's
//! own `filter` is held to stay unread.

use super::*;
use std::path::PathBuf;

const RULE: &str = "ast.sql-built-by-hand";

fn rules() -> &'static AstRules {
    static RULES: std::sync::OnceLock<AstRules> = std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        AstRules::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"))
            .expect("rules load")
    })
}

fn check(language: &str, path: &str, wrap: impl Fn(&str) -> String, cases: &[(&str, bool)]) {
    for (code, expected) in cases {
        let found = scan_file(rules(), language, path, &wrap(code))
            .iter()
            .any(|f| f.rule_id == RULE);
        assert_eq!(
            found,
            *expected,
            "{language}: `{code}` should{} be reported",
            if *expected { "" } else { " not" }
        );
    }
}

const JAVASCRIPT: &[(&str, bool)] = &[
    (
        "supabase.from('users').select('*').or(`name.eq.${name},email.eq.${name}`)",
        true,
    ),
    (
        "supabase.from('users').select('*').or('name.eq.' + name)",
        true,
    ),
    ("query.or(\"age.gt.\" + age)", true),
    (
        "supabase.from('users').select('*').filter('id', 'in', '(' + ids + ')')",
        true,
    ),
    (
        "supabase.from('users').select('*').filter('id', 'in', `(${ids})`)",
        true,
    ),
    (
        "supabase.from('users').select('*').or('role.eq.admin,role.eq.owner')",
        false,
    ),
    (
        "supabase.from('users').select('*').filter('name', 'eq', name)",
        false,
    ),
    ("supabase.from('users').select('*').or(clause)", false),
    // An array's own `filter`, whatever its function joins, is not a query.
    ("users.filter(u => u.name === 'a' + name)", false),
    ("users.map(u => u.name).filter(n => n + 'x')", false),
    ("[1, 2].filter(Boolean)", false),
    // Another library's `or` handed fixed names.
    ("Joi.object().or('a', 'b')", false),
    // Another library's `or` handed a function: only text is filter text.
    ("schema.or(v => 'a' + v)", false),
];

#[test]
fn filter_text_built_from_pieces_is_found_in_javascript_and_typescript() {
    let wrap = |code: &str| {
        format!(
            "async function users(supabase, query, users, schema, name, age, ids, clause) {{\n  return {code};\n}}\n"
        )
    };
    check("javascript", "src/app.js", wrap, JAVASCRIPT);
    check("typescript", "src/app.ts", wrap, JAVASCRIPT);
}

#[test]
fn filter_text_built_from_pieces_is_found_in_python() {
    check(
        "python",
        "src/app.py",
        |code| format!("def users(client, name, age, ids, rows):\n    return {code}\n"),
        &[
            (
                "client.table('users').select('*').or_(f\"name.eq.{name}\").execute()",
                true,
            ),
            (
                "client.table('users').select('*').or_(\"age.gt.\" + age).execute()",
                true,
            ),
            (
                "client.table('users').select('*').or_(\"age.gt.%s\" % age).execute()",
                true,
            ),
            (
                "client.table('users').select('*').filter('id', 'in', f\"({ids})\").execute()",
                true,
            ),
            (
                "client.table('users').select('*').or_(\"role.eq.admin,role.eq.owner\").execute()",
                false,
            ),
            (
                "client.table('users').select('*').filter('name', 'eq', name).execute()",
                false,
            ),
            // Python's own `filter`, and a query filter of two conditions.
            ("list(filter(lambda r: r + 1, rows))", false),
            ("session.query(User).filter(User.age > age + 1)", false),
        ],
    );
}

#[test]
fn the_unread_list_is_empty() {
    let rule = rules().rules().find(|r| r.id == RULE).unwrap();
    // The setup: the field is still read, with an entry per ecosystem it was written for.
    assert!(
        rule.unread_packages.contains_key("npm") && rule.unread_packages.contains_key("Python")
    );
    for (ecosystem, packages) in &rule.unread_packages {
        assert!(packages.is_empty(), "{ecosystem}: {packages:?}");
    }
}
