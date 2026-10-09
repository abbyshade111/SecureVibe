//! `ast.sql-built-by-hand` reading MongoDB's `$where`, whose text the database runs as JavaScript
//! (the gap analysis of 7 October 2026, finding 1, first half). Mongoose, the MongoDB drivers for
//! npm and Go, and PyMongo came off the rule's `unreadPackages` list when each way of writing a
//! `$where` was read, so each has a case that must be found and one that must not.

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

fn found(language: &str, path: &str, source: &str) -> bool {
    scan_file(rules(), language, path, source)
        .iter()
        .any(|f| f.rule_id == RULE)
}

fn check(language: &str, path: &str, wrap: impl Fn(&str) -> String, cases: &[(&str, bool)]) {
    for (code, expected) in cases {
        assert_eq!(
            found(language, path, &wrap(code)),
            *expected,
            "{language}: `{code}` should{} be reported",
            if *expected { "" } else { " not" }
        );
    }
}

const JAVASCRIPT: &[(&str, bool)] = &[
    (
        "Users.find({ $where: \"this.name == '\" + name + \"'\" })",
        true,
    ),
    ("Users.find({ $where: `this.name == '${name}'` })", true),
    (
        "db.collection('users').find({ \"$where\": 'this.age > ' + age })",
        true,
    ),
    ("Users.find({ '$where': \"this.age > \" + age })", true),
    ("Users.find().$where('this.age > ' + age)", true),
    ("Users.find({ $where: 'this.age > 18' })", false),
    (
        "Users.find({ $where: function () { return this.age > 18 } })",
        false,
    ),
    ("Users.find({ name: \"a\" + name })", false),
    ("Users.find({ name: name })", false),
    ("Users.find().$where('this.age > 18')", false),
    // A name handed over is judged as `where` is: only text built in the call is reported.
    ("Users.find({ $where: clause })", false),
    ("Users.find().$where(clause)", false),
];

#[test]
fn a_where_built_from_pieces_is_found_in_javascript_and_typescript() {
    let wrap =
        |code: &str| format!("async function users(name, age, clause) {{\n  return {code};\n}}\n");
    check("javascript", "src/app.js", wrap, JAVASCRIPT);
    check("typescript", "src/app.ts", wrap, JAVASCRIPT);
}

#[test]
fn a_where_built_from_pieces_is_found_in_python() {
    check(
        "python",
        "src/app.py",
        |code| format!("def users(db, name, age):\n    return {code}\n"),
        &[
            (
                "db.users.find({\"$where\": \"this.name == '\" + name + \"'\"})",
                true,
            ),
            ("db.users.find({'$where': f\"this.age > {age}\"})", true),
            ("db.users.find({\"$where\": \"this.age > %s\" % age})", true),
            (
                "db.users.find({\"$where\": \"this.age > {}\".format(age)})",
                true,
            ),
            ("db.users.find({\"$where\": \"this.age > 18\"})", false),
            ("db.users.find({\"name\": \"a\" + name})", false),
            ("db.users.find({\"age\": {\"$gt\": age}})", false),
        ],
    );
}

#[test]
fn a_where_built_from_pieces_is_found_in_go() {
    check(
        "go",
        "main.go",
        |code| {
            format!(
                "package main\n\nfunc users(c *mongo.Collection, name string) {{\n\tfilter := {code}\n\tc.Find(ctx, filter)\n}}\n"
            )
        },
        &[
            (
                "bson.M{\"$where\": \"this.name == '\" + name + \"'\"}",
                true,
            ),
            (
                "bson.M{\"$where\": fmt.Sprintf(\"this.name == '%s'\", name)}",
                true,
            ),
            (
                "bson.D{{\"$where\", \"this.name == '\" + name + \"'\"}}",
                true,
            ),
            (
                "bson.D{{Key: \"$where\", Value: \"this.name == '\" + name + \"'\"}}",
                true,
            ),
            ("bson.M{\"$where\": \"this.age > 18\"}", false),
            ("bson.D{{\"$where\", \"this.age > 18\"}}", false),
            ("bson.M{\"name\": \"a\" + name}", false),
            ("bson.D{{Key: \"name\", Value: \"a\" + name}}", false),
        ],
    );
}

#[test]
fn the_mongodb_packages_are_off_the_unread_list() {
    let rule = rules().rules().find(|r| r.id == RULE).unwrap();
    let listed = |ecosystem: &str, package: &str| {
        rule.unread_packages
            .get(ecosystem)
            .is_some_and(|p| p.contains_key(package))
    };
    for (ecosystem, package) in [
        ("npm", "mongoose"),
        ("npm", "mongodb"),
        ("Python", "pymongo"),
        ("Go", "go.mongodb.org/mongo-driver"),
        ("Go", "go.mongodb.org/mongo-driver/v2"),
    ] {
        assert!(!listed(ecosystem, package), "{ecosystem}: {package}");
    }
    // The setup: the list is still read.
    assert!(
        rule.unread_packages.contains_key("npm") && rule.unread_packages.contains_key("Python")
    );
}

#[test]
fn a_chained_name_with_a_dollar_still_narrows_by_name() {
    // `.$where` is a chained call like knex's `.whereRaw`: listed among the names, it narrows what a
    // file that did not parse cleanly holds back; not listed, it does not.
    assert!(names_only("^(query|\\$where)$|\\.(?:\\$where)$"));
    assert!(!names_only("^(query)$|\\.(?:\\$where)$"));
    assert!(!names_only("^(query|where)$|\\.(?:\\$where)$"));
}
