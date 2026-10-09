//! `ast.sql-built-by-hand` reading Django's `.extra` and `RawSQL`, and Laravel's `DB::` static calls
//! and `...Raw` methods (the gap analysis of 7 October 2026, finding 1, first half). Each package
//! came off the rule's `unreadPackages` list when every call named here was read, so each call has a
//! case that must be found and one that must not.

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

fn found(language: &str, source: &str) -> bool {
    scan_file(rules(), language, &format!("src/app.{language}"), source)
        .iter()
        .any(|f| f.rule_id == RULE)
}

#[test]
fn django_extra_and_rawsql_are_read() {
    let cases = [
        ("User.objects.extra(where=[\"name = '%s'\" % name])", true),
        (
            "User.objects.extra(where=[\"name = '\" + name + \"'\"])",
            true,
        ),
        ("User.objects.extra(where=[f\"name = '{name}'\"])", true),
        (
            "User.objects.extra(select={\"n\": \"age > {}\".format(age)})",
            true,
        ),
        (
            "User.objects.annotate(n=RawSQL(\"SELECT count(*) FROM t WHERE x = \" + name, []))",
            true,
        ),
        (
            "User.objects.annotate(n=RawSQL(f\"SELECT count(*) FROM t WHERE x = {name}\", []))",
            true,
        ),
        (
            "df = read_sql(f\"SELECT * FROM t WHERE name = '{name}'\", conn)",
            true,
        ),
        (
            "User.objects.extra(where=[\"name = %s\"], params=[name])",
            false,
        ),
        (
            "User.objects.extra(select={\"is_recent\": \"created > now() - interval '1 day'\"})",
            false,
        ),
        (
            "User.objects.annotate(n=RawSQL(\"SELECT count(*) FROM t WHERE x = %s\", (name,)))",
            false,
        ),
        (
            "df = read_sql(\"SELECT * FROM t WHERE name = %s\", conn, params=[name])",
            false,
        ),
    ];
    for (code, expected) in cases {
        let source = format!("def view(request, name, age, conn):\n    return {code}\n");
        assert_eq!(
            found("python", &source),
            expected,
            "python: `{code}` should{} be reported",
            if expected { "" } else { " not" }
        );
    }
}

#[test]
fn laravel_db_calls_and_raw_methods_are_read() {
    let cases = [
        (
            "DB::select(\"SELECT * FROM users WHERE name = '\" . $name . \"'\");",
            true,
        ),
        (
            "DB::select(\"SELECT * FROM users WHERE name = '$name'\");",
            true,
        ),
        (
            "DB::select(sprintf(\"SELECT * FROM users WHERE name = '%s'\", $name));",
            true,
        ),
        ("DB::statement('DROP TABLE ' . $table);", true),
        ("DB::unprepared($sql . ';');", true),
        (
            "DB::table('users')->select(DB::raw('count(*) as n, ' . $col))->get();",
            true,
        ),
        (
            "DB::table('users')->whereRaw(\"name = '$name'\")->get();",
            true,
        ),
        ("User::query()->orderByRaw($col . ' desc')->get();", true),
        ("User::query()->selectRaw('price * ' . $rate)->get();", true),
        (
            "DB::select('SELECT * FROM users WHERE name = ?', [$name]);",
            false,
        ),
        (
            "DB::table('users')->whereRaw('name = ?', [$name])->get();",
            false,
        ),
        ("DB::table('users')->select('name', 'email')->get();", false),
        ("$user->update(['name' => $name]);", false),
        ("$user->delete();", false),
        ("DB::table('users')->insert(['name' => $name]);", false),
    ];
    for (code, expected) in cases {
        let source = format!(
            "<?php\nfunction f($name, $table, $sql, $col, $rate, $user) {{\n    {code}\n}}\n"
        );
        assert_eq!(
            found("php", &source),
            expected,
            "php: `{code}` should{} be reported",
            if expected { "" } else { " not" }
        );
    }
}

#[test]
fn django_and_laravel_are_off_the_unread_list() {
    let rule = rules().rules().find(|r| r.id == RULE).unwrap();
    let listed = |ecosystem: &str, package: &str| {
        rule.unread_packages
            .get(ecosystem)
            .is_some_and(|p| p.contains_key(package))
    };
    assert!(
        listed("Python", "pymongo") && listed("npm", "mongoose"),
        "the rest stays"
    );
    for (ecosystem, package) in [
        ("Python", "django"),
        ("PHP", "laravel/framework"),
        ("PHP", "illuminate/database"),
    ] {
        assert!(
            !listed(ecosystem, package),
            "{package} is read, so it holds nothing back"
        );
    }
}
