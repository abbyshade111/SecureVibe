//! `ast.sql-built-by-hand` reading knex's and GORM's own query calls (the gap analysis of 7 October
//! 2026, finding 1, first half). Each package came off the rule's `unreadPackages` list when every
//! call named here was read, so each call has a case that must be found and one that must not.

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
fn knex_raw_calls_are_read() {
    let cases = [
        (
            "db('users').whereRaw(\"name = '\" + req.query.name + \"'\")",
            true,
        ),
        ("db('users').whereRaw(`name = '${req.query.name}'`)", true),
        ("db('users').orWhereRaw('age > ' + req.query.age)", true),
        ("db('users').havingRaw('count(*) > ' + n)", true),
        ("db('users').orderByRaw(req.query.sort + ' desc')", true),
        ("db('users').groupByRaw('date(' + col + ')')", true),
        ("db('users').joinRaw('join t on t.id = ' + id)", true),
        (
            "db.select(db.raw('count(*) as n')).fromRaw('users where id = ' + id)",
            true,
        ),
        ("db('users').whereRaw('name = ?', [req.query.name])", false),
        ("db('users').orderByRaw('created_at desc')", false),
        ("db('users').where({ name: req.query.name })", false),
    ];
    for language in ["javascript", "typescript"] {
        for (code, expected) in cases {
            let source = format!("module.exports = (db, req, n, col, id) => {code};\n");
            assert_eq!(
                found(language, &source),
                expected,
                "{language}: `{code}` should{} be reported",
                if expected { "" } else { " not" }
            );
        }
    }
}

#[test]
fn gorm_raw_clause_and_inline_conditions_are_read() {
    let cases = [
        (
            "db.Raw(\"SELECT * FROM users WHERE name = '\" + name + \"'\").Scan(&u)",
            true,
        ),
        (
            "db.Raw(fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", name)).Scan(&u)",
            true,
        ),
        ("db.Where(\"name = '\" + name + \"'\").Find(&users)", true),
        (
            "db.Where(fmt.Sprintf(\"name = '%s'\", name)).Find(&users)",
            true,
        ),
        ("db.Or(\"age > \" + age).Find(&users)", true),
        ("db.Not(\"name = '\" + name + \"'\").Find(&users)", true),
        ("db.Order(sort + \" desc\").Find(&users)", true),
        ("db.Group(\"date(\" + col + \")\").Find(&users)", true),
        ("db.Having(\"count(*) > \" + n).Find(&users)", true),
        ("db.Joins(\"JOIN t ON t.id = \" + id).Find(&users)", true),
        ("db.Select(\"name, \" + col).Find(&users)", true),
        ("db.Find(&users, \"name = '\" + name + \"'\")", true),
        ("db.First(&u, fmt.Sprintf(\"id = %s\", id))", true),
        (
            "db.Raw(\"SELECT * FROM users WHERE name = ?\", name).Scan(&u)",
            false,
        ),
        ("db.Where(\"name = ?\", name).Find(&users)", false),
        ("db.Where(&User{Name: name}).Find(&users)", false),
        (
            "db.Where(map[string]interface{}{\"name\": name}).Find(&users)",
            false,
        ),
        ("db.Order(\"created_at desc\").Find(&users)", false),
        ("db.Find(&users, \"name = ?\", name)", false),
        ("db.Find(&users)", false),
        ("db.First(&u, id)", false),
    ];
    for (code, expected) in cases {
        let source = format!(
            "package main\n\nfunc f(db *gorm.DB, name, age, sort, col, n, id string) {{\n\t{code}\n}}\n"
        );
        assert_eq!(
            found("go", &source),
            expected,
            "go: `{code}` should{} be reported",
            if expected { "" } else { " not" }
        );
    }
}

#[test]
fn knex_and_gorm_are_off_the_unread_list() {
    let rule = rules().rules().find(|r| r.id == RULE).unwrap();
    let listed = |ecosystem: &str, package: &str| {
        rule.unread_packages
            .get(ecosystem)
            .is_some_and(|p| p.contains_key(package))
    };
    // The list itself is still read: the rest of what #1163 listed is there.
    assert!(listed("npm", "mongoose") && listed("Python", "django"));
    assert!(
        !listed("npm", "knex"),
        "knex's calls are read, so it holds nothing back"
    );
    assert!(
        !listed("Go", "gorm.io/gorm"),
        "GORM's calls are read, so it holds nothing back"
    );
}

#[test]
fn a_chained_call_listed_among_the_names_still_narrows_by_name() {
    // A file that did not parse cleanly holds back only the rules whose call it names; the
    // chained form must not make the JavaScript and TypeScript patterns hold back every file.
    assert!(names_only("^(query|whereRaw)$|\\.(?:whereRaw)$"));
    assert!(
        !names_only("^(query)$|\\.(?:whereRaw)$"),
        "a chained name not among the names"
    );
    assert!(
        !names_only("^(query|whereRaw)$|\\.(?:where.aw)$"),
        "a chained pattern, not a name"
    );
    for language in ["javascript", "typescript"] {
        let c = rules().compiled.iter().find(|c| c.rule.id == RULE).unwrap();
        assert!(names_only(c.function[language].as_str()), "{language}");
    }
}

#[test]
fn the_calls_a_clean_result_names_leave_the_chained_form_out() {
    let (names, more) = calls_named("^(query|whereRaw)$|\\.(?:whereRaw)$").unwrap();
    assert_eq!(names, ["query", "whereRaw"]);
    assert!(!more, "the chained form is not another kind of call");
}
