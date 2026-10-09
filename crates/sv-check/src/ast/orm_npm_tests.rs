//! `ast.sql-built-by-hand` reading TypeORM's query builder, Sequelize's `literal`, and Drizzle's
//! `sql.raw` (the gap analysis of 7 October 2026, finding 1, first half). Each package came off the
//! rule's `unreadPackages` list when every call named here was read, so each call has a case that
//! must be found and one that must not.

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

fn check(cases: &[(&str, bool)]) {
    for language in ["javascript", "typescript"] {
        for (code, expected) in cases {
            let source = format!(
                "module.exports = async (repo, qb, db, sql, Sequelize, d3, name, col, n, id) => {code};\n"
            );
            assert_eq!(
                found(language, &source),
                *expected,
                "{language}: `{code}` should{} be reported",
                if *expected { "" } else { " not" }
            );
        }
    }
}

#[test]
fn typeorm_query_builder_calls_are_read() {
    check(&[
        (
            "repo.createQueryBuilder('u').where(\"u.name = '\" + name + \"'\").getMany()",
            true,
        ),
        (
            "repo.createQueryBuilder('u').where(`u.name = '${name}'`).getMany()",
            true,
        ),
        ("qb.andWhere('u.age > ' + n)", true),
        ("qb.orWhere(`u.id = ${id}`)", true),
        ("qb.having('count(*) > ' + n)", true),
        ("qb.orderBy('u.' + col, 'DESC')", true),
        ("qb.addOrderBy(col + ' desc')", true),
        ("qb.groupBy('u.' + col)", true),
        (
            "repo.createQueryBuilder('u').where('u.name = :name', { name }).getMany()",
            false,
        ),
        ("qb.where({ name })", false),
        ("qb.orderBy('u.createdAt', 'DESC')", false),
        ("qb.where('u.id IN (:...ids)', { ids: [id] })", false),
    ]);
}

#[test]
fn sequelize_literal_is_read() {
    check(&[
        (
            "Sequelize.literal('(SELECT COUNT(*) FROM posts WHERE user_id = ' + id + ')')",
            true,
        ),
        ("Sequelize.literal(`name = '${name}'`)", true),
        (
            "Sequelize.literal('(SELECT COUNT(*) FROM posts WHERE posts.user_id = User.id)')",
            false,
        ),
    ]);
}

#[test]
fn drizzle_raw_is_read_and_its_template_is_not_a_finding() {
    check(&[
        (
            "db.execute(sql.raw(\"SELECT * FROM users WHERE name = '\" + name + \"'\"))",
            true,
        ),
        (
            "db.execute(sql.raw(`SELECT * FROM users WHERE name = '${name}'`))",
            true,
        ),
        (
            "db.execute(sql`SELECT * FROM users WHERE name = ${name}`)",
            false,
        ),
        ("db.execute(sql.raw('SELECT 1'))", false),
    ]);
}

#[test]
fn a_chart_s_select_is_not_a_query() {
    check(&[
        ("d3.select('#' + id).append('svg')", false),
        ("d3.selectAll('.' + col)", false),
    ]);
}

#[test]
fn typeorm_sequelize_and_drizzle_are_off_the_unread_list() {
    let rule = rules().rules().find(|r| r.id == RULE).unwrap();
    let listed = |package: &str| {
        rule.unread_packages
            .get("npm")
            .is_some_and(|p| p.contains_key(package))
    };
    assert!(
        listed("mongoose") && listed("@supabase/supabase-js"),
        "the rest stays"
    );
    for package in ["typeorm", "sequelize", "drizzle-orm"] {
        assert!(
            !listed(package),
            "{package} is read, so it holds nothing back"
        );
    }
}
