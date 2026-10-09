//! `ast.token-none-algorithm` (the gap analysis of 7 October 2026, finding 11, its last part): a token
//! check whose accepted algorithms include `none`, so a token with no signature passes (V9.1.2). Its
//! own file, so its cases do not land at the end of `tests.rs`.

use super::*;
use std::path::PathBuf;

const RULE: &str = "ast.token-none-algorithm";

fn rules() -> &'static AstRules {
    static RULES: OnceLock<AstRules> = OnceLock::new();
    RULES.get_or_init(|| {
        AstRules::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"))
            .expect("rules load")
    })
}

/// Whether the rule reports `source`, read as `file`. A file the parser could not read fails the
/// test rather than reading as clean.
fn reported(language: &str, file: &str, source: &str) -> bool {
    let read = read_file(rules(), language, file, source);
    assert!(!read.parse_error, "{file} did not parse: {source}");
    assert!(
        read.broken.is_empty(),
        "a query did not compile: {:?}",
        read.broken
    );
    read.findings.iter().any(|f| f.rule_id == RULE)
}

fn check(language: &str, file: &str, wrap: impl Fn(&str) -> String, cases: &[(&str, bool)]) {
    for (code, expected) in cases {
        assert_eq!(
            reported(language, file, &wrap(code)),
            *expected,
            "{language}: `{code}` should{} be reported",
            if *expected { "" } else { " not" }
        );
    }
}

#[test]
fn python_lists_with_none_are_found() {
    check(
        "python",
        "auth.py",
        |code| format!("import jwt\n\ndef user(token, key):\n    return {code}\n"),
        &[
            ("jwt.decode(token, key, algorithms=[\"none\"])", true),
            (
                "jwt.decode(token, key, algorithms=[\"HS256\", \"none\"])",
                true,
            ),
            ("jwt.decode(token, key, algorithms=['None'])", true),
            ("jose_jwt.decode(token, key, algorithms=(\"none\",))", true),
            ("jwt.decode(token, key, algorithms=[\"HS256\"])", false),
            (
                "jwt.decode(token, key, algorithms=[\"RS256\", \"ES256\"])",
                false,
            ),
            // `none` somewhere else in the call is not the list of algorithms.
            (
                "jwt.decode(token, key, algorithms=[\"HS256\"], audience=\"none\")",
                false,
            ),
            ("render(template, mode=\"none\")", false),
        ],
    );
}

const JAVASCRIPT: &[(&str, bool)] = &[
    ("jwt.verify(token, key, { algorithms: ['none'] })", true),
    (
        "jwt.verify(token, key, { algorithms: ['HS256', 'none'] })",
        true,
    ),
    (
        "jwt.verify(token, key, { \"algorithms\": [\"none\"] })",
        true,
    ),
    ("jwt.verify(token, key, { algorithms: ['HS256'] })", false),
    (
        "jwt.verify(token, key, { algorithms: ['RS256'], audience: 'none' })",
        false,
    ),
    ("element.style = { display: 'none' }", false),
];

#[test]
fn javascript_and_typescript_lists_with_none_are_found() {
    let wrap =
        |code: &str| format!("function user(jwt, token, key, element) {{\n  return {code};\n}}\n");
    check("javascript", "auth.js", wrap, JAVASCRIPT);
    check("typescript", "auth.ts", wrap, JAVASCRIPT);
}

#[test]
fn go_methods_with_none_are_found() {
    check(
        "go",
        "auth.go",
        |code| format!("package main\n\nfunc parse(s string) {{\n\t{code}\n}}\n"),
        &[
            (
                "jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{\"none\"}))",
                true,
            ),
            (
                "jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{\"HS256\", \"none\"}))",
                true,
            ),
            (
                "jwt.Parse(s, func(t *jwt.Token) (interface{}, error) { return jwt.UnsafeAllowNoneSignatureType, nil })",
                true,
            ),
            (
                "jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{\"HS256\"}))",
                false,
            ),
            ("jwt.Parse(s, keyFunc)", false),
            ("fmt.Println(\"none\")", false),
        ],
    );
}

#[test]
fn ruby_algorithms_with_none_are_found() {
    check(
        "ruby",
        "auth.rb",
        |code| format!("def user(token, key)\n  {code}\nend\n"),
        &[
            ("JWT.decode(token, key, true, { algorithm: 'none' })", true),
            (
                "JWT.decode(token, key, true, algorithms: ['HS256', 'none'])",
                true,
            ),
            (
                "JWT.decode(token, key, true, { algorithm: 'HS256' })",
                false,
            ),
            ("render json: { status: 'none' }", false),
        ],
    );
}
