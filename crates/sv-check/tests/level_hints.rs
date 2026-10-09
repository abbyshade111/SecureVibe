//! What the app's own code shows that the answers setting its level do not (gap analysis of 7
//! October 2026, finding 17; ADR-024, Later, 9 October 2026).

use std::collections::BTreeSet;
use std::path::PathBuf;
use sv_check::level_hints::{Answers, Hint, Hints, SIGN_UP, find, question};
use sv_scan::files::Listing;

fn hints() -> Hints {
    Hints::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/level-hints.json"))
        .expect("the list loads")
}

/// The hints for an app made of `files`, with these answers and these folders set apart.
fn found(
    name: &str,
    files: &[(&str, &str)],
    private_audience: bool,
    listed: &[&str],
    set_apart: &[&str],
) -> Vec<Hint> {
    let dir = std::env::temp_dir().join(format!("sv-level-hints-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    for (path, text) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let listing = Listing::of(&dir);
    // The setup: every file is in the listing, or "not found" below would test nothing.
    for (path, _) in files {
        assert!(
            listing.files.iter().any(|e| e.relative == *path),
            "{path} was not listed"
        );
    }
    let listed: Vec<String> = listed.iter().map(|s| (*s).to_owned()).collect();
    let set_apart: BTreeSet<String> = set_apart.iter().map(|s| (*s).to_owned()).collect();
    let out = find(
        &listing,
        &hints(),
        &Answers {
            private_audience,
            listed: &listed,
        },
        &set_apart,
    );
    std::fs::remove_dir_all(&dir).ok();
    out
}

const SIGNUP: (&str, &str) = (
    "app.py",
    "from flask import Flask\napp = Flask(__name__)\n\n@app.route(\"/register\", methods=[\"POST\"])\ndef register():\n    return 'ok'\n",
);

#[test]
fn a_sign_up_route_beside_a_private_audience_is_asked_about() {
    let out = found("signup", &[SIGNUP], true, &[], &[]);
    assert_eq!(
        out,
        vec![Hint {
            kind: SIGN_UP.to_owned(),
            seen: "/register".to_owned(),
            file: "app.py".to_owned(),
            line: 4,
        }]
    );
    let said = question(&out).expect("a question");
    assert!(
        said.contains("a sign-up page open to strangers (`/register`, app.py line 4)"),
        "{said}"
    );
    assert!(said.contains("only a hint"), "{said}");
}

#[test]
fn a_sign_up_route_is_not_asked_about_when_the_audience_already_says_strangers() {
    // Customers or the public already hold the app to level 2; nothing is asked there, but the
    // finder is also given the answer, so a public audience never makes this question.
    assert!(found("public", &[SIGNUP], false, &[], &[]).is_empty());
}

#[test]
fn routes_in_every_usual_quoting_count_and_longer_names_do_not() {
    for (name, line, seen) in [
        ("express", "app.post('/signup', handler)\n", Some("/signup")),
        (
            "template",
            "router.get(`/sign-up/`, page)\n",
            Some("/sign-up"),
        ),
        ("query", "fetch(\"/join?team=1\")\n", Some("/join")),
        ("nested", "path(\"/users/new\", view)\n", Some("/users/new")),
        ("longer", "app.get('/registered-devices', list)\n", None),
        ("inner", "app.get('/api/register', x)\n", None),
        ("bare", "register = True\n", None),
    ] {
        let out = found(name, &[("server.js", line)], true, &[], &[]);
        assert_eq!(
            out.first().map(|h| h.seen.as_str()),
            seen,
            "{line:?}: {out:?}"
        );
    }
}

#[test]
fn field_names_for_sensitive_information_are_asked_about_in_any_spelling() {
    for (name, line, kind) in [
        ("snake", "blood_pressure = Column(Integer)\n", "health"),
        ("camel", "const bloodPressure = row.value;\n", "health"),
        ("upper", "SSN_FIELD = 1; ssn = form['x']\n", "government-id"),
        ("card", "card_number: str\n", "payment-card"),
        ("bank", "iban = models.CharField()\n", "financial"),
    ] {
        let out = found(name, &[("models.py", line)], false, &[], &[]);
        assert_eq!(
            out.iter().map(|h| h.kind.as_str()).collect::<Vec<_>>(),
            vec![kind],
            "{line:?}"
        );
    }
}

#[test]
fn a_name_inside_a_longer_name_is_not_a_match() {
    // `assn` and `ssnake` hold `ssn`; `ivan` holds nothing; `prescriptionless` is another word.
    let out = found(
        "inside",
        &[(
            "app.py",
            "assn = 1\nssnake = 2\nivan = 'name'\nprescriptionless = True\n",
        )],
        true,
        &[],
        &[],
    );
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn a_category_already_listed_is_not_asked_about() {
    let files = [(
        "models.py",
        "diagnosis = Column(Text)\niban = Column(Text)\n",
    )];
    let all = found("unlisted", &files, false, &[], &[]);
    assert_eq!(all.len(), 2, "the setup: both are found unlisted: {all:?}");
    let out = found("listed", &files, false, &["health"], &[]);
    assert_eq!(
        out.iter().map(|h| h.kind.as_str()).collect::<Vec<_>>(),
        vec!["financial"]
    );
}

#[test]
fn tests_and_folders_set_apart_are_not_read() {
    let in_tests = found(
        "tests",
        &[("tests/test_models.py", "diagnosis = 'flu'\n")],
        true,
        &[],
        &[],
    );
    assert!(in_tests.is_empty(), "{in_tests:?}");
    let apart = found(
        "apart",
        &[("vendor/old/app.py", "diagnosis = 'flu'\n")],
        true,
        &[],
        &["vendor/old"],
    );
    assert!(apart.is_empty(), "{apart:?}");
    // The control: the same file, not set apart, is read.
    let read = found(
        "not-apart",
        &[("vendor/old/app.py", "diagnosis = 'flu'\n")],
        true,
        &[],
        &[],
    );
    assert_eq!(read.len(), 1, "{read:?}");
}

#[test]
fn files_that_are_not_code_are_not_read() {
    let out = found(
        "prose",
        &[("README.md", "We never store a diagnosis. See /register.\n")],
        true,
        &[],
        &[],
    );
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn an_app_with_none_of_them_gets_no_question() {
    let out = found("clean", &[("app.py", "print('hello')\n")], true, &[], &[]);
    assert!(out.is_empty());
    assert_eq!(question(&out), None);
}

#[test]
fn one_hint_per_kind_sign_up_first_and_the_first_place_seen() {
    let out = found(
        "order",
        &[
            ("a.py", "medication = 1\ndiagnosis = 2\n"),
            ("b.py", "@app.route('/signup')\nssn = 3\n"),
        ],
        true,
        &[],
        &[],
    );
    let kinds: Vec<&str> = out.iter().map(|h| h.kind.as_str()).collect();
    // Categories in alphabetical order, whatever order the files are read in.
    assert_eq!(kinds, vec![SIGN_UP, "government-id", "health"], "{out:?}");
    assert_eq!((out[2].file.as_str(), out[2].line), ("a.py", 1));
    let said = question(&out).unwrap();
    assert!(
        said.contains(
            ", government ID information (`ssn`, b.py line 2), and health information (`medication`, a.py line 1)"
        ),
        "{said}"
    );
}

#[test]
fn a_public_audience_still_hears_about_fields_but_not_sign_up() {
    // The audience decides only the sign-up question: the fields are asked about either way.
    let files = [("app.py", "@app.route('/signup')\ndiagnosis = 1\n")];
    let private = found("mixed-private", &files, true, &[], &[]);
    assert_eq!(private.len(), 2, "the setup: both found: {private:?}");
    let public = found("mixed-public", &files, false, &[], &[]);
    assert_eq!(
        public.iter().map(|h| h.kind.as_str()).collect::<Vec<_>>(),
        vec!["health"]
    );
}

#[test]
fn a_listed_category_in_another_spelling_is_still_listed() {
    let files = [("models.py", "diagnosis = Column(Text)\n")];
    assert_eq!(
        found("spelled-none", &files, false, &[], &[]).len(),
        1,
        "the setup"
    );
    for written in ["Health", " health ", "HEALTH"] {
        let out = found("spelled", &files, false, &[written], &[]);
        assert!(out.is_empty(), "{written:?}: {out:?}");
    }
}

#[test]
fn camel_case_matches_a_name_listed_with_underscores() {
    let out = found(
        "camel-card",
        &[("form.ts", "const cardNumber: string = input.value;\n")],
        false,
        &[],
        &[],
    );
    assert_eq!(
        out.first().map(|h| h.seen.as_str()),
        Some("cardNumber"),
        "{out:?}"
    );
}

#[test]
fn a_longer_field_holding_a_name_is_another_name() {
    // `patient_diagnosis_code` holds `diagnosis`; `income_tax_bracket` holds `income`. Each is its
    // own name, and a hint is only ever a whole one.
    let out = found(
        "holds",
        &[(
            "app.py",
            "patient_diagnosis_code = 1\nincome_tax_bracket = 2\n",
        )],
        false,
        &[],
        &[],
    );
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn a_test_file_beside_the_app_is_not_read() {
    // Test files by their own name, not only by folder.
    let out = found(
        "test-name",
        &[
            ("test_app.py", "diagnosis = 1\n"),
            ("app.test.js", "app.get('/signup')\n"),
        ],
        true,
        &[],
        &[],
    );
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn spaces_around_a_listed_category_are_not_part_of_its_name() {
    // The manifest reads `"\tfinancial "` as `financial` (ADR-024, Later, 6 October 2026); so
    // does this, or a category it counts as listed would be asked about all the same.
    let files = [("models.py", "iban = Column(Text)\n")];
    assert_eq!(
        found("spaces-none", &files, false, &[], &[]).len(),
        1,
        "the setup"
    );
    let out = found("spaces", &files, false, &["\tfinancial "], &[]);
    assert!(out.is_empty(), "{out:?}");
}
