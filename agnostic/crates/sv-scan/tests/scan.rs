//! Scanner tests against fixture apps that each exist to break one assumption.

use std::path::PathBuf;
use sv_frameworks::Condition;
use sv_scan::{Evidence, ScanReport, Signatures, scan};

fn data(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

fn signatures() -> Signatures {
    Signatures::load(&data("tech-signatures.json")).expect("signatures load")
}

/// Both sets, as the CLI loads them.
fn all_signatures() -> Signatures {
    Signatures::load_all(&[
        &data("tech-signatures.json"),
        &data("claim-corroborators.json"),
    ])
    .expect("signatures load")
}

fn scan_fixture_with(name: &str, sigs: &Signatures) -> ScanReport {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    scan(&dir, sigs).expect("scan")
}

fn scan_fixture(name: &str) -> ScanReport {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    scan(&dir, &signatures()).expect("scan")
}

fn answer(report: &ScanReport, c: Condition) -> &sv_scan::Answer {
    report
        .answers
        .iter()
        .find(|a| a.condition == c)
        .expect("condition answered")
}

#[test]
fn a_standard_library_xml_parser_is_found_even_though_nothing_declares_it() {
    // The fixture this scanner exists for. `xml.etree` ships with Python: no requirements entry,
    // no lockfile line, nothing for a dependency scan to see. A dependency-only scanner would
    // answer "no XML parser is used" and switch off V1.5.1 — an XXE requirement — for an app that
    // parses attacker-supplied XML in its very first route.
    let report = scan_fixture("stdlib-xml-python");
    assert!(
        !report
            .declared
            .iter()
            .any(|d| d.name.to_lowercase().contains("xml")),
        "the fixture must declare no XML dependency, or it is not testing anything"
    );
    let xml = answer(&report, Condition::Xml);
    assert_eq!(xml.value, Some(true));
    assert!(
        matches!(&xml.evidence, Evidence::Source { file, .. } if file == "app.py"),
        "expected source evidence from app.py, got {:?}",
        xml.evidence
    );
}

#[test]
fn a_declared_dependency_answers_its_condition() {
    let report = scan_fixture("node-websockets");
    let ws = answer(&report, Condition::Websockets);
    assert_eq!(ws.value, Some(true));
    assert!(
        matches!(&ws.evidence, Evidence::Dependency { name, manifest }
            if name == "ws" && manifest == "package.json"),
        "expected the ws dependency as evidence, got {:?}",
        ws.evidence
    );
}

#[test]
fn source_sv_cannot_read_makes_every_absence_unknown() {
    // A Swift file `sv` has no reader for. It cannot say GraphQL is absent from an app it has only
    // partly read, and "I did not find it" must not be reported as "it is not there".
    let report = scan_fixture("unreadable-language");
    assert!(report.unread_extensions.contains("swift"));
    let graphql = answer(&report, Condition::Graphql);
    assert_eq!(
        graphql.value, None,
        "an unread language must leave absences unknown, not false"
    );
    assert!(matches!(graphql.evidence, Evidence::Incomplete { .. }));
}

#[test]
fn a_fully_read_app_can_say_a_technology_is_absent() {
    // The other side of the rule. Without this, the scanner could never conclude anything and
    // every requirement would sit at not-assessed for ever, which is honest and useless.
    let report = scan_fixture("pinned-clean");
    assert!(report.unread_extensions.is_empty());
    let graphql = answer(&report, Condition::Graphql);
    assert_eq!(graphql.value, Some(false));
    assert!(matches!(graphql.evidence, Evidence::NothingFound { .. }));
}

#[test]
fn a_language_that_has_no_format_strings_is_not_credited_with_them() {
    // JavaScript has no C-style format strings; Python does. The inherited v1 reason for V1.3.10
    // said "Node.js does not have C-style format strings", which was true of v1's own template and
    // false of the Python app it was later applied to.
    let node = scan_fixture("pinned-clean");
    assert_eq!(answer(&node, Condition::FormatStrings).value, Some(false));

    let python = scan_fixture("stdlib-xml-python");
    let fs = answer(&python, Condition::FormatStrings);
    assert_eq!(
        fs.value,
        Some(true),
        "Python has format strings user input can reach"
    );
    assert!(matches!(&fs.evidence, Evidence::Language { language } if language == "python"));
}

#[test]
fn jndi_is_absent_from_an_app_with_no_jvm_source() {
    let report = scan_fixture("stdlib-xml-python");
    assert_eq!(answer(&report, Condition::Jndi).value, Some(false));
}

#[test]
fn every_derived_condition_has_a_signature() {
    // A `derived` condition with no signature would sit unanswered for ever while looking like an
    // oversight nobody notices. If one is added to the enum, this fails until it is described.
    let sigs = signatures();
    let described: Vec<&str> = sigs
        .signatures
        .iter()
        .map(|s| s.condition.as_str())
        .collect();
    let missing: Vec<&str> = Condition::ALL
        .iter()
        .filter(|c| c.source() == sv_frameworks::Source::Derived)
        .map(|c| c.name())
        .filter(|n| !["always", "never"].contains(n))
        .filter(|n| !described.contains(n))
        .collect();
    assert!(
        missing.is_empty(),
        "derived conditions with no signature: {missing:?}"
    );
}

#[test]
fn the_scanner_ignores_installed_dependencies() {
    // node_modules is other people's code. Scanning it would make every condition true everywhere.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pinned-clean");
    let modules = dir.join("node_modules/evil");
    std::fs::create_dir_all(&modules).unwrap();
    std::fs::write(
        modules.join("index.js"),
        "const x = new WebSocket('ws://x');",
    )
    .unwrap();
    let report = scan(&dir, &signatures()).unwrap();
    let ws = answer(&report, Condition::Websockets);
    std::fs::remove_dir_all(dir.join("node_modules")).ok();
    assert_eq!(
        ws.value,
        Some(false),
        "a WebSocket inside node_modules is a dependency's business, not this app's"
    );
}

#[test]
fn a_standard_library_xml_parser_is_found_in_go_too() {
    // A second witness for the source scan, in a different language with a different stdlib. The
    // Python fixture alone would make the source step look like it worked by accident.
    let report = scan_fixture("go-stdlib-xml");
    assert!(
        report.declared.is_empty(),
        "go.mod declares nothing in this fixture"
    );
    let xml = answer(&report, Condition::Xml);
    assert_eq!(xml.value, Some(true));
    assert!(
        matches!(&xml.evidence, Evidence::Source { file, .. } if file == "main.go"),
        "expected source evidence from main.go, got {:?}",
        xml.evidence
    );
}

#[test]
fn nothing_is_ever_answered_false_while_files_go_unread() {
    // The general form, rather than one condition's version of it. Any absence concluded from a
    // partial read is a wrong statement in a report, whichever condition it happens to be.
    let report = scan_fixture("unreadable-language");
    assert!(
        !report.unread_extensions.is_empty(),
        "the fixture must contain unread source"
    );
    let wrongly_absent: Vec<&str> = report
        .answers
        .iter()
        .filter(|a| a.value == Some(false))
        .map(|a| a.condition.name())
        .collect();
    assert!(
        wrongly_absent.is_empty(),
        "concluded absent from a partly-read app: {wrongly_absent:?}"
    );
}

#[test]
fn an_ecosystem_that_pins_nothing_cannot_rule_a_dependency_out() {
    // requirements.txt without a lockfile: the declared names are not what is installed, so an
    // absent dependency is not evidence of an absent technology. v1's ecosystems.ts already made
    // this point — an ecosystem in use that pins nothing means nobody can say what is there.
    let report = scan_fixture("unpinned-python");
    assert!(!report.unpinned.is_empty(), "the fixture must pin nothing");
    let ldap = answer(&report, Condition::Ldap);
    assert_eq!(
        ldap.value, None,
        "an unpinned ecosystem cannot rule out a package-based technology"
    );
    assert!(matches!(ldap.evidence, Evidence::Incomplete { .. }));
}

#[test]
fn an_unpinned_ecosystem_still_answers_what_it_can_see() {
    // The limit of the rule above: not knowing what is installed does not stop `sv` reading the
    // app's own source. Python is present, so format strings are present, pinning or no pinning.
    let report = scan_fixture("unpinned-python");
    assert_eq!(answer(&report, Condition::FormatStrings).value, Some(true));
}

#[test]
fn the_pinning_rule_is_not_a_python_quirk() {
    // A second witness in a different ecosystem: package.json with no lockfile. `^4.18.0` is a
    // range, so the installed tree is not the declared one, and an absent name proves nothing.
    let report = scan_fixture("unpinned-npm");
    assert!(report.unpinned.iter().any(|e| e.name == "npm"));
    assert_eq!(answer(&report, Condition::Graphql).value, None);
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-scan-{name}"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn reading_nothing_at_all_answers_nothing() {
    // A scan that did not run is not a clean result. An empty folder must not come back as "none
    // of these technologies are used", which reads exactly like a thorough scan that found none.
    let dir = scratch("empty");
    let report = scan(&dir, &signatures()).unwrap();
    assert_eq!(report.files_read, 0);
    let concluded: Vec<&str> = report
        .answers
        .iter()
        .filter(|a| a.value.is_some())
        .map(|a| a.condition.name())
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        concluded.is_empty(),
        "concluded from an empty folder: {concluded:?}"
    );
}

#[test]
fn a_folder_of_only_skipped_directories_answers_nothing_either() {
    // The same rule reached a different way: everything present was skipped, so nothing was read.
    // Without this the empty-folder test is the only witness, and one witness is an accident.
    let dir = scratch("skipped");
    std::fs::create_dir_all(dir.join("node_modules/left-pad")).unwrap();
    std::fs::write(
        dir.join("node_modules/left-pad/index.js"),
        "module.exports = 1;",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    let report = scan(&dir, &signatures()).unwrap();
    assert_eq!(report.files_read, 0);
    let concluded = report.answers.iter().filter(|a| a.value.is_some()).count();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        concluded, 0,
        "everything here was skipped, so nothing was read"
    );
}

// ---- corroborators: checking the manifest's claims against the code ----

#[test]
fn a_claim_that_can_be_hand_rolled_is_never_called_absent() {
    // The rule the corroborators exist under. Sign-in can be built from a hash function and a
    // database table, leaving no library behind. `pinned-clean` is an Express app with no auth
    // package at all — and `sv` must answer "I could not tell", not "this app has no sign-in".
    // Answering false here would exclude fifty-three ASVS requirements on the strength of a
    // missing dependency.
    let report = scan_fixture_with("pinned-clean", &all_signatures());
    let auth = answer(&report, Condition::Auth);
    assert_eq!(
        auth.value, None,
        "no auth library is not the same as no sign-in"
    );
    assert!(matches!(
        auth.evidence,
        Evidence::NotFoundButNotDecisive { .. }
    ));
}

#[test]
fn a_payment_sdk_contradicts_a_manifest_that_denies_payments() {
    let report = scan_fixture_with("stripe-checkout", &all_signatures());
    let payments = answer(&report, Condition::Payments);
    assert_eq!(payments.value, Some(true));
    assert!(
        matches!(&payments.evidence, Evidence::Dependency { name, .. } if name == "stripe"),
        "expected the stripe dependency as evidence, got {:?}",
        payments.evidence
    );
}

#[test]
fn configuration_in_the_repository_can_be_ruled_out_because_it_is_a_file() {
    // The exception to the rule above, and the reason `absenceIsEvidence` exists. A CI pipeline
    // is a file in the repository: if it is not there, there is no pipeline.
    let with_ci = scan_fixture_with("stripe-checkout", &all_signatures());
    assert_eq!(answer(&with_ci, Condition::CiCd).value, Some(true));
    assert!(matches!(
        answer(&with_ci, Condition::CiCd).evidence,
        Evidence::File { .. }
    ));

    let without = scan_fixture_with("pinned-clean", &all_signatures());
    assert_eq!(
        answer(&without, Condition::CiCd).value,
        Some(false),
        "no workflow file means no pipeline, and that is an answer"
    );
}

#[test]
fn a_dot_directory_is_not_skipped_when_the_pipeline_lives_in_one() {
    // `.github` is a dot-directory and is exactly where CI lives. A blanket dot-skip in the walk
    // would answer "no CI/CD" for every repository that has one — a wrong statement in a report
    // produced by an optimisation.
    let report = scan_fixture_with("stripe-checkout", &all_signatures());
    assert!(
        report.all_paths.iter().any(|p| p.contains(".github")),
        "the walk must see .github, saw: {:?}",
        report.all_paths
    );
}

#[test]
fn every_claim_corroborator_names_a_condition_that_exists() {
    // A typo in the data file would otherwise sit there doing nothing, looking like a claim that
    // simply never corroborates.
    let sigs = all_signatures();
    let unknown: Vec<&str> = sigs
        .signatures
        .iter()
        .map(|s| s.condition.as_str())
        .filter(|n| Condition::from_name(n).is_none())
        .collect();
    assert!(
        unknown.is_empty(),
        "signatures naming no known condition: {unknown:?}"
    );
}

#[test]
fn only_file_based_claims_treat_absence_as_evidence() {
    // If a future edit sets absenceIsEvidence on a library-based claim, fifty-three requirements
    // quietly switch off the next time an app has hand-rolled sign-in. This is the guard.
    let sigs = Signatures::load(&data("claim-corroborators.json")).unwrap();
    let decisive: Vec<&str> = sigs
        .signatures
        .iter()
        .filter(|s| s.absence_is_evidence)
        .map(|s| s.condition.as_str())
        .collect();
    assert_eq!(
        decisive,
        vec!["ci-cd", "iac"],
        "only configuration that must be a file in the repository may be ruled out by its absence"
    );
    for sig in sigs.signatures.iter().filter(|s| s.absence_is_evidence) {
        assert!(
            !sig.files.is_empty(),
            "{} rules itself out by absence but names no files to look for",
            sig.condition
        );
    }
}

#[test]
fn no_hand_rollable_claim_is_ever_ruled_out_on_a_real_app() {
    // The general form of the rule, rather than `auth`'s version of it. `pinned-clean` is a plain
    // Express app: it has no auth, no uploads, no payments, no email, no scheduler and no AI. The
    // tempting answer is "false" to all of them, and that answer is wrong for every one, because
    // each can be written by hand and leave nothing behind. Only the two file-based claims may be
    // ruled out here.
    let sigs = Signatures::load(&data("claim-corroborators.json")).unwrap();
    let report = scan_fixture_with("pinned-clean", &all_signatures());
    for sig in sigs.signatures.iter().filter(|s| !s.absence_is_evidence) {
        let condition = Condition::from_name(&sig.condition).unwrap();
        assert_ne!(
            answer(&report, condition).value,
            Some(false),
            "{} was ruled out although it can be written by hand",
            sig.condition
        );
    }
}
