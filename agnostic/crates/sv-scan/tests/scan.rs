//! Scanner tests against fixture apps that each exist to break one assumption.

use std::collections::BTreeSet;
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
    // A Swift file. The code rules read Swift, but the technology scan does not: it reads no
    // `Package.swift` and has no Swift patterns. It cannot say GraphQL is absent from an app it has
    // only partly looked in, and "I did not find it" must not be reported as "it is not there".
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
    // produced by an optimization.
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

#[test]
fn every_signature_speaks_a_language_and_an_ecosystem_the_scanner_knows() {
    // A misspelled key is the worst kind of mistake this data file can hold, because nothing goes
    // wrong: `evaluate` looks the language up, finds nothing, and moves on. The corroborator is
    // dead, the claim comes back unverified, and that is indistinguishable from an app that simply
    // does not do the thing. Every key is checked against what the scanner actually dispatches on.
    let sigs = all_signatures();
    let known_languages: BTreeSet<&str> = [
        "js", "ts", "py", "java", "kt", "go", "rs", "rb", "php", "cs", "c", "cpp", "html",
    ]
    .iter()
    .filter_map(|ext| sv_scan::ecosystems::language_of(ext))
    .collect();
    let known_ecosystems: BTreeSet<&str> = sv_scan::ecosystems::ECOSYSTEMS
        .iter()
        .map(|e| e.name)
        .collect();

    let mut wrong = Vec::new();
    for sig in &sigs.signatures {
        for language in sig.source.keys() {
            if !known_languages.contains(language.as_str()) {
                wrong.push(format!("{}: source language `{language}`", sig.condition));
            }
        }
        for ecosystem in sig.packages.keys() {
            if !known_ecosystems.contains(ecosystem.as_str()) {
                wrong.push(format!("{}: ecosystem `{ecosystem}`", sig.condition));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "these keys match nothing the scanner dispatches on, so they can never fire: {wrong:#?}"
    );
}

/// One realistic file per claim, written the way somebody would actually write it rather than as a
/// copy of the pattern out of the data file. A corroborator that only matches its own spelling is
/// not a corroborator, and a test that pastes the pattern back in cannot tell the difference.
const WITNESSES: &[(&str, &str, &str)] = &[
    (
        "external-apis",
        "rates.py",
        "import requests\n\ndef latest():\n    r = requests.get(\"https://example.test/v1/rates\", timeout=5)\n    return r.json()\n",
    ),
    (
        "public-api",
        "middleware.js",
        "function requireKey(req, res, next) {\n  const key = req.header('X-API-Key');\n  if (!key) return res.status(401).end();\n  next();\n}\n",
    ),
    (
        "multi-tenant",
        "queries.py",
        "def invoices_for(db, tenant_id):\n    return db.query(\"select * from invoices where tenant_id = ?\", [tenant_id])\n",
    ),
    (
        "tls",
        "serve.go",
        "func main() {\n\tlog.Fatal(http.ListenAndServeTLS(\":443\", \"cert.pem\", \"key.pem\", nil))\n}\n",
    ),
    (
        "internet",
        "app.py",
        "if __name__ == \"__main__\":\n    app.run(host=\"0.0.0.0\", port=8000)\n",
    ),
    (
        "ai-actions",
        "assistant.py",
        "reply = client.chat.completions.create(\n    model=\"gpt-4o\",\n    messages=messages,\n    tools=[book_table, cancel_booking],\n)\nfor call in reply.choices[0].message.tool_calls:\n    dispatch(call)\n",
    ),
    (
        "ai-history",
        "chat.ts",
        "const previous = await db.messages.findMany({ where: { conversationId } });\nconst messages = [...previous, { role: 'user', content: input }];\n",
    ),
    (
        "ai-moderation",
        "screen.py",
        "flagged = client.moderations.create(input=user_text).results[0].flagged\nif flagged:\n    return refuse()\n",
    ),
    (
        "multimodal-ai",
        "describe.py",
        "content = [\n    {\"type\": \"text\", \"text\": prompt},\n    {\"type\": \"image_url\", \"image_url\": {\"url\": data_url}},\n]\n",
    ),
    (
        "multiple-services",
        "orders_client.py",
        "import grpc\nfrom . import inventory_pb2_grpc\n\nchannel = grpc.insecure_channel(\"inventory:50051\")\nstock = inventory_pb2_grpc.InventoryStub(channel)\n",
    ),
    (
        "multiple-services",
        "consumer.ts",
        "@Controller()\nexport class OrdersController {\n  @MessagePattern('order_created')\n  handle(@Payload() order: Order) {\n    return this.billing.charge(order);\n  }\n}\n",
    ),
    (
        "authorization-server",
        "sso.js",
        "const Provider = require('oidc-provider');\n\nconst issuer = new Provider('https://accounts.example.test', {\n  clients: [{ client_id: 'billing', redirect_uris: ['https://billing.example.test/callback'] }],\n});\n\nmodule.exports = issuer.callback();\n",
    ),
    (
        "authorization-server",
        "Startup.cs",
        "public void ConfigureServices(IServiceCollection services)\n{\n    services.AddIdentityServer()\n        .AddInMemoryClients(Config.Clients)\n        .AddDeveloperSigningCredential();\n}\n",
    ),
    (
        "authorization-server",
        "oidc.py",
        "from authlib.integrations.flask_oauth2 import AuthorizationServer\n\nserver = AuthorizationServer(app, query_client=get_client, save_token=save_token)\n",
    ),
];

#[test]
fn every_new_corroborator_fires_on_code_somebody_would_really_write() {
    let sigs = all_signatures();
    for (condition_name, file, contents) in WITNESSES {
        let dir = scratch(&format!("witness-{condition_name}"));
        std::fs::write(dir.join(file), contents).unwrap();
        let report = scan(&dir, &sigs).unwrap();
        let condition = Condition::from_name(condition_name).unwrap();
        let found = answer(&report, condition);
        let value = found.value;
        let evidence = format!("{:?}", found.evidence);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            value,
            Some(true),
            "{condition_name} did not fire on {file}; evidence was {evidence}"
        );
    }
}

#[test]
fn the_file_based_corroborators_fire_on_the_paths_they_name() {
    // The other half of the same coverage: four of the new claims are answered by a path rather
    // than by anything inside a file, and `WITNESSES` above cannot reach them.
    let cases: &[(&str, &str)] = &[
        ("hosted-scm", "CODEOWNERS"),
        ("outside-contributors", "CONTRIBUTING.md"),
        ("public-api", "openapi.yaml"),
        ("tls", "Caddyfile"),
        ("internet", "fly.toml"),
        ("multiple-services", "inventory.proto"),
        ("multiple-services", "asyncapi.yaml"),
    ];
    let sigs = all_signatures();
    for (condition_name, file) in cases {
        let dir = scratch(&format!("path-witness-{condition_name}-{file}"));
        std::fs::write(dir.join(file), "# placeholder\n").unwrap();
        // Something readable, so the scan is not the empty-folder case.
        std::fs::write(dir.join("main.py"), "print('hello')\n").unwrap();
        let report = scan(&dir, &sigs).unwrap();
        let condition = Condition::from_name(condition_name).unwrap();
        let value = answer(&report, condition).value;
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(value, Some(true), "{condition_name} did not fire on {file}");
    }
}

#[test]
fn every_claim_corroborator_has_a_witness() {
    // Deliberate rather than accidental coverage: adding a corroborator to the data file without a
    // witness above fails here, rather than shipping a pattern nobody has ever seen match.
    let sigs = Signatures::load(&data("claim-corroborators.json")).unwrap();
    let witnessed: BTreeSet<&str> = WITNESSES
        .iter()
        .map(|(c, _, _)| *c)
        .chain(["hosted-scm", "outside-contributors"])
        // Checked by `a_claim_nothing_can_check_says_so_rather_than_finding_nothing` instead:
        // there is nothing for a witness to contain.
        .chain(["shared-hostname"])
        // These six predate this work and are covered by the fixture apps above.
        .chain([
            "ci-cd",
            "iac",
            "auth",
            "oauth",
            "jwt",
            "uploads",
            "payments",
            "email",
            "scheduler",
            "webrtc",
            "ai",
            "rag",
            "mcp",
            "training",
            "self-hosted-model",
            "out-of-band-auth",
        ])
        .collect();
    let unwitnessed: Vec<&str> = sigs
        .signatures
        .iter()
        .map(|s| s.condition.as_str())
        .filter(|c| !witnessed.contains(c))
        .collect();
    assert!(
        unwitnessed.is_empty(),
        "corroborators with nothing showing they ever match: {unwitnessed:?}"
    );
}

#[test]
fn a_dockerfile_is_infrastructure_configuration() {
    // `iac` names `Dockerfile` and rules itself out by absence, so an app whose only infrastructure
    // configuration is a Dockerfile was being reported as having none — a false exclusion on a
    // file-based claim, which is the one place absence is allowed to be an answer at all.
    let dir = scratch("dockerfile-only");
    std::fs::write(
        dir.join("Dockerfile"),
        "FROM node:22\nCOPY . /app\nCMD [\"node\", \"server.js\"]\n",
    )
    .unwrap();
    std::fs::write(dir.join("server.js"), "console.log('hi');\n").unwrap();
    let report = scan(&dir, &all_signatures()).unwrap();
    let value = answer(&report, Condition::Iac).value;
    let seen: Vec<String> = report.all_paths.iter().cloned().collect();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        value,
        Some(true),
        "a Dockerfile is infrastructure configuration; paths seen were {seen:?}"
    );
}

#[test]
fn a_claim_nothing_can_check_says_so_rather_than_finding_nothing() {
    // `shared-hostname` is a fact about deployment, not about code. The distinction this test
    // guards is between "I looked and found nothing" and "there was never anywhere to look": the
    // first invites somebody to go and look harder, the second is the final answer. Reporting the
    // second as the first is how a gap in the checks turns into a quiet clean bill of health.
    let sigs = all_signatures();
    let dir = scratch("no-check-exists");
    std::fs::write(dir.join("main.py"), "print('hello')\n").unwrap();
    let report = scan(&dir, &sigs).unwrap();
    let found = answer(&report, Condition::SharedHostname);
    let value = found.value;
    let evidence = found.evidence.clone();
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(value, None, "nothing may be concluded about it either way");
    match evidence {
        Evidence::NoCheckExists { reason } => {
            assert!(
                reason.contains("deployed"),
                "the reason must say why no check is possible: {reason}"
            );
        }
        other => panic!("expected NoCheckExists, got {other:?}"),
    }
}

#[test]
fn a_signature_that_cannot_check_anything_carries_no_patterns() {
    // Otherwise `noCorroborator` becomes a way of switching a real corroborator off while leaving
    // its patterns in the file, where they read as though they still run.
    let sigs = all_signatures();
    for sig in sigs.signatures.iter().filter(|s| s.no_corroborator) {
        assert!(
            sig.packages.is_empty()
                && sig.source.is_empty()
                && sig.files.is_empty()
                && sig.languages.is_empty(),
            "{} says no check is possible but names things to look for",
            sig.condition
        );
        assert!(
            sig.note.len() > 80,
            "{} must explain why nothing can check it",
            sig.condition
        );
    }
}

// ---- dependency names as each ecosystem really writes them ----

/// Writes an app from (path, contents) pairs and scans it with both signature sets.
fn scan_files(name: &str, files: &[(&str, &str)]) -> ScanReport {
    let dir = scratch(name);
    for (path, contents) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let report = scan(&dir, &all_signatures()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    report
}

const GO_WEBSOCKET_APP: &[(&str, &str)] = &[
    (
        "go.mod",
        "module example.com/chat\n\ngo 1.22\n\nrequire (\n\tgithub.com/gorilla/websocket v1.5.3\n\tgithub.com/golang-jwt/jwt/v5 v5.2.1\n)\n",
    ),
    (
        "go.sum",
        "github.com/gorilla/websocket v1.5.3 h1:x\ngithub.com/golang-jwt/jwt/v5 v5.2.1 h1:y\n",
    ),
    // Imported under an alias, which is how the source pattern `websocket.Upgrader` was being
    // missed: the dependency is the evidence here, and it has to be read.
    (
        "main.go",
        "package main\n\nimport (\n\t\"net/http\"\n\tws \"github.com/gorilla/websocket\"\n)\n\nvar up = ws.Upgrader{}\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tc, _ := up.Upgrade(w, r, nil)\n\tdefer c.Close()\n}\n",
    ),
];

#[test]
fn a_go_module_path_matches_the_package_a_signature_names() {
    // Found on a Go app that declared and used gorilla/websocket and had the WebSocket requirements
    // excluded as "no WebSocket library is used": go.mod says `github.com/gorilla/websocket`, the
    // signature says `gorilla/websocket`, and the comparison was exact.
    let report = scan_files("go-websocket", GO_WEBSOCKET_APP);
    let found = answer(&report, Condition::Websockets);
    assert_eq!(found.value, Some(true), "{:?}", found.evidence);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { name, .. } if name == "github.com/gorilla/websocket"),
        "the dependency is what has to answer it: {:?}",
        found.evidence
    );
}

#[test]
fn a_go_major_version_suffix_does_not_hide_the_package() {
    // `/v5` is part of the module path from v2 on, and says nothing about what the package is.
    let report = scan_files("go-jwt-v5", GO_WEBSOCKET_APP);
    let found = answer(&report, Condition::Jwt);
    assert_eq!(found.value, Some(true), "{:?}", found.evidence);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { .. }),
        "{:?}",
        found.evidence
    );
}

#[test]
fn a_go_module_matches_only_on_a_path_boundary() {
    // The tail has to be a whole path segment: `example.com/notgorilla/websocket-docs` is not
    // gorilla/websocket, and neither is a module that merely ends in the same letters.
    let report = scan_files(
        "go-near-miss",
        &[
            (
                "go.mod",
                "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/example/xgorilla/websocket v1.0.0\n\tgithub.com/example/gorilla/websocket-docs v1.0.0\n)\n",
            ),
            (
                "go.sum",
                "github.com/example/xgorilla/websocket v1.0.0 h1:x\ngithub.com/example/gorilla/websocket-docs v1.0.0 h1:y\n",
            ),
            ("main.go", "package main\n\nfunc main() {}\n"),
        ],
    );
    let found = answer(&report, Condition::Websockets);
    assert!(
        !matches!(found.evidence, Evidence::Dependency { .. }),
        "a near-miss module name matched: {:?}",
        found.evidence
    );
}

#[test]
fn a_kotlin_build_script_is_read_for_its_dependencies() {
    // `build.gradle.kts` is what a Kotlin project gets by default, and it was not read at all.
    let report = scan_files(
        "gradle-kts",
        &[
            (
                "build.gradle.kts",
                "plugins { kotlin(\"jvm\") version \"2.0.0\" }\n\ndependencies {\n    implementation(\"org.springframework:spring-websocket:6.1.0\")\n}\n",
            ),
            (
                "gradle.lockfile",
                "org.springframework:spring-websocket:6.1.0=runtimeClasspath\n",
            ),
            ("src/main/kotlin/App.kt", "fun main() { println(\"hi\") }\n"),
        ],
    );
    let found = answer(&report, Condition::Websockets);
    assert_eq!(found.value, Some(true), "{:?}", found.evidence);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { manifest, .. } if manifest == "build.gradle.kts"),
        "{:?}",
        found.evidence
    );
}

#[test]
fn every_go_signature_names_a_module_path_that_go_mod_could_contain() {
    // `goth`, `stripe-go`, `go-openai` and `autocert` were all in the data files, and none of them
    // is anything `go.mod` ever says: it says `github.com/markbates/goth`, a module path. A bare
    // name can never match, so it is refused here rather than left to look like coverage. The one
    // shape allowed without a `/` is a vanity domain such as `resty.dev`.
    let mut wrong = Vec::new();
    for file in ["tech-signatures.json", "claim-corroborators.json"] {
        let sigs = Signatures::load(&data(file)).unwrap();
        for sig in &sigs.signatures {
            for name in sig.packages.get("Go").into_iter().flatten() {
                if !name.contains('/') && !name.contains('.') {
                    wrong.push(format!("{file} {}: `{name}`", sig.condition));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn go_modules_at_a_later_major_version_answer_their_claims() {
    // The second witness for the version suffix, on three different claims, each in the form the
    // project's own README tells people to `go get`.
    let report = scan_files(
        "go-versions",
        &[
            (
                "go.mod",
                "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/robfig/cron/v3 v3.0.1\n\tgithub.com/stripe/stripe-go/v76 v76.0.0\n\tgithub.com/go-ldap/ldap/v3 v3.4.8\n)\n",
            ),
            (
                "go.sum",
                "github.com/robfig/cron/v3 v3.0.1 h1:a\ngithub.com/stripe/stripe-go/v76 v76.0.0 h1:b\ngithub.com/go-ldap/ldap/v3 v3.4.8 h1:c\n",
            ),
            ("main.go", "package main\n\nfunc main() {}\n"),
        ],
    );
    for condition in [Condition::Scheduler, Condition::Payments, Condition::Ldap] {
        let found = answer(&report, condition);
        assert!(
            matches!(&found.evidence, Evidence::Dependency { .. }),
            "{condition:?}: {:?}",
            found.evidence
        );
    }
}

#[test]
fn a_go_module_whose_owner_merely_ends_the_same_way_is_not_matched() {
    // Second witness for the boundary: `xrobfig/cron` is somebody else's cron.
    let report = scan_files(
        "go-near-miss-2",
        &[
            (
                "go.mod",
                "module example.com/app\n\ngo 1.22\n\nrequire github.com/xrobfig/cron v1.0.0\n",
            ),
            ("go.sum", "github.com/xrobfig/cron v1.0.0 h1:a\n"),
            ("main.go", "package main\n\nfunc main() {}\n"),
        ],
    );
    let found = answer(&report, Condition::Scheduler);
    assert!(
        !matches!(found.evidence, Evidence::Dependency { .. }),
        "{:?}",
        found.evidence
    );
}

#[test]
fn a_claim_is_corroborated_from_a_kotlin_build_script() {
    // Second witness for `build.gradle.kts`, through a claim rather than a technology: Spring
    // Security declared in the Kotlin DSL is sign-in, and it used to be invisible.
    let report = scan_files(
        "gradle-kts-auth",
        &[
            (
                "build.gradle.kts",
                "dependencies {\n    implementation(\"org.springframework.boot:spring-boot-starter-security\")\n}\n",
            ),
            ("src/main/kotlin/App.kt", "fun main() {}\n"),
        ],
    );
    let found = answer(&report, Condition::Auth);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { name, .. } if name == "spring-boot-starter-security"),
        "{:?}",
        found.evidence
    );
}

#[test]
fn a_kotlin_build_script_is_read_for_its_versions() {
    // The third place the missing ecosystem showed: a Kotlin project that did not pin was not
    // reported, because it was not recognized as a project at all. Gradle's lockfile is optional,
    // so it is the versions that decide: one that floats is unpinned, all exact is not.
    let dir = scratch("gradle-kts-unpinned");
    std::fs::write(
        dir.join("build.gradle.kts"),
        "dependencies {\n    implementation(\"org.x:y:1.+\")\n}\n",
    )
    .unwrap();
    let floating = sv_scan::ecosystems::unpinned(&dir);
    std::fs::write(
        dir.join("build.gradle.kts"),
        "dependencies {\n    implementation(\"org.x:y:1.2.3\")\n}\n",
    )
    .unwrap();
    let exact = sv_scan::ecosystems::unpinned(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        floating.iter().any(|e| e.manifest == "build.gradle.kts"),
        "{floating:?}"
    );
    assert!(exact.is_empty(), "{exact:?}");
}

#[test]
fn an_app_with_a_database_beside_it_is_not_multiple_services() {
    // The commonest shape of all: one web app, a compose file that starts it next to Postgres, an
    // HTTP client for an outside API. None of that is services talking to each other, and a
    // contradiction banner telling this owner otherwise would be noise they learn to skip.
    let report = scan_files(
        "single-service",
        &[
            (
                "docker-compose.yml",
                "services:\n  web:\n    build: .\n    ports: [\"8000:8000\"]\n  db:\n    image: postgres:16\n",
            ),
            (
                "requirements.txt",
                "flask==3.0.0\nrequests==2.32.0\npsycopg==3.2.0\n",
            ),
            (
                "requirements.lock",
                "flask==3.0.0\nrequests==2.32.0\npsycopg==3.2.0\n",
            ),
            (
                "app.py",
                "import requests\nfrom flask import Flask\n\napp = Flask(__name__)\n\n@app.get('/rates')\ndef rates():\n    return requests.get('https://example.test/rates', timeout=5).json()\n",
            ),
        ],
    );
    let found = answer(&report, Condition::MultipleServices);
    assert_ne!(found.value, Some(true), "{:?}", found.evidence);
}

#[test]
fn a_declared_broker_client_answers_multiple_services() {
    // The dependency route, which neither witness above takes.
    let report = scan_files(
        "broker-dep",
        &[
            (
                "package.json",
                "{\"name\":\"orders\",\"dependencies\":{\"kafkajs\":\"^2.2.4\"}}",
            ),
            (
                "package-lock.json",
                "{\"name\":\"orders\",\"lockfileVersion\":3,\"packages\":{}}",
            ),
            ("index.js", "console.log('orders');\n"),
        ],
    );
    let found = answer(&report, Condition::MultipleServices);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { name, .. } if name == "kafkajs"),
        "{:?}",
        found.evidence
    );
}

// ---- projects that are not at the top of the repository ----

#[test]
fn a_client_and_server_layout_has_its_dependencies_read() {
    // The usual shape of a full-stack app from an AI builder, with no manifest at the top. Every
    // dependency in it used to go unread.
    let report = scan_files(
        "client-server",
        &[
            (
                "server/package.json",
                "{\"name\":\"server\",\"dependencies\":{\"express\":\"^4.19.0\",\"ws\":\"^8.18.0\"}}",
            ),
            (
                "server/package-lock.json",
                "{\"name\":\"server\",\"lockfileVersion\":3,\"packages\":{}}",
            ),
            ("server/index.js", "const express = require('express');\n"),
            (
                "client/package.json",
                "{\"name\":\"client\",\"dependencies\":{\"react\":\"^19.0.0\"}}",
            ),
            (
                "client/package-lock.json",
                "{\"name\":\"client\",\"lockfileVersion\":3,\"packages\":{}}",
            ),
            (
                "client/src/main.jsx",
                "export const App = () => <p>hi</p>;\n",
            ),
        ],
    );
    let found = answer(&report, Condition::Websockets);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { name, manifest } if name == "ws" && manifest == "server/package.json"),
        "{:?}",
        found.evidence
    );
    let manifests: Vec<&str> = report
        .ecosystems
        .iter()
        .map(|e| e.manifest.as_str())
        .collect();
    assert_eq!(
        manifests,
        vec!["client/package.json", "server/package.json"]
    );
    assert!(report.unpinned.is_empty(), "{:?}", report.unpinned);
}

#[test]
fn a_nested_project_with_no_lockfile_is_unpinned_and_named() {
    let dir = scratch("nested-unpinned");
    std::fs::create_dir_all(dir.join("api")).unwrap();
    std::fs::write(dir.join("api/requirements.txt"), "flask>=3\n").unwrap();
    let unpinned = sv_scan::ecosystems::unpinned(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let manifests: Vec<&str> = unpinned.iter().map(|e| e.manifest.as_str()).collect();
    assert_eq!(manifests, vec!["api/requirements.txt"]);
}

#[test]
fn a_workspace_member_is_pinned_by_the_lockfile_at_the_workspace_root() {
    // npm, pnpm, Yarn, Cargo and uv keep one lockfile at the root for every member.
    let dir = scratch("npm-workspace");
    std::fs::create_dir_all(dir.join("packages/api")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        "{\"name\":\"shop\",\"private\":true,\"workspaces\":[\"packages/*\"]}",
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        "{\"lockfileVersion\":3,\"packages\":{}}",
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/api/package.json"),
        "{\"name\":\"api\",\"dependencies\":{\"express\":\"^4.19.0\"}}",
    )
    .unwrap();
    let detected = sv_scan::ecosystems::detect(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let member = detected
        .iter()
        .find(|e| e.manifest == "packages/api/package.json")
        .expect("the member is found");
    assert_eq!(member.lockfile.as_deref(), Some("package-lock.json"));
}

#[test]
fn a_lockfile_at_the_top_does_not_pin_an_unrelated_project_below_it() {
    // Without a workspace declaration the root lockfile is the root project's alone. Counting it for
    // `server/` would say the server pins what it installs when nothing does.
    let dir = scratch("stray-root-lock");
    std::fs::create_dir_all(dir.join("server")).unwrap();
    std::fs::write(dir.join("package.json"), "{\"name\":\"site\"}").unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        "{\"lockfileVersion\":3,\"packages\":{}}",
    )
    .unwrap();
    std::fs::write(
        dir.join("server/package.json"),
        "{\"name\":\"server\",\"dependencies\":{\"express\":\"^4.19.0\"}}",
    )
    .unwrap();
    let unpinned = sv_scan::ecosystems::unpinned(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let manifests: Vec<&str> = unpinned.iter().map(|e| e.manifest.as_str()).collect();
    assert_eq!(manifests, vec!["server/package.json"]);
}

#[test]
fn a_manifest_inside_installed_dependencies_is_not_a_project() {
    let dir = scratch("nested-node-modules");
    std::fs::create_dir_all(dir.join("node_modules/ws")).unwrap();
    std::fs::create_dir_all(dir.join("web/node_modules/left-pad")).unwrap();
    std::fs::write(dir.join("package.json"), "{\"name\":\"app\"}").unwrap();
    std::fs::write(
        dir.join("node_modules/ws/package.json"),
        "{\"name\":\"ws\"}",
    )
    .unwrap();
    std::fs::write(dir.join("web/package.json"), "{\"name\":\"web\"}").unwrap();
    std::fs::write(
        dir.join("web/node_modules/left-pad/package.json"),
        "{\"name\":\"left-pad\"}",
    )
    .unwrap();
    let detected = sv_scan::ecosystems::detect(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let manifests: Vec<&str> = detected.iter().map(|e| e.manifest.as_str()).collect();
    assert_eq!(manifests, vec!["package.json", "web/package.json"]);
}

#[test]
fn cargo_and_pnpm_workspaces_pin_their_members_and_a_plain_crate_does_not() {
    // The second witness for the workspace rule, in two more ecosystems and in both directions.
    let dir = scratch("cargo-pnpm-workspaces");
    for d in ["crates/core", "tools/gen", "web/apps/site"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n",
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 3\n").unwrap();
    std::fs::write(
        dir.join("crates/core/Cargo.toml"),
        "[package]\nname = \"core\"\n",
    )
    .unwrap();
    // A tool with its own Cargo.toml that the workspace does not list: the root lockfile is not its.
    std::fs::write(
        dir.join("tools/gen/Cargo.toml"),
        "[package]\nname = \"gen\"\n",
    )
    .unwrap();
    // A pnpm workspace inside `web/`, whose lockfile covers `web/apps/site`.
    std::fs::write(
        dir.join("web/pnpm-workspace.yaml"),
        "packages:\n  - apps/*\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("web/package.json"),
        "{\"name\":\"web\",\"private\":true}",
    )
    .unwrap();
    std::fs::write(dir.join("web/pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    std::fs::write(
        dir.join("web/apps/site/package.json"),
        "{\"name\":\"site\"}",
    )
    .unwrap();
    let detected = sv_scan::ecosystems::detect(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let lock_of = |m: &str| {
        detected
            .iter()
            .find(|e| e.manifest == m)
            .unwrap_or_else(|| panic!("{m} not found: {detected:?}"))
            .lockfile
            .clone()
    };
    assert_eq!(
        lock_of("crates/core/Cargo.toml").as_deref(),
        Some("Cargo.lock")
    );
    assert_eq!(
        lock_of("tools/gen/Cargo.toml"),
        None,
        "not a member of the workspace"
    );
    assert_eq!(
        lock_of("web/apps/site/package.json").as_deref(),
        Some("web/pnpm-lock.yaml")
    );
}

#[test]
fn a_crate_under_a_root_that_is_not_a_workspace_pins_nothing() {
    // The other direction for Cargo: a root crate's lockfile is its own.
    let dir = scratch("cargo-not-workspace");
    std::fs::create_dir_all(dir.join("helper")).unwrap();
    std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"app\"\n").unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 3\n").unwrap();
    std::fs::write(
        dir.join("helper/Cargo.toml"),
        "[package]\nname = \"helper\"\n",
    )
    .unwrap();
    let unpinned = sv_scan::ecosystems::unpinned(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let manifests: Vec<&str> = unpinned.iter().map(|e| e.manifest.as_str()).collect();
    assert_eq!(manifests, vec!["helper/Cargo.toml"]);
}

#[test]
fn a_dependency_declared_only_inside_node_modules_is_not_the_apps() {
    // Second witness for the skipped folders, through a claim: an installed package that itself
    // depends on stripe does not mean this app takes payments.
    let report = scan_files(
        "node-modules-claim",
        &[
            (
                "package.json",
                "{\"name\":\"app\",\"dependencies\":{\"billing-kit\":\"1.0.0\"}}",
            ),
            (
                "package-lock.json",
                "{\"lockfileVersion\":3,\"packages\":{}}",
            ),
            (
                "node_modules/billing-kit/package.json",
                "{\"name\":\"billing-kit\",\"dependencies\":{\"stripe\":\"^16.0.0\"}}",
            ),
            ("index.js", "console.log('hi');\n"),
        ],
    );
    let found = answer(&report, Condition::Payments);
    assert!(
        !matches!(found.evidence, Evidence::Dependency { .. }),
        "{:?}",
        found.evidence
    );
}

#[test]
fn a_project_the_npm_workspace_does_not_list_is_not_pinned_by_its_lockfile() {
    // `workspaces: ["packages/*"]` covers `packages/api` and not `scripts/seed`, which npm installs
    // on its own and from nothing.
    let dir = scratch("npm-workspace-nonmember");
    std::fs::create_dir_all(dir.join("packages/api")).unwrap();
    std::fs::create_dir_all(dir.join("scripts/seed")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        "{\"name\":\"shop\",\"workspaces\":{\"packages\":[\"packages/*\"]}}",
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), "{\"lockfileVersion\":3}").unwrap();
    std::fs::write(dir.join("packages/api/package.json"), "{\"name\":\"api\"}").unwrap();
    std::fs::write(dir.join("scripts/seed/package.json"), "{\"name\":\"seed\"}").unwrap();
    let unpinned = sv_scan::ecosystems::unpinned(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let manifests: Vec<&str> = unpinned.iter().map(|e| e.manifest.as_str()).collect();
    assert_eq!(manifests, vec!["scripts/seed/package.json"]);
}

#[test]
fn a_language_only_the_code_rules_read_still_leaves_absences_unknown() {
    // A Dart server whose GraphQL is a pub package. `pubspec.yaml` is not read, so the one place
    // the answer sits is a place the scan never looks, and calling GraphQL absent would be wrong.
    let report = scan_fixture("dart-server");
    assert!(report.languages.contains("dart"), "{:?}", report.languages);
    assert!(
        report.unread_extensions.contains("dart"),
        "{:?}",
        report.unread_extensions
    );
    let graphql = answer(&report, Condition::Graphql);
    assert_eq!(graphql.value, None, "{:?}", graphql.evidence);
    let wrongly_absent: Vec<&str> = report
        .answers
        .iter()
        .filter(|a| a.value == Some(false))
        .map(|a| a.condition.name())
        .collect();
    assert!(wrongly_absent.is_empty(), "{wrongly_absent:?}");
}

#[test]
fn an_oauth_client_is_not_mistaken_for_an_authorization_server() {
    // The corroborator's whole value is the line it draws, so the side it must *not* fire on is
    // worth a test of its own. Each of these is an ordinary "Sign in with Google" app: it uses
    // OAuth, and running the server is somebody else's job.
    //
    // Authlib is the case that shaped the data file. It is both a client and a server library, so
    // it is deliberately absent from the corroborator's package lists — finding it in
    // requirements.txt says nothing about which half is in use — and only its server-side class
    // name in `source` counts.
    let cases: &[(&str, &str)] = &[
        (
            "login.py",
            "from authlib.integrations.flask_client import OAuth\n\noauth = OAuth(app)\noauth.register(name=\"google\", client_id=CLIENT_ID, client_secret=CLIENT_SECRET)\n",
        ),
        (
            "auth.ts",
            "import NextAuth from 'next-auth';\nimport Google from 'next-auth/providers/google';\n\nexport const { handlers } = NextAuth({ providers: [Google] });\n",
        ),
        (
            "store.jsx",
            "export default function App() {\n  return (\n    <Provider store={store}>\n      <Routes />\n    </Provider>\n  );\n}\n",
        ),
    ];
    let sigs = all_signatures();
    for (file, contents) in cases {
        let dir = scratch(&format!("oauth-client-{file}"));
        std::fs::write(dir.join(file), contents).unwrap();
        let report = scan(&dir, &sigs).unwrap();
        let found = answer(&report, Condition::AuthorizationServer);
        let value = found.value;
        let evidence = format!("{:?}", found.evidence);
        std::fs::remove_dir_all(&dir).ok();
        assert_ne!(
            value,
            Some(true),
            "{file} is an OAuth client, but authorization-server fired on it: {evidence}"
        );
    }
}

#[test]
fn a_dual_purpose_library_in_the_dependency_list_does_not_make_an_app_a_server() {
    // The half of the rule above that lives in the package lists rather than the source patterns,
    // and the one that had no witness until this test: `authlib` back among the Python packages
    // passed every other test in the suite while quietly undoing the fix, because a Flask app
    // doing "Sign in with Google" installs Authlib exactly like this.
    let dir = scratch("authlib-client-requirements");
    std::fs::write(
        dir.join("requirements.txt"),
        "flask==3.0.3
authlib==1.3.2
",
    )
    .unwrap();
    std::fs::write(
        dir.join("app.py"),
        "from flask import Flask

app = Flask(__name__)
",
    )
    .unwrap();
    let report = scan(&dir, &all_signatures()).unwrap();
    let server = answer(&report, Condition::AuthorizationServer);
    let oauth = answer(&report, Condition::Oauth);
    let server_evidence = format!("{:?}", server.evidence);
    std::fs::remove_dir_all(&dir).ok();

    // Assert the setup worked before asserting what was not found: a requirements.txt the scanner
    // never read would pass the real assertion below for the wrong reason.
    assert_eq!(
        oauth.value,
        Some(true),
        "the fixture's requirements.txt was not read as OAuth at all, so it proves nothing"
    );
    assert_ne!(
        server.value,
        Some(true),
        "a client's dependency list was read as running an authorization server: {server_evidence}"
    );
}
