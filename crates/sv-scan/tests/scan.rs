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

/// A scratch folder no other test run can reach, removed when the test that made it ends.
///
/// Named after the test alone (`sv-scan-{name}`), two `cargo test` runs at once on one computer
/// shared it, and one run's clean-up deleted the other's files mid-test. The process id and a count
/// make the name this run's and this call's alone. A folder whose test panicked is kept, to be
/// looked at.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }
}

impl std::ops::Deref for Scratch {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl AsRef<std::path::Path> for Scratch {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

fn scratch(name: &str) -> Scratch {
    static MADE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = MADE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sv-scan-{name}-{}-{n}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

#[test]
fn a_scratch_folder_is_this_calls_alone_and_goes_when_the_test_lets_go() {
    // Two `cargo test` runs at once used to share `sv-{prefix}-{name}`, and one run's clean-up
    // deleted the other's files mid-test. Two calls with one name, in one process, get two folders,
    // each named for this process, each there while held and gone after.
    let first = scratch("same-name");
    let second = scratch("same-name");
    assert_ne!(first.to_path_buf(), second.to_path_buf());
    let pid = std::process::id().to_string();
    for dir in [&first, &second] {
        assert!(dir.is_dir(), "{} was made", dir.display());
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.contains(&pid), "{name} names the run it belongs to");
    }
    std::fs::write(first.join("file"), "x").unwrap();
    let (gone, kept) = (first.to_path_buf(), second.to_path_buf());
    drop(first);
    assert!(
        !gone.exists(),
        "{} is removed, with its file",
        gone.display()
    );
    assert!(kept.is_dir(), "the other folder is left alone");
    drop(second);
    assert!(!kept.exists());
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
        "mcp-server",
        "server.py",
        "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"notes\")\n\n@mcp.tool()\ndef search(query: str) -> str:\n    return query\n",
    ),
    (
        // The owner's first build: a weekly job asks Claude to search the vendors' own sites.
        "web-search",
        "refresh.js",
        "const reply = await anthropic.messages.create({\n  model: MODEL,\n  max_tokens: 4096,\n  tools: [{ type: \"web_search_20250305\", name: \"web_search\", allowed_domains: vendorDomains }],\n  messages,\n});\n",
    ),
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
fn a_compose_file_that_builds_two_services_answers_multiple_services() {
    // Two services built from this repository's own code, each in its own folder, beside a stock
    // database image. Plain HTTP between them leaves nothing else to find, which is why the
    // compose file matters.
    let compose = "services:\n  api:\n    build:\n      context: ./api\n    ports: [\"8000:8000\"]\n  web:\n    build: ./web\n    depends_on: [api]\n  db:\n    image: postgres:16\n";
    let report = scan_files(
        "two-builds",
        &[
            ("compose.yaml", compose),
            ("api/app.py", "print('api')\n"),
            ("web/index.js", "console.log('web');\n"),
        ],
    );
    let found = answer(&report, Condition::MultipleServices);
    assert_eq!(found.value, Some(true), "{:?}", found.evidence);
    assert!(
        matches!(&found.evidence, sv_scan::Evidence::Source { file, .. } if file == "compose.yaml"),
        "the report must say which file showed it: {:?}",
        found.evidence
    );

    // A second `build:` that is commented out is not a second service.
    let commented = compose.replace(
        "    build: ./web",
        "    # build: ./web\n    image: web:latest",
    );
    let report = scan_files(
        "one-build-one-comment",
        &[
            ("docker-compose.yml", commented.as_str()),
            ("app.py", "print('api')\n"),
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
fn a_requirements_lock_pins_a_pyproject_project_and_a_tools_own_lockfile_comes_first() {
    // `uv pip compile pyproject.toml -o requirements.lock` writes it, and Rye uses the name.
    let dir = scratch("pyproject-requirements-lock");
    std::fs::write(dir.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
    std::fs::write(dir.join("requirements.lock"), "pyyaml==6.0.2\n").unwrap();
    let alone = sv_scan::ecosystems::detect(&dir);
    std::fs::write(dir.join("uv.lock"), "version = 1\n").unwrap();
    let beside_uv = sv_scan::ecosystems::detect(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let lockfile = |detected: &[sv_scan::ecosystems::DetectedEcosystem]| {
        detected
            .iter()
            .find(|e| e.manifest == "pyproject.toml")
            .expect("the project is found")
            .lockfile
            .clone()
    };
    assert_eq!(lockfile(&alone).as_deref(), Some("requirements.lock"));
    assert_eq!(lockfile(&beside_uv).as_deref(), Some("uv.lock"));
}

#[test]
fn a_second_lockfile_beside_the_one_read_is_named_as_passed_over() {
    let dir = scratch("two-lockfiles");
    std::fs::create_dir_all(dir.join("server")).unwrap();
    std::fs::write(dir.join("package.json"), "{\"name\":\"web\"}").unwrap();
    std::fs::write(dir.join("package-lock.json"), "{\"lockfileVersion\":3}").unwrap();
    std::fs::write(dir.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    std::fs::write(dir.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    // One lockfile only, in a project of its own below: nothing passed over there.
    std::fs::write(dir.join("server/package.json"), "{\"name\":\"api\"}").unwrap();
    std::fs::write(dir.join("server/yarn.lock"), "# yarn lockfile v1\n").unwrap();
    let detected = sv_scan::ecosystems::detect(&dir);
    std::fs::remove_dir_all(&dir).ok();
    let project = |manifest: &str| {
        detected
            .iter()
            .find(|e| e.manifest == manifest)
            .unwrap_or_else(|| panic!("{manifest} is found: {detected:?}"))
    };
    let top = project("package.json");
    assert_eq!(top.lockfile.as_deref(), Some("package-lock.json"));
    assert_eq!(top.passed_over, vec!["yarn.lock", "pnpm-lock.yaml"]);
    let server = project("server/package.json");
    assert_eq!(server.lockfile.as_deref(), Some("server/yarn.lock"));
    assert!(server.passed_over.is_empty(), "{server:?}");
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

// ---- a rate limiter is not an API ----

/// Item 3 of the owner's first build from scratch: `express-rate-limit` and its kind answered
/// `public-api`, so an app with no sign-in and no API at all was handed the API requirements over
/// the manifest's own "no" (corroboration only ever adds).
const RATE_LIMITERS: &[&str] = &[
    "express-rate-limit",
    "@fastify/rate-limit",
    "flask-limiter",
    "slowapi",
    "rack-attack",
];

#[test]
fn a_rate_limiter_is_not_evidence_of_a_public_api() {
    let limited = scan_files(
        "rate-limited",
        &[
            (
                "package.json",
                "{\"name\":\"shop\",\"dependencies\":{\"express\":\"^4.19.0\",\"express-rate-limit\":\"^7.4.0\",\"@fastify/rate-limit\":\"^10.1.0\"}}",
            ),
            (
                "package-lock.json",
                "{\"name\":\"shop\",\"lockfileVersion\":3,\"packages\":{}}",
            ),
            (
                "requirements.txt",
                "flask==3.0.0\nflask-limiter==3.8.0\nslowapi==0.1.9\n",
            ),
            (
                "requirements.lock",
                "flask==3.0.0\nflask-limiter==3.8.0\nslowapi==0.1.9\n",
            ),
            ("index.js", "console.log('shop');\n"),
        ],
    );
    let found = answer(&limited, Condition::PublicApi);
    assert_ne!(found.value, Some(true), "{:?}", found.evidence);

    // The control: the same app with an API description package is found, so the scan above read
    // the dependencies and had the chance to answer.
    let described = scan_files(
        "rate-limited-and-described",
        &[
            (
                "package.json",
                "{\"name\":\"shop\",\"dependencies\":{\"express\":\"^4.19.0\",\"express-rate-limit\":\"^7.4.0\",\"swagger-ui-express\":\"^5.0.1\"}}",
            ),
            (
                "package-lock.json",
                "{\"name\":\"shop\",\"lockfileVersion\":3,\"packages\":{}}",
            ),
            ("index.js", "console.log('shop');\n"),
        ],
    );
    let found = answer(&described, Condition::PublicApi);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { name, .. } if name == "swagger-ui-express"),
        "{:?}",
        found.evidence
    );
}

#[test]
fn no_public_api_package_is_a_rate_limiter() {
    // The data file, read directly: a rate limiter put back under `public-api`, in any ecosystem,
    // fails here whether or not a scan test happens to use that ecosystem.
    let text = std::fs::read_to_string(data("claim-corroborators.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let entry = json["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["condition"] == "public-api")
        .expect("public-api has a corroborator");
    let packages: Vec<&str> = entry["packages"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|list| list.as_array().unwrap().iter().filter_map(|p| p.as_str()))
        .collect();
    assert!(!packages.is_empty());
    for p in &packages {
        let lower = p.to_lowercase();
        assert!(
            !RATE_LIMITERS.contains(&lower.as_str())
                && !lower.contains("rate-limit")
                && !lower.contains("ratelimit")
                && !lower.contains("limiter")
                && !lower.contains("throttl"),
            "{p} limits requests; it says nothing about who is calling"
        );
    }
}

#[test]
fn a_ruby_rate_limiter_is_not_evidence_either() {
    let gemfile = |extra: &str| {
        format!("source 'https://rubygems.org'\ngem 'rails', '~> 7.2'\ngem 'rack-attack'\n{extra}")
    };
    let limited = scan_files(
        "ruby-rate-limited",
        &[
            ("Gemfile", &gemfile("")),
            (
                "Gemfile.lock",
                "GEM\n  specs:\n    rails (7.2.1)\n    rack-attack (6.7.0)\n",
            ),
            ("app.rb", "puts 'shop'\n"),
        ],
    );
    let found = answer(&limited, Condition::PublicApi);
    assert_ne!(found.value, Some(true), "{:?}", found.evidence);

    // The control: Ruby's dependencies are read, and an API description gem is found.
    let described = scan_files(
        "ruby-rate-limited-and-described",
        &[
            ("Gemfile", &gemfile("gem 'rswag'\n")),
            (
                "Gemfile.lock",
                "GEM\n  specs:\n    rails (7.2.1)\n    rack-attack (6.7.0)\n    rswag (2.14.0)\n",
            ),
            ("app.rb", "puts 'shop'\n"),
        ],
    );
    let found = answer(&described, Condition::PublicApi);
    assert!(
        matches!(&found.evidence, Evidence::Dependency { name, .. } if name == "rswag"),
        "{:?}",
        found.evidence
    );
}

#[test]
fn folders_that_are_not_the_app_are_not_evidence_about_it() {
    // An example app beside the real one: it declares a sign-in library, it is written in Go, and it
    // does not pin what it installs. None of that is the app's.
    let app = std::env::temp_dir().join(format!("sv-scan-not-the-app-{}", std::process::id()));
    std::fs::remove_dir_all(&app).ok();
    std::fs::create_dir_all(app.join("examples/shop")).unwrap();
    std::fs::create_dir_all(app.join("crates/one/tests")).unwrap();
    std::fs::write(app.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(app.join("requirements.txt"), "flask==3.0.0\n").unwrap();
    std::fs::write(app.join("examples/shop/requirements.txt"), "flask-login\n").unwrap();
    std::fs::write(app.join("examples/shop/main.go"), "package main\n").unwrap();
    // A file whose name alone is evidence: an example's Terraform is not the app's infrastructure.
    std::fs::write(app.join("examples/shop/main.tf"), "provider \"aws\" {}\n").unwrap();
    std::fs::write(app.join("crates/one/tests/page.dart"), "void main() {}\n").unwrap();
    // A file whose name only starts like the folder is the app's own.
    std::fs::write(app.join("examples.py"), "print('mine')\n").unwrap();
    let sigs = all_signatures();

    // The control: read as one app, the example is evidence, which is what went wrong on `sv`.
    let whole = scan(&app, &sigs).unwrap();
    assert_eq!(answer(&whole, Condition::Auth).value, Some(true));
    assert!(whole.languages.contains("go"));
    assert_eq!(answer(&whole, Condition::Iac).value, Some(true));
    assert!(whole.declared.iter().any(|d| d.name == "flask-login"));
    assert!(
        whole
            .unpinned
            .iter()
            .any(|e| e.manifest.starts_with("examples/"))
    );

    let folders = vec!["examples".to_owned(), "crates/*/tests".to_owned()];
    let apart =
        sv_scan::scan_listing_app(&sv_scan::files::Listing::of(&app), &sigs, &folders).unwrap();
    assert_ne!(answer(&apart, Condition::Auth).value, Some(true));
    assert!(!apart.languages.contains("go"));
    assert_ne!(answer(&apart, Condition::Iac).value, Some(true));
    assert!(!apart.all_paths.iter().any(|p| p.starts_with("examples/")));
    assert!(!apart.declared.iter().any(|d| d.name == "flask-login"));
    assert!(
        apart.declared.iter().any(|d| d.name == "flask"),
        "the app's own still counts"
    );
    assert!(
        !apart
            .unpinned
            .iter()
            .any(|e| e.manifest.starts_with("examples/")),
        "{:?}",
        apart.unpinned
    );
    assert!(
        !apart
            .ecosystems
            .iter()
            .any(|e| e.manifest.starts_with("examples/"))
    );
    assert!(
        apart.unread_extensions.is_empty(),
        "{:?}",
        apart.unread_extensions
    );
    assert!(apart.all_paths.contains("examples.py"));
    let set_apart: Vec<&str> = apart.set_apart.iter().map(|p| p.as_str()).collect();
    assert_eq!(set_apart, vec!["crates/one/tests", "examples"]);
    assert_eq!(apart.not_the_app, folders, "the list is used");
    assert!(apart.not_the_app_refused.is_none());
    let (set, total) = apart.code_set_apart;
    assert!(set >= 2 && set < total, "{:?}", apart.code_set_apart);
    std::fs::remove_dir_all(&app).ok();
}

#[test]
fn a_list_that_would_set_apart_all_the_app_s_code_is_not_used() {
    // All of the app's code under two folders, and a sign-in library declared beside it. `src` alone
    // leaves `lib`; `src` and `lib` together leave nothing.
    let app = std::env::temp_dir().join(format!("sv-scan-all-apart-{}", std::process::id()));
    std::fs::remove_dir_all(&app).ok();
    std::fs::create_dir_all(app.join("src/web")).unwrap();
    std::fs::create_dir_all(app.join("lib")).unwrap();
    std::fs::write(app.join("src/web/app.py"), "import flask_login\n").unwrap();
    std::fs::write(app.join("lib/util.py"), "print('util')\n").unwrap();
    std::fs::write(app.join("src/requirements.txt"), "flask-login\n").unwrap();
    // Not code: a README and an image outside the list do not keep it from covering the code.
    std::fs::write(app.join("README.md"), "# App\n").unwrap();
    let listing = sv_scan::files::Listing::of(&app);
    let sigs = all_signatures();

    let one = vec!["src".to_owned()];
    let some = sv_scan::scan_listing_app(&listing, &sigs, &one).unwrap();
    assert_eq!(
        some.not_the_app, one,
        "a list that leaves code outside is used"
    );
    assert!(some.not_the_app_refused.is_none());
    assert_eq!(some.code_set_apart, (1, 2));
    assert_ne!(answer(&some, Condition::Auth).value, Some(true));

    // `*` matches every folder one level down; the manifest refuses it alone, not inside a path.
    for folders in [
        vec!["src".to_owned(), "lib".to_owned()],
        vec!["*".to_owned(), "docs".to_owned()],
    ] {
        let all = sv_scan::scan_listing_app(&listing, &sigs, &folders).unwrap();
        assert!(
            all.not_the_app.is_empty(),
            "{folders:?}: {:?}",
            all.not_the_app
        );
        let why = all.not_the_app_refused.as_deref().expect("said why");
        assert!(why.contains("all 2 of the app's code files"), "{why}");
        assert_eq!(all.code_set_apart, (0, 2));
        assert!(all.set_apart.is_empty(), "{:?}", all.set_apart);
        // Read as the app: its sign-in library is evidence again.
        assert_eq!(
            answer(&all, Condition::Auth).value,
            Some(true),
            "{folders:?}"
        );
        assert!(all.languages.contains("python"));
    }

    // An app with no code at all has nothing to hide, and the list is used.
    let bare = std::env::temp_dir().join(format!("sv-scan-no-code-{}", std::process::id()));
    std::fs::remove_dir_all(&bare).ok();
    std::fs::create_dir_all(bare.join("site")).unwrap();
    std::fs::write(bare.join("site/notes.txt"), "hello\n").unwrap();
    let site = vec!["site".to_owned()];
    let (kept, refused, counts) =
        sv_scan::not_the_app_in(&sv_scan::files::Listing::of(&bare), &site);
    assert_eq!((kept, refused, counts), (site, None, (0, 0)));
    std::fs::remove_dir_all(&app).ok();
    std::fs::remove_dir_all(&bare).ok();
}

#[test]
fn a_folder_is_matched_by_whole_names() {
    let folders = vec!["examples".to_owned(), "crates/*/tests".to_owned()];
    for (path, inside) in [
        ("examples", true),
        ("examples/shop/app.py", true),
        ("crates/sv-cli/tests/fixture.rs", true),
        ("crates/sv-cli/tests", true),
        ("examples.md", false),
        ("my-examples/app.py", false),
        ("src/examples/app.py", false),
        ("crates/sv-cli/src/main.rs", false),
        ("crates/tests", false),
    ] {
        assert_eq!(sv_scan::under_any(path, &folders), inside, "{path}");
    }
}

// ---- serving tools over MCP, not using them ----

#[test]
fn an_mcp_server_in_typescript_answers_mcp_server() {
    let report = scan_files(
        "mcp-server-ts",
        &[(
            "src/index.ts",
            "import { McpServer } from \"@modelcontextprotocol/sdk/server/mcp.js\";\n\nconst server = new McpServer({ name: \"notes\", version: \"1.0.0\" });\n",
        )],
    );
    let found = answer(&report, Condition::McpServer);
    assert_eq!(found.value, Some(true), "{:?}", found.evidence);
}

#[test]
fn an_app_whose_ai_calls_mcp_tools_is_not_an_mcp_server() {
    // The client's side: it launches a server and calls its tools. That answers `mcp`, and must
    // not answer `mcp-server`, or a client would be asked about a server it does not run.
    let report = scan_files(
        "mcp-client-py",
        &[(
            "agent.py",
            "from mcp import ClientSession, StdioServerParameters\nfrom mcp.client.stdio import stdio_client\n\nasync def run():\n    async with stdio_client(StdioServerParameters(command=\"notes\")) as (r, w):\n        async with ClientSession(r, w) as session:\n            await session.call_tool(\"search\", {\"query\": \"x\"})\n",
        )],
    );
    assert_eq!(
        answer(&report, Condition::Mcp).value,
        Some(true),
        "the control: it is an MCP client"
    );
    let server = answer(&report, Condition::McpServer);
    assert_ne!(server.value, Some(true), "{:?}", server.evidence);
}

#[test]
fn a_fastmcp_server_in_python_answers_mcp_server() {
    let report = scan_files(
        "mcp-server-py",
        &[(
            "tools.py",
            "from fastmcp import FastMCP\n\napp = FastMCP(name=\"calendar\")\n\n@app.tool\ndef next_meeting() -> str:\n    return \"none\"\n",
        )],
    );
    let found = answer(&report, Condition::McpServer);
    assert_eq!(found.value, Some(true), "{:?}", found.evidence);
}

#[test]
fn an_agent_that_connects_to_a_remote_mcp_server_is_not_one() {
    let report = scan_files(
        "mcp-client-sse",
        &[(
            "assistant.py",
            "from mcp import ClientSession\nfrom mcp.client.sse import sse_client\n\nasync def tools():\n    async with sse_client(\"https://tools.example.test/sse\") as (r, w):\n        async with ClientSession(r, w) as s:\n            return await s.list_tools()\n",
        )],
    );
    assert_eq!(
        answer(&report, Condition::Mcp).value,
        Some(true),
        "the control"
    );
    let server = answer(&report, Condition::McpServer);
    assert_ne!(server.value, Some(true), "{:?}", server.evidence);
}

#[test]
fn a_fine_tuning_call_to_a_vendor_is_training_even_with_no_framework() {
    // The `training` corroborator knew the frameworks (torch, transformers) and missed an app that
    // fine-tunes with one call to a vendor and installs nothing of the kind. Each case is that
    // vendor's call as its own SDK or API definition spells it, in an app with no ML dependency.
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "openai-py",
            "tune.py",
            "from openai import OpenAI\nclient = OpenAI()\njob = client.fine_tuning.jobs.create(training_file=f.id, model=\"gpt-4o-mini\")\n",
            "fine_tuning.jobs.create",
        ),
        (
            "openai-node",
            "tune.js",
            "import OpenAI from \"openai\";\nconst client = new OpenAI();\nconst job = await client.fineTuning.jobs.create({ training_file: id, model: \"gpt-4o-mini\" });\n",
            "fineTuning.jobs.create",
        ),
        (
            "openai-http",
            "tune.ts",
            "await fetch(\"https://api.openai.com/v1/fine_tuning/jobs\", { method: \"POST\", body });\n",
            "/fine_tuning/jobs",
        ),
        (
            "vertex",
            "tune.py",
            "from vertexai.tuning import sft\njob = sft.train(source_model=\"gemini-2.0-flash-001\", train_dataset=uri)\n",
            "sft.train(",
        ),
        (
            "genai",
            "tune.py",
            "from google import genai\nclient = genai.Client()\njob = client.tunings.tune(base_model=m, training_dataset=d)\n",
            "tunings.tune(",
        ),
        (
            "bedrock-py",
            "tune.py",
            "import boto3\nbedrock = boto3.client(\"bedrock\")\nbedrock.create_model_customization_job(jobName=n, baseModelIdentifier=m)\n",
            "create_model_customization_job",
        ),
        (
            "bedrock-js",
            "tune.ts",
            "import { BedrockClient, CreateModelCustomizationJobCommand } from \"@aws-sdk/client-bedrock\";\nawait client.send(new CreateModelCustomizationJobCommand(input));\n",
            "CreateModelCustomizationJob",
        ),
    ];
    for (name, file, text, pattern) in cases {
        let dir = scratch(&format!("fine-tune-{name}"));
        std::fs::write(dir.join(file), text).unwrap();
        let report = scan(&dir, &all_signatures()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        // Setup, asserted: the file was read, so an answer is about its contents.
        assert_eq!(report.files_read, 1, "{name}: the file was not read");
        let training = answer(&report, Condition::Training);
        assert_eq!(
            training.value,
            Some(true),
            "{name}: {:?}",
            training.evidence
        );
        assert!(
            matches!(&training.evidence, Evidence::Source { pattern: p, .. } if p.as_str() == *pattern),
            "{name}: expected {pattern:?} as the evidence, got {:?}",
            training.evidence
        );
    }
}

#[test]
fn calling_a_hosted_model_is_not_training() {
    // The control for the test above: the same vendors' clients, used to ask a model something,
    // are not fine-tuning, and the corroborator must not say they are. Nothing found proves
    // nothing for this claim, so the answer is "could not tell", never "no training".
    let dir = scratch("hosted-model-only");
    std::fs::write(
        dir.join("ask.py"),
        "from openai import OpenAI\nclient = OpenAI()\nreply = client.chat.completions.create(model=\"gpt-4o-mini\", messages=m)\nfiles = client.files.list()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("ask.ts"),
        "import OpenAI from \"openai\";\nconst client = new OpenAI();\nconst reply = await client.responses.create({ model: \"gpt-4o-mini\", input });\n",
    )
    .unwrap();
    let report = scan(&dir, &all_signatures()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(report.files_read, 2, "both files were read");
    let training = answer(&report, Condition::Training);
    assert_eq!(training.value, None, "{:?}", training.evidence);
}

/// A requirements file as `pip-compile --generate-hashes` or `pip freeze` with hashes writes it.
fn hashed(lines: &[&str]) -> String {
    let hash = "ab".repeat(32);
    lines
        .iter()
        .map(|l| {
            if l.contains("==") && !l.starts_with('#') {
                format!("{l} \\\n    --hash=sha256:{hash}\n")
            } else {
                format!("{l}\n")
            }
        })
        .collect()
}

fn python_lockfile(dir: &std::path::Path) -> Option<String> {
    sv_scan::ecosystems::detect(dir)
        .into_iter()
        .find(|e| e.name == "Python")
        .expect("the project is found")
        .lockfile
}

#[test]
fn a_requirements_file_that_pins_and_hashes_everything_is_its_own_lockfile() {
    // family-hub's shape, reported on 3 October 2026: every package `==` with `--hash`.
    let dir = scratch("requirements-hashed");
    std::fs::write(
        dir.join("requirements.txt"),
        hashed(&[
            "# This file is autogenerated by pip-compile",
            "--index-url https://pypi.org/simple",
            "blinker==1.9.0",
            "flask[async]==3.1.3 ; python_version >= \"3.9\"",
            "",
        ]),
    )
    .unwrap();
    let locked = python_lockfile(&dir);
    let unpinned = sv_scan::ecosystems::unpinned(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(locked.as_deref(), Some("requirements.txt"));
    assert!(unpinned.is_empty(), "{unpinned:?}");
}

#[test]
fn one_package_without_a_hash_or_a_pin_means_the_requirements_file_is_not_a_lock() {
    for (name, extra) in [
        ("no-hash", "itsdangerous==2.2.0\n".to_owned()),
        ("a-range", hashed(&["jinja2>=3.1"])),
        ("a-wildcard", hashed(&["jinja2==3.*"])),
        ("an-include", "-r base.txt\n".to_owned()),
        ("editable", "-e ./local-package\n".to_owned()),
    ] {
        let dir = scratch(&format!("requirements-not-locked-{name}"));
        let mut text = hashed(&["blinker==1.9.0", "flask==3.1.3"]);
        text.push_str(&extra);
        std::fs::write(dir.join("requirements.txt"), text).unwrap();
        let locked = python_lockfile(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(locked, None, "{name}");
    }
    // Nothing in it at all is not a lock either.
    assert!(!sv_scan::ecosystems::fully_hash_pinned("# nothing\n\n"));
}

#[test]
fn a_pylock_file_pins_both_kinds_of_python_project() {
    let dir = scratch("pylock");
    std::fs::write(dir.join("requirements.txt"), "flask>=3\n").unwrap();
    std::fs::write(dir.join("pylock.toml"), "lock-version = \"1.0\"\n").unwrap();
    let beside_requirements = python_lockfile(&dir);
    std::fs::remove_file(dir.join("requirements.txt")).unwrap();
    std::fs::write(dir.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
    let beside_pyproject = python_lockfile(&dir);
    // A named one, for one environment, on its own and beside the plain one.
    std::fs::remove_file(dir.join("pylock.toml")).unwrap();
    std::fs::write(dir.join("pylock.prod.toml"), "lock-version = \"1.0\"\n").unwrap();
    let named = python_lockfile(&dir);
    std::fs::write(dir.join("pylock.toml"), "lock-version = \"1.0\"\n").unwrap();
    let both = sv_scan::ecosystems::detect(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(beside_requirements.as_deref(), Some("pylock.toml"));
    assert_eq!(beside_pyproject.as_deref(), Some("pylock.toml"));
    assert_eq!(named.as_deref(), Some("pylock.prod.toml"));
    let both = both.iter().find(|e| e.name == "Python").unwrap();
    assert_eq!(both.lockfile.as_deref(), Some("pylock.toml"));
    assert_eq!(both.passed_over, vec!["pylock.prod.toml".to_owned()]);
}

#[test]
fn a_pipenv_project_is_found_with_its_lockfile() {
    // Deep review H9: an app with only `Pipfile` and `Pipfile.lock` had no Python at all.
    let dir = scratch("pipenv-detected");
    std::fs::create_dir_all(dir.join("api")).unwrap();
    std::fs::write(
        dir.join("api/Pipfile"),
        "[packages]\ndjango = \"==2.2.0\"\n",
    )
    .unwrap();
    let alone = sv_scan::ecosystems::detect(&dir);
    std::fs::write(dir.join("api/Pipfile.lock"), "{}").unwrap();
    let locked = sv_scan::ecosystems::detect(&dir);
    let unpinned = sv_scan::ecosystems::unpinned(&dir);
    let names = sv_scan::deps::read(&dir);
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(alone.len(), 1, "{alone:?}");
    assert_eq!(alone[0].name, "Python");
    assert_eq!(alone[0].manifest, "api/Pipfile");
    assert_eq!(alone[0].lockfile, None);
    assert_eq!(locked[0].lockfile.as_deref(), Some("api/Pipfile.lock"));
    assert!(unpinned.is_empty(), "the lockfile pins it: {unpinned:?}");
    assert!(
        names
            .iter()
            .any(|d| d.name == "django" && d.manifest == "api/Pipfile"),
        "the Pipfile's packages are read for the technology scan: {names:?}"
    );
}

#[test]
fn python_dependency_declarations_sv_does_not_read_are_found() {
    use sv_scan::ecosystems::DeclarationKind;
    let dir = scratch("python-declarations");
    let write = |path: &str, text: &str| {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write("requirements.txt", "flask==3.0.0\n");
    write("requirements-dev.txt", "pytest==8.0.0\n");
    write("dev_requirements.txt", "black==24.1.0\n");
    write("requirements/prod.txt", "gunicorn==22.0.0\n");
    write("requirements.in", "flask\n");
    write(
        "setup.py",
        "from setuptools import setup\nsetup(install_requires=['flask'])\n",
    );
    write("setup.cfg", "[flake8]\nmax-line-length = 100\n");
    write(
        "worker/setup.cfg",
        "[options]\ninstall_requires =\n    celery\n",
    );
    write("worker/Pipfile", "[packages]\ncelery = \"*\"\n");
    write("worker/Pipfile.lock", "{}");
    write(
        "notebooks/environment.yml",
        "name: lab\ndependencies:\n  - numpy\n",
    );
    write("notes.txt", "not a list of packages\n");
    let listing = sv_scan::files::Listing::of(&dir);
    let found = sv_scan::ecosystems::python_declarations_in(&listing);
    std::fs::remove_dir_all(&dir).ok();

    let got: Vec<(&str, DeclarationKind, bool)> = found
        .iter()
        .map(|d| (d.path.as_str(), d.kind, d.beside_lockfile))
        .collect();
    assert_eq!(
        got,
        vec![
            ("dev_requirements.txt", DeclarationKind::Requirements, false),
            ("notebooks/environment.yml", DeclarationKind::Conda, false),
            ("requirements-dev.txt", DeclarationKind::Requirements, false),
            (
                "requirements/prod.txt",
                DeclarationKind::Requirements,
                false
            ),
            ("setup.py", DeclarationKind::Setup, false),
            ("worker/setup.cfg", DeclarationKind::Setup, true),
        ],
        "a setup.cfg that only configures a tool, requirements.in, requirements.txt itself, and \
         a text file that is not a list are not declarations"
    );
}
