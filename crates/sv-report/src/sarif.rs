//! Findings as SARIF 2.1.0, for editors and CI tools that read it.
//!
//! SARIF has no way to say "this was not examined", and nothing here pretends otherwise: the file
//! carries the findings and only the findings. The gaps live in the reports a person reads, and the
//! `invocation` below records that this run was partial whenever `sv` knows it was, because a tool
//! that reports zero results from a scan that never ran looks exactly like a clean one.

use crate::Report;
use serde_json::{Value, json};

pub fn render(report: &Report) -> String {
    // Every finding the file carries: those still counted, and the false alarms a person set aside,
    // which go in marked as suppressed with the person's reason, so a tool reading the file (GitHub's
    // Security tab among them) shows what the report shows.
    let false_alarms: Vec<&sv_check::review::SetAside> = report
        .set_aside
        .iter()
        .filter(|s| s.verdict == sv_check::review::FALSE_ALARM)
        .collect();
    // Each problem a result of its own, as the tools that read SARIF expect: one gathered into
    // another on its line (`one_per_line`) is listed again beside it, under its own rule.
    let every: Vec<&sv_check::Finding> = report
        .findings
        .iter()
        .flat_map(|f| std::iter::once(f).chain(f.also_on_this_line.iter()))
        .chain(false_alarms.iter().map(|s| &s.finding))
        .collect();
    let rules: Vec<Value> = {
        let mut seen: Vec<&str> = every.iter().map(|f| f.rule_id.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        seen.into_iter()
            .map(|id| {
                let of_rule: Vec<&sv_check::Finding> =
                    every.iter().copied().filter(|f| f.rule_id == id).collect();
                rule_entry(id, &of_rule)
            })
            .collect()
    };

    let results: Vec<Value> = every
        .iter()
        .map(|f| {
            let set_aside = false_alarms
                .iter()
                .find(|s| std::ptr::eq(&s.finding, *f));
            let accepted = report.set_aside.iter().find(|s| {
                s.verdict == sv_check::review::ACCEPTED_RISK
                    && s.finding.fingerprint == f.fingerprint
                    && s.finding.rule_id == f.rule_id
            });
            let mut result = json!({
                "ruleId": f.rule_id,
                "level": match f.severity {
                    sv_check::Severity::Critical | sv_check::Severity::High => "error",
                    sv_check::Severity::Medium => "warning",
                    _ => "note",
                },
                "message": { "text": format!("{} {}", f.title, f.description) },
                "properties": {
                    "certainty": f.certainty(),
                    "inTestCode": f.in_test_code(),
                    "alsoReportedBy": f.also_reported_by,
                },
                "locations": [location(&f.location)],
            });
            if !f.location.is_file() {
                result["properties"]["place"] = json!(f.location.file);
            }
            if let Some(library) = &f.bundled_library {
                result["properties"]["inBundledLibrary"] = json!(library);
            }
            if f.worth_a_look() {
                result["properties"]["worthALook"] = json!(true);
            }
            match &f.outranked {
                Some(sv_check::finding::Outranked::CheckedWhileRunning { check }) => {
                    result["properties"]["worthALook"] = json!(true);
                    result["properties"]["outrankedBy"] = json!(check);
                }
                Some(sv_check::finding::Outranked::NotHeldTo) => {
                    result["properties"]["notHeldTo"] = json!(true);
                }
                None => {}
            }
            if !f.fingerprint.is_empty() {
                result["partialFingerprints"] = json!({ "svFingerprint/v1": f.fingerprint });
            }
            if let Some(s) = set_aside {
                result["suppressions"] = json!([{
                    "kind": "external",
                    "status": "accepted",
                    "justification": format!("False alarm, set aside by {} on {}: {}", s.by, s.on, s.why),
                }]);
            }
            if let Some(s) = accepted {
                result["properties"]["acceptedRisk"] = json!({ "by": s.by, "on": s.on, "why": s.why });
            }
            result
        })
        .collect();

    // Said plainly rather than left to be inferred from an empty `results` array.
    let notifications: Vec<Value> = report
        .gaps
        .iter()
        .map(|gap| {
            json!({
                "level": "warning",
                "message": { "text": format!("Not examined: {} — {}", gap.what, gap.why) },
                "descriptor": { "id": "sv.not-examined" }
            })
        })
        .collect();

    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "sv",
                "version": report.sv.version,
                "informationUri": "https://github.com/abbyshade111/SecureVibe",
                "properties": { "commit": report.sv.commit },
                "rules": rules,
            }},
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
            }],
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&document).expect("a JSON value serializes")
}

/// The file a finding about the running app is pointed at: the manifest, whose `[run]` section says
/// how `sv` started the app. `sv report --run` cannot run without it, so it is always there.
const RUNNING_APP_ANCHOR: &str = "securevibe.toml";

/// Where a finding is, as a SARIF `location`.
///
/// A file of the app is an `artifactLocation.uri` relative to the app's folder, percent-encoded so
/// a space, a `#`, or a letter outside ASCII is a valid URI rather than one a reader guesses at.
///
/// The running app has no file. SARIF itself allows a result with no location, but GitHub code
/// scanning does not show one ("At least one location is required", and `physicalLocation` is
/// marked required), and refuses an upload holding one. So such a finding is pointed at the
/// manifest that says how the app was run, line 1, and says so in the location's own message,
/// with the place named as a `logicalLocation` and in the result's `properties.place`. The address
/// the probe asked is in the result's message, as it always was.
fn location(at: &sv_check::Location) -> Value {
    if at.is_file() {
        return json!({
            "physicalLocation": {
                "artifactLocation": { "uri": relative_uri(&at.file) },
                "region": { "startLine": at.line.max(1) }
            }
        });
    }
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": RUNNING_APP_ANCHOR },
            "region": { "startLine": 1 }
        },
        "logicalLocations": [{ "name": at.file }],
        "message": { "text": format!(
            "Seen in {}, which has no file or line of its own. It points at {RUNNING_APP_ANCHOR}, \
             which says how the app was started.",
            at.file
        ) }
    })
}

/// A path as a relative reference (RFC 3986, section 4.2): every byte but the unreserved ones and
/// `/` percent-encoded, so a `:` cannot read as a scheme and a `#` or `?` cannot end the path. A
/// path that starts `//` would name a host, so it gains a `./`, which names the same file.
fn relative_uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    if path.starts_with("//") {
        out.push_str("./");
    }
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A rule's own words, from the data file it was loaded from.
struct RuleText {
    title: String,
    description: String,
    impact: String,
    fix: String,
}

/// The rules `sv` keeps as data (`data/ast-rules.json` and `data/secret-rules.json`), read from the
/// same folder the checks read them from, once. A file that cannot be read leaves its rules to be
/// described from their findings, below.
fn catalog() -> &'static std::collections::BTreeMap<String, RuleText> {
    static CATALOG: std::sync::OnceLock<std::collections::BTreeMap<String, RuleText>> =
        std::sync::OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut out = std::collections::BTreeMap::new();
        for name in ["ast-rules.json", "secret-rules.json"] {
            let Ok(text) = std::fs::read_to_string(sv_frameworks::data::file(name)) else {
                continue;
            };
            let Ok(file) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            for rule in file["rules"].as_array().into_iter().flatten() {
                let text = |key: &str| rule[key].as_str().unwrap_or("").to_owned();
                if let Some(id) = rule["id"].as_str() {
                    out.insert(
                        id.to_owned(),
                        RuleText {
                            title: text("title"),
                            description: text("description"),
                            impact: text("impact"),
                            fix: text("fix"),
                        },
                    );
                }
            }
        }
        out
    })
}

/// One rule's entry in `tool.driver.rules`, the same whichever of its findings came first.
///
/// A rule kept as data is described in its own words. Any other rule (the running-app probes, a
/// tool's, a settings check) is described by what all its findings say alike: a tool's findings
/// all carry the tool's rule text, and a probe's carry its rule's harm and fix. A field the
/// findings disagree on (a probe's title names the page it asked) is not taken from any one of
/// them; it says that each result says it. The weaknesses and requirements are every one the
/// rule's findings name.
fn rule_entry(id: &str, findings: &[&sv_check::Finding]) -> Value {
    fn alike<'a>(
        findings: &[&'a sv_check::Finding],
        field: fn(&sv_check::Finding) -> &str,
    ) -> Option<&'a str> {
        let first = field(findings.first()?);
        (!first.is_empty() && findings.iter().all(|f| field(f) == first)).then_some(first)
    }
    let (short, full, help) = match catalog().get(id) {
        Some(own) => (
            own.title.clone(),
            [own.description.as_str(), own.impact.as_str()]
                .iter()
                .filter(|t| !t.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(" "),
            own.fix.clone(),
        ),
        None => (
            alike(findings, |f| &f.title)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("Rule {id}: each result says what it found.")),
            alike(findings, |f| &f.impact)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    "What this rule found differs from one result to the next; each result's \
                 message says what was found and why it matters."
                        .to_owned()
                }),
            alike(findings, |f| &f.fix)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    "Each result's message says what was found; the report `sv` wrote beside this \
                 file says how to fix each one."
                        .to_owned()
                }),
        ),
    };
    let union = |field: fn(&sv_check::Finding) -> &Vec<String>| {
        let mut all: Vec<&str> = findings
            .iter()
            .flat_map(|f| field(f).iter().map(String::as_str))
            .collect();
        all.sort_unstable();
        all.dedup();
        all
    };
    json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": short },
        "fullDescription": { "text": full },
        "help": { "text": help },
        "properties": {
            "tags": union(|f| &f.cwe),
            "requirements": union(|f| &f.requirement_ids),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Counts, Report};

    fn empty_report(gaps: Vec<crate::Gap>) -> Report {
        Report {
            app_name: "test".into(),
            target_level: 1,
            generated: None,
            sv: Default::default(),
            run_record: None,
            run_note: None,
            run_steps: Vec::new(),
            test_output: None,
            run_status: None,
            ai_process: Default::default(),
            counts: Counts::default(),
            requirements: vec![],
            excluded: vec![],
            undecided: vec![],
            claims: vec![],
            findings: vec![],
            set_aside: Vec::new(),
            reviews_not_counted: Vec::new(),
            out_of_scope: vec![],
            checklist_above_level: vec![],
            tests_to_write: vec![],
            only_you_can_check: Vec::new(),
            before_going_live: Vec::new(),
            questions_for_you: Vec::new(),
            no_instructions_yet: 0,
            named_not_credited: vec![],
            not_for_tests: 0,
            threats: Vec::new(),
            threat_parts: Vec::new(),
            threat_atlas_release: None,
            satisfied_elsewhere: vec![],
            gaps,
            examined: Vec::new(),
            could_not_run: Vec::new(),
            partly_read: Vec::new(),
        }
    }

    #[test]
    fn a_scan_that_examined_nothing_does_not_look_like_a_clean_one() {
        // Zero results and zero notifications is a tool saying "I looked everywhere and it is
        // fine". Zero results with the gaps attached is a tool saying what it did.
        let report = empty_report(vec![crate::Gap {
            what: "the running app".into(),
            why: "no container backend is available".into(),
        }]);
        let value: serde_json::Value = serde_json::from_str(&render(&report)).unwrap();
        let notifications = &value["runs"][0]["invocations"][0]["toolExecutionNotifications"];
        assert_eq!(notifications.as_array().map(Vec::len), Some(1));
        assert!(
            notifications[0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("no container backend"),
            "{notifications}"
        );
    }

    fn finding(rule: &str, file: &str, line: usize, title: &str) -> sv_check::Finding {
        sv_check::Finding {
            rule_id: rule.into(),
            title: title.into(),
            severity: sv_check::Severity::High,
            confidence: sv_check::Confidence::High,
            location: sv_check::Location {
                file: file.into(),
                line,
            },
            secret: None,
            requirement_ids: vec!["V1.2.4".into()],
            cwe: vec!["CWE-89".into()],
            description: format!("{title}, described."),
            impact: format!("What {title} could lead to."),
            fix: format!("How to fix {title}."),
            also_reported_by: Vec::new(),
            fingerprint: "0123456789abcdef".into(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            outranked: None,
            also_on_this_line: Vec::new(),
        }
    }

    fn sarif_of(findings: Vec<sv_check::Finding>) -> serde_json::Value {
        let mut report = empty_report(vec![]);
        report.findings = findings;
        serde_json::from_str(&render(&report)).expect("the SARIF is JSON")
    }

    /// Whether `uri` is a relative reference by RFC 3986's grammar (section 4.2) that is only a
    /// path: no scheme, no authority, no query, no fragment, and every byte either one a path may
    /// hold as it is or a percent sign followed by two hexadecimal digits.
    fn is_relative_path_reference(uri: &str) -> Result<(), String> {
        if uri.starts_with("//") {
            return Err("starts with //, which names a host".into());
        }
        let first_segment = uri.split('/').next().unwrap_or("");
        if first_segment.contains(':') {
            return Err("its first segment has a colon, which reads as a scheme".into());
        }
        let bytes = uri.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            let allowed = b.is_ascii_alphanumeric()
                || b"-._~".contains(&b)
                || b"!$&'()*+,;=".contains(&b)
                || b":@/".contains(&b);
            if b == b'%' {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or("a % with no two digits after it")?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return Err(format!(
                        "a % followed by {:?}",
                        String::from_utf8_lossy(hex)
                    ));
                }
                i += 3;
                continue;
            }
            if !allowed {
                return Err(format!(
                    "the byte {b:#04x} ({:?}) must be percent-encoded",
                    b as char
                ));
            }
            i += 1;
        }
        Ok(())
    }

    fn percent_decoded(uri: &str) -> String {
        let bytes = uri.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).expect("the decoded bytes are UTF-8")
    }

    #[test]
    fn a_file_path_is_written_as_a_relative_uri_that_decodes_back_to_it() {
        let paths = [
            "src/app.py",
            "My Documents/app.py",
            "src/café/über straße.py",
            "日本語/ファイル.js",
            "a#b?c%d[e]/f g.ts",
            "weird:name.py",
            "C:/not/a/scheme.py",
            "../outside/app.py",
            "//looks/like/a/host.py",
        ];
        let findings: Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| finding(&format!("ast.rule-{i}"), p, i + 3, "x"))
            .collect();
        let value = sarif_of(findings);
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), paths.len(), "every finding is a result");
        for (result, path) in results.iter().zip(paths) {
            let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap_or_else(|| panic!("{path}: no uri in {result}"));
            if let Err(why) = is_relative_path_reference(uri) {
                panic!("{path} was written as {uri:?}, which is not a relative reference: {why}");
            }
            // `./` in front is how a path starting `//` stays a path; it names the same file.
            let decoded = percent_decoded(uri);
            let decoded = decoded.strip_prefix("./").unwrap_or(&decoded);
            assert_eq!(decoded, path, "{uri:?} does not decode back to the file");
        }
        // The setup really had the characters the test is about, and they really were encoded.
        let all = serde_json::to_string(&value).unwrap();
        assert!(all.contains("My%20Documents/app.py"), "{all}");
        assert!(all.contains("caf%C3%A9"), "{all}");
    }

    #[test]
    fn a_finding_about_the_running_app_gets_an_honest_place_github_will_take() {
        let mut probe = finding(
            "probe.admin-open",
            sv_check::Location::RUNNING_APP,
            1,
            "The page /admin opens without signing in",
        );
        probe.location = sv_check::Location::running_app();
        let mut logged = finding("probe.log-timestamp-zoned", "", 1, "A time with no zone");
        logged.location = sv_check::Location::running_app_output();
        let value = sarif_of(vec![probe, logged]);
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        for result in results {
            let location = &result["locations"][0];
            let uri = location["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap_or_else(|| panic!("GitHub needs a file for every result: {result}"));
            assert_eq!(
                uri, "securevibe.toml",
                "a running-app finding points at the manifest that says how the app was run"
            );
            is_relative_path_reference(uri).unwrap();
            let place = location["logicalLocations"][0]["name"].as_str().unwrap();
            assert!(place.starts_with("the running app"), "{location}");
            let said = location["message"]["text"].as_str().unwrap();
            assert!(said.contains("no file"), "{said}");
            // One line of plain words (the review of 6 October, item 16: a stray backslash and a
            // run of spaces were left in it).
            assert!(
                !said.contains(['\\', '\n']) && !said.contains("  "),
                "{said:?}"
            );
            assert_eq!(result["properties"]["place"], place, "{result}");
            // The address the probe asked stays in the result's own words.
            assert!(
                result["message"]["text"]
                    .as_str()
                    .unwrap()
                    .contains("/admin")
                    || place.ends_with("output"),
                "{result}"
            );
            // GitHub tracks alerts by this key; it must not be renamed.
            assert_eq!(
                result["partialFingerprints"]["svFingerprint/v1"],
                "0123456789abcdef"
            );
        }
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("\"uri\": \"the running app"),
            "no place that is not a file is written as a file address"
        );
    }

    fn rules_by_id(
        value: &serde_json::Value,
    ) -> std::collections::BTreeMap<String, serde_json::Value> {
        value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["id"].as_str().unwrap().to_owned(), r.clone()))
            .collect()
    }

    #[test]
    fn a_rule_is_described_the_same_whichever_of_its_findings_comes_first() {
        // A probe rule whose findings each name their own page: no one of them describes the rule.
        let mut a = finding(
            "probe.admin-open",
            "",
            1,
            "The page /admin opens without signing in",
        );
        let mut b = finding(
            "probe.admin-open",
            "",
            1,
            "The page /settings opens without signing in",
        );
        for f in [&mut a, &mut b] {
            f.location = sv_check::Location::running_app();
            f.impact = "Anyone can use it.".into();
            f.fix = "Ask for a sign-in.".into();
        }
        b.description = "Asked for /settings, it answered.".into();
        b.cwe = vec!["CWE-306".into()];
        // A rule from sv's own data, whose findings say more than the rule (the bound-parameter note).
        let mut c = finding("ast.sql-built-by-hand", "app.py", 3, "x");
        let mut d = finding("ast.sql-built-by-hand", "db.py", 9, "x");
        c.title = "SQL built by hand, first instance".into();
        d.title = "SQL built by hand, second instance".into();
        d.impact = "Something else entirely.".into();
        // A tool's rule, whose findings all carry the tool's rule text.
        let e = finding("semgrep.sqli", "app.py", 4, "Semgrep's own title");
        let mut f = finding("semgrep.sqli", "db.py", 2, "Semgrep's own title");
        f.description = "A different message for this one.".into();

        let forward = rules_by_id(&sarif_of(vec![
            a.clone(),
            b.clone(),
            c.clone(),
            d.clone(),
            e.clone(),
            f.clone(),
        ]));
        let backward = rules_by_id(&sarif_of(vec![f, e, d, c, b, a]));
        assert_eq!(forward.len(), 3, "{forward:?}");
        assert_eq!(
            forward, backward,
            "a rule's entry depends on which finding came first"
        );

        let probe = &forward["probe.admin-open"];
        let short = probe["shortDescription"]["text"].as_str().unwrap();
        assert!(
            !short.contains("/admin") && !short.contains("/settings"),
            "{probe}"
        );
        assert_eq!(probe["fullDescription"]["text"], "Anyone can use it.");
        assert_eq!(probe["help"]["text"], "Ask for a sign-in.");
        assert_eq!(
            probe["properties"]["tags"],
            serde_json::json!(["CWE-306", "CWE-89"]),
            "every weakness the rule's findings name"
        );

        // The rule's own words from data/ast-rules.json, not either finding's.
        let ast = &forward["ast.sql-built-by-hand"];
        let catalog: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let own = catalog["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "ast.sql-built-by-hand")
            .expect("the rule the test names is in the data file");
        assert_eq!(ast["shortDescription"]["text"], own["title"], "{ast}");
        assert!(
            ast["fullDescription"]["text"]
                .as_str()
                .unwrap()
                .contains(own["description"].as_str().unwrap()),
            "{ast}"
        );
        assert_eq!(ast["help"]["text"], own["fix"], "{ast}");

        let tool = &forward["semgrep.sqli"];
        assert_eq!(tool["shortDescription"]["text"], "Semgrep's own title");
        // Every rule's words are plain lines, the fallbacks for words its findings do not share
        // included (the review of 6 October, item 16).
        for (id, rule) in &forward {
            for part in ["fullDescription", "help"] {
                let text = rule[part]["text"].as_str().unwrap_or_default();
                assert!(
                    !text.contains(['\\', '\n']) && !text.contains("  "),
                    "{id} {part}: {text:?}"
                );
            }
        }
    }

    #[test]
    fn a_rule_whose_findings_differ_is_described_in_plain_lines() {
        // The review of 6 October, item 16: the words used when a rule's findings do not share
        // them carried a stray backslash and a run of spaces.
        let a = finding("othertool.thing", "a.py", 1, "One");
        let mut b = finding("othertool.thing", "b.py", 2, "Two");
        b.impact = "Another impact.".into();
        b.fix = "Another fix.".into();
        let rules = rules_by_id(&sarif_of(vec![a, b]));
        let rule = &rules["othertool.thing"];
        for part in ["fullDescription", "help"] {
            let text = rule[part]["text"].as_str().unwrap();
            assert!(
                text.contains("result's message"),
                "the setup: the fallback is used: {text}"
            );
            assert!(
                !text.contains(['\\', '\n']) && !text.contains("  "),
                "{part}: {text:?}"
            );
        }
    }

    #[test]
    fn a_secret_rule_is_described_from_its_own_data() {
        let catalog: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../data/secret-rules.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let own = &catalog["rules"][0];
        let id = own["id"].as_str().expect("the data file has a first rule");
        let mut f = finding(id, "config.py", 2, "A title that is not the rule's");
        f.fix = "A fix that is not the rule's".into();
        let rules = rules_by_id(&sarif_of(vec![f]));
        assert_eq!(rules[id]["shortDescription"]["text"], own["title"]);
        assert_eq!(rules[id]["help"]["text"], own["fix"]);
    }

    #[test]
    fn the_document_is_valid_sarif_shaped_json() {
        let value: serde_json::Value =
            serde_json::from_str(&render(&empty_report(vec![]))).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "sv");
        assert!(value["runs"][0]["results"].is_array());
    }
}
