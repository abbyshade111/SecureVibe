//! What the reports must never do.
//!
//! These are not tests of layout. Each one is a way a report can be wrong in the direction that
//! matters: making the app look more examined than it was.

use std::collections::BTreeSet;
use std::path::PathBuf;
use sv_check::Verified;
use sv_check::{Confidence, Finding, Location, Severity};
use sv_frameworks::applicability::{Buckets, NotApplicable, NotAssessed};
use sv_frameworks::{Condition, Frameworks, Source};
use sv_report::{Gap, Inputs, Status, build};

fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data")
}

fn frameworks() -> Frameworks {
    Frameworks::load(&data().join("frameworks")).expect("the OWASP data loads")
}

fn finding(rule_id: &str, requirement_ids: &[&str]) -> Finding {
    Finding {
        rule_id: rule_id.into(),
        title: "something".into(),
        severity: Severity::High,
        confidence: Confidence::High,
        location: Location {
            file: "app.py".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: requirement_ids.iter().map(|s| (*s).to_owned()).collect(),
        cwe: vec![],
        description: "d".into(),
        impact: "i".into(),
        fix: "f".into(),
    }
}

fn inputs<'a>(
    frameworks: &'a Frameworks,
    buckets: &'a Buckets,
    findings: Vec<Finding>,
    verified: &'a [Verified],
) -> Inputs<'a> {
    Inputs {
        app_name: "Test",
        target_level: 1,
        generated: None,
        run_note: None,
        run_steps: Vec::new(),
        frameworks,
        buckets,
        claims: &[],
        findings,
        verified,
        gaps: vec![],
        manual_only: Default::default(),
        named_in_tests: Default::default(),
        not_for_tests: Default::default(),
        documented: &[],
        attested: &[],
        human: None,
        threats: None,
    }
}

#[test]
fn a_requirement_nothing_looked_at_is_not_verified_rather_than_absent() {
    // The report's whole reason for existing. An applicable requirement with no evidence has to
    // appear, and appear as unexamined: leaving it out makes a report of 3 findings about 200
    // requirements read like a report about 3 requirements.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into(), "V1.3.1".into()],
        ..Default::default()
    };
    let report = build(inputs(&f, &buckets, vec![], &[]));
    assert_eq!(report.counts.applicable, 2);
    assert_eq!(report.counts.not_verified, 2);
    assert_eq!(report.requirements.len(), 2);
    assert!(
        report
            .requirements
            .iter()
            .all(|r| r.status == Status::NotVerified)
    );
}

#[test]
fn a_satisfied_check_never_hides_a_finding_about_the_same_requirement() {
    // Two checks can disagree about one requirement, and the report must take the worse answer.
    // Taking the happier one is how a report ends up saying "checked" about the exact requirement
    // something else just failed.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into()],
        ..Default::default()
    };
    let passed = vec![Verified::new(
        "config.something",
        &["V1.2.1"],
        "the files this check reads".to_owned(),
    )];
    let report = build(inputs(
        &f,
        &buckets,
        vec![finding("ast.sql", &["V1.2.1"])],
        &passed,
    ));
    assert_eq!(report.requirements[0].status, Status::NeedsAttention);
    assert_eq!(report.counts.checked, 0);
}

#[test]
fn nothing_is_ever_labelled_a_pass() {
    // "Checked" is an automated check being satisfied over stated coverage. The word "pass" would be read as the
    // requirement being met, which nothing in this workspace is able to establish.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into()],
        ..Default::default()
    };
    let passed = vec![Verified::new(
        "config.something",
        &["V1.2.1"],
        "the files this check reads".to_owned(),
    )];
    let report = build(inputs(&f, &buckets, vec![], &passed));
    assert_eq!(report.requirements[0].status, Status::Checked);

    let markdown = sv_report::markdown::compliance(&report);
    let html = sv_report::html::page(&report);
    // The status a reader sees against the requirement, which is the part that gets skimmed.
    assert_eq!(report.requirements[0].status.label(), "checked");
    for status in [Status::NeedsAttention, Status::Checked, Status::NotVerified] {
        assert!(
            !status.label().contains("pass"),
            "`{}` would be read as the requirement being met",
            status.label()
        );
    }
    for rendered in [&markdown, &html] {
        let lowered = rendered.to_lowercase();
        assert!(
            lowered.contains("not the same as the requirement being met"),
            "the report must say what `checked` is worth"
        );
        // The only sentences allowed to contain the word are the ones denying it.
        for line in rendered
            .lines()
            .filter(|l| l.to_lowercase().contains("passed"))
        {
            assert!(
                line.contains("nothing here") || line.contains("Nothing in this report"),
                "a report must not say a requirement passed: {line}"
            );
        }
    }
}

#[test]
fn the_reports_say_how_much_was_not_examined_before_they_say_what_was_found() {
    // Order is the message. Findings read first are read as the whole truth about the app.
    let f = frameworks();
    let buckets = Buckets::default();
    let mut i = inputs(&f, &buckets, vec![finding("ast.sql", &[])], &[]);
    i.gaps = vec![Gap {
        what: "the running app".into(),
        why: "no container backend".into(),
    }];
    let report = build(i);
    let security = sv_report::markdown::security(&report);
    let gaps_at = security
        .find("What was not examined")
        .expect("the gaps section");
    let findings_at = security.find("to fix").expect("the findings section");
    assert!(
        gaps_at < findings_at,
        "the gaps must come first:\n{security}"
    );
}

#[test]
fn a_finding_about_an_excluded_requirement_is_shown_rather_than_dropped() {
    // A check found something and named a requirement the engine excluded. Dropping the line hides
    // a possibly-wrong exclusion behind a clean count.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec![],
        not_applicable: vec![NotApplicable {
            id: "V1.2.1".into(),
            reason: "claimed no sign-in".into(),
            condition: Condition::Auth,
            source: Source::Claim,
        }],
        not_assessed: vec![NotAssessed {
            id: "V1.3.1".into(),
            blocked_on: vec![Condition::Auth],
        }],
        out_of_level: vec![],
    };
    let report = build(inputs(
        &f,
        &buckets,
        vec![finding("ast.sql", &["V1.2.1", "V1.3.1"])],
        &[],
    ));
    assert_eq!(report.out_of_scope.len(), 2, "{:?}", report.out_of_scope);
    assert!(
        report.out_of_scope[0].landed_in.contains("excluded"),
        "{:?}",
        report.out_of_scope[0]
    );
    let markdown = sv_report::markdown::compliance(&report);
    assert!(
        markdown.contains("not being assessed against"),
        "{markdown}"
    );
}

#[test]
fn every_requirement_a_check_cites_is_a_requirement_that_exists() {
    // The guard that found the fault this test was written after. Five checkers cited `AC-05`,
    // `AC-08`, `AC-09`, `AC-10` and `AC-13`: Appendix C *family* ids, written with a hyphen and a
    // leading zero instead of a dot, so they matched no requirement at all. A citation that
    // resolves to nothing is invisible — the report simply has one fewer line — and had the
    // spelling been right it would have been worse, because `config.secrets-file-committed`
    // passing would have marked an AI-explainability family as looked-at on the strength of a
    // .gitignore.
    let f = frameworks();
    let known: BTreeSet<&str> = f.requirements.keys().map(String::as_str).collect();

    let mut cited: BTreeSet<String> = BTreeSet::new();
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Both, and the second one is not obvious: the rules that read code and the credential formats
    // live in `data/*.json`, outside `crates/`. The first version of this test walked `crates/`
    // alone, collected fourteen ids, and passed — while every id in `ast-rules.json` and
    // `secret-rules.json` went unchecked. A guard that silently covers half of what it names is
    // worse than none, because the half it misses now looks guarded.
    collect_cited(&workspace.join("crates"), &mut cited);
    collect_cited(&workspace.join("data"), &mut cited);

    // The sanity check is that both sources were really reached, rather than a count that says
    // nothing about which files it came from.
    for (id, whose) in [
        ("V13.4.4", "the probes, in Rust"),
        ("V1.5.2", "the rules that read code, in JSON"),
        ("V11.1.1", "the credential formats, in JSON"),
    ] {
        assert!(
            cited.contains(id),
            "the collector never reached {whose}; it found {cited:?}"
        );
    }

    let unknown: Vec<&String> = cited
        .iter()
        .filter(|id| !known.contains(id.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "checks cite requirements that are in no loaded framework, so the citation does nothing: \
         {unknown:?}"
    );
}

/// Pulls every id out of the checkers' `requirement_ids` lists.
///
/// Only those lists, and not every id-shaped string in the files: the probes also name whole ASVS
/// chapters in prose, when saying which ones they *cannot* reach, and a chapter is not a
/// requirement. Reading those as citations would make this test fail on text that is already
/// correct — a guard that cries wolf is a guard that gets deleted.
fn collect_cited(dir: &std::path::Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_cited(&path, out);
            continue;
        }
        let Some(extension) = path.extension() else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if extension == "json" {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            collect_json(&value, out);
        } else if extension == "rs" {
            // Only `requirement_ids: vec![…]` and `requirement_ids: &[…]`, and only up to the
            // closing bracket. Splitting on the name alone also matches it in prose — the field's
            // own doc comment, for one — and then runs to some unrelated `]` far below, dragging
            // in every string literal in between. The first version of this did exactly that and
            // reported ninety "bad citations", none of which were citations.
            for tail in text.split("requirement_ids").skip(1) {
                let Some(open) = tail.find('[') else { continue };
                let between = &tail[..open];
                if !between
                    .trim_start_matches(':')
                    .trim()
                    .trim_end_matches('&')
                    .trim_end_matches("vec!")
                    .trim()
                    .is_empty()
                {
                    continue;
                }
                let Some(end) = tail[open..].find(']') else {
                    continue;
                };
                for quoted in tail[open..open + end].split('"').skip(1).step_by(2) {
                    out.insert(quoted.to_owned());
                }
            }
        }
    }
}

fn collect_json(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key == "requirementIds" {
                    if let Some(ids) = child.as_array() {
                        out.extend(ids.iter().filter_map(|v| v.as_str()).map(str::to_owned));
                    }
                } else {
                    collect_json(child, out);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|v| collect_json(v, out)),
        _ => {}
    }
}

#[test]
fn the_rendered_pages_tell_the_same_story_as_the_model() {
    // A second witness for the rules above, of a different shape: what a reader actually sees,
    // rather than what the struct holds. A renderer that quietly omits the contested requirement,
    // or puts the gaps below the findings, is wrong in exactly the way that matters and none of
    // the model-level tests would notice.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into(), "V1.3.1".into(), "V13.3.1".into()],
        ..Default::default()
    };
    let passed = vec![Verified::new(
        // The same requirement something else found a problem in.
        "config.contested",
        &["V1.2.1"],
        "the files this check reads".to_owned(),
    )];
    let mut i = inputs(&f, &buckets, vec![finding("ast.sql", &["V1.2.1"])], &passed);
    i.gaps = vec![Gap {
        what: "the running app".into(),
        why: "no container backend".into(),
    }];
    let report = build(i);

    let html = sv_report::html::page(&report);
    let compliance = sv_report::markdown::compliance(&report);

    for rendered in [&html, &compliance] {
        // Every applicable requirement appears, including the two nothing looked at.
        for id in ["V1.2.1", "V1.3.1", "V13.3.1"] {
            assert!(rendered.contains(id), "{id} is missing from the page");
        }
        // The contested one is shown as needing attention, not as checked. Anchored on the table
        // row rather than on the first mention anywhere: the id appears in prose above the table
        // too, and a window measured from the first match reads whatever happens to follow it.
        let marker = if rendered.starts_with("# ") {
            "| V1.2.1 |"
        } else {
            "<code>V1.2.1</code>"
        };
        let at = rendered
            .find(marker)
            .unwrap_or_else(|| panic!("no table row for V1.2.1 in:\n{rendered}"));
        let row = &rendered[at..(at + 200).min(rendered.len())];
        assert!(
            row.contains("needs attention"),
            "the contested requirement reads as checked: {row}"
        );
        // And what was not examined comes before the tables of what was.
        let gaps_at = rendered
            .find("What was not examined")
            .expect("the gaps section");
        let table_at = rendered
            .find("Requirements that apply")
            .expect("the requirements table");
        assert!(gaps_at < table_at, "the gaps must come first");
    }
}

#[test]
fn a_satisfied_check_outside_the_tables_is_shown_rather_than_vanishing() {
    // Found by running it: the probes verified three requirements that are above the app's target
    // level, the count said "0 checked", and a reader would have concluded the probes never ran.
    // A vanishing positive claim is safer than a vanishing finding and still says something untrue.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into()],
        out_of_level: vec!["V13.4.4".into()],
        not_assessed: vec![NotAssessed {
            id: "V16.5.1".into(),
            blocked_on: vec![Condition::Auth],
        }],
        ..Default::default()
    };
    let verified = vec![
        Verified::new(
            "probe.trace-enabled",
            &["V13.4.4"],
            "a TRACE request".to_owned(),
        ),
        Verified::new("config.security-contact", &[], "SECURITY.md".to_owned()),
    ];
    let report = build(inputs(&f, &buckets, vec![], &verified));

    assert_eq!(report.counts.checked, 0, "neither is in scope");
    assert_eq!(
        report.satisfied_elsewhere.len(),
        2,
        "{:?}",
        report.satisfied_elsewhere
    );

    let trace = &report.satisfied_elsewhere[0];
    assert!(
        trace.why.contains("above this app's target level"),
        "{}",
        trace.why
    );
    let contact = &report.satisfied_elsewhere[1];
    assert!(contact.why.contains("no requirement"), "{}", contact.why);

    for rendered in [
        sv_report::markdown::compliance(&report),
        sv_report::html::page(&report),
    ] {
        assert!(
            rendered.contains("probe.trace-enabled"),
            "a check that ran must appear somewhere:\n{rendered}"
        );
    }
}

#[test]
fn a_check_whose_requirements_landed_in_different_places_says_so_for_each() {
    // Second witness, of a different shape: one check, three requirements, three fates. Reporting
    // the first one's fate as though it were all of theirs is a small untruth a reader cannot catch.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec![],
        out_of_level: vec!["V13.4.4".into()],
        not_assessed: vec![NotAssessed {
            id: "V16.5.1".into(),
            blocked_on: vec![Condition::Auth],
        }],
        not_applicable: vec![NotApplicable {
            id: "V13.4.2".into(),
            reason: "claimed no sign-in".into(),
            condition: Condition::Auth,
            source: Source::Claim,
        }],
    };
    let verified = vec![Verified::new(
        "probe.several",
        &["V13.4.4", "V16.5.1", "V13.4.2"],
        "one request".to_owned(),
    )];
    let report = build(inputs(&f, &buckets, vec![], &verified));
    let why = &report.satisfied_elsewhere[0].why;
    assert!(why.contains("above this app's target level"), "{why}");
    assert!(why.contains("not assessed"), "{why}");
    assert!(why.contains("excluded"), "{why}");
}

#[test]
fn a_report_from_a_run_says_it_was_a_run() {
    // A report whose evidence came from a running app is a different kind of document from one that
    // only read files, and the reader should not have to work that out from which sections happen
    // to be populated.
    let f = frameworks();
    let buckets = Buckets::default();
    let mut i = inputs(&f, &buckets, vec![], &[]);
    i.run_note = Some("This app was started with busybox:1.36 and asked 4 questions.".to_owned());
    let report = build(i);
    for rendered in [
        sv_report::markdown::compliance(&report),
        sv_report::html::page(&report),
    ] {
        let at = rendered
            .find("asked 4 questions")
            .expect("the run note must appear");
        let table_at = rendered
            .find("Requirements that apply")
            .unwrap_or(rendered.len());
        assert!(at < table_at, "the run note belongs near the top");
    }
}

#[test]
fn a_clean_check_about_a_design_review_requirement_supports_it_and_does_not_check_it() {
    // SBD-AC-05 asks for a secret manager, automatic rotation and no secrets in the code. A clean
    // credential scan speaks to the last of those only. Filed as "checked" it would claim the other
    // two, which is how V13.3.1 (use a key vault) was reported as checked by a scan of source files.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["SBD-AC-05".into(), "V1.2.4".into()],
        ..Default::default()
    };
    let passed = vec![
        Verified::new("secrets.scan", &["SBD-AC-05"], "12 files".into()),
        Verified::new(
            "ast.sql-built-by-hand",
            &["V1.2.4"],
            "3 python files".into(),
        ),
    ];
    let mut i = inputs(&f, &buckets, vec![], &passed);
    i.manual_only = BTreeSet::from(["SBD-AC-05".to_owned()]);
    let report = build(i);
    let line = |id: &str| report.requirements.iter().find(|l| l.id == id).unwrap();

    let sbd = line("SBD-AC-05");
    assert_eq!(sbd.status, Status::NotVerified);
    assert!(sbd.checked_by.is_empty(), "{:?}", sbd.checked_by);
    assert_eq!(sbd.supported_by.len(), 1);
    assert_eq!(sbd.supported_by[0].check_id, "secrets.scan");

    // A requirement a check can settle is still settled by one.
    assert_eq!(line("V1.2.4").status, Status::Checked);
    assert_eq!(
        report.counts.checked, 1,
        "only the settled one counts as checked"
    );

    // And both renderings say whose answer it still needs, and what was looked at.
    for (what, text) in [
        ("markdown", sv_report::markdown::compliance(&report)),
        ("html", sv_report::html::page(&report)),
    ] {
        assert!(
            text.contains("a person has to answer it; supporting: secrets.scan: 12 files"),
            "{what} does not show the supporting evidence"
        );
    }
}

#[test]
fn a_finding_against_a_design_review_requirement_still_needs_attention() {
    // The other direction. A committed credential is a plain failure of "no secrets in code/logs",
    // and being design review does not soften that.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["SBD-AC-05".into()],
        ..Default::default()
    };
    let mut i = inputs(
        &f,
        &buckets,
        vec![finding("secrets.stripe-key", &["V13.3.1", "SBD-AC-05"])],
        &[],
    );
    i.manual_only = BTreeSet::from(["SBD-AC-05".to_owned()]);
    let report = build(i);
    assert_eq!(report.requirements[0].status, Status::NeedsAttention);
}

/// The whole chain the CLI runs, on real data: the OWASP files, the v2 applicability rules, the
/// credential scan over a real folder, and the report built from what those produce.
fn report_for_folder(files: &[(&str, &str)]) -> sv_report::Report {
    use sv_frameworks::applicability::{ApplicabilityConfig, ConditionContext, bucket};
    let dir = std::env::temp_dir().join(format!(
        "sv-report-chain-{}-{}",
        std::process::id(),
        files[0].0.replace('.', "-")
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    for (name, contents) in files {
        std::fs::write(dir.join(name), contents).unwrap();
    }
    let agnostic = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rules =
        sv_check::secrets::SecretRules::load(&agnostic.join("data/secret-rules.json")).unwrap();
    let scan = sv_check::secrets::scan_dir(&rules, &dir);
    std::fs::remove_dir_all(&dir).ok();

    let f = frameworks();
    let config = ApplicabilityConfig::load_v2(
        &data().join("knowledge"),
        &agnostic.join("data/applicability-v2.json"),
    )
    .unwrap();
    let buckets = bucket(&f, &config, &ConditionContext::default(), 3);
    let manual_only = buckets.manual_only(&config);
    build(Inputs {
        app_name: "Chain",
        target_level: 3,
        generated: None,
        run_note: None,
        run_steps: Vec::new(),
        frameworks: &f,
        buckets: &buckets,
        claims: &[],
        findings: scan.findings.clone(),
        verified: &scan.verified,
        gaps: vec![],
        manual_only,
        named_in_tests: Default::default(),
        not_for_tests: Default::default(),
        documented: &[],
        attested: &[],
        human: None,
        threats: None,
    })
}

#[test]
fn end_to_end_a_clean_scan_supports_the_secrets_controls_and_checks_none_of_them() {
    let report = report_for_folder(&[("app.py", "import os\nKEY = os.environ['STRIPE_KEY']\n")]);
    for id in ["SBD-AC-05", "V13.3.1", "V11.1.1"] {
        let line = report
            .requirements
            .iter()
            .find(|l| l.id == id)
            .unwrap_or_else(|| panic!("{id} should apply"));
        assert_eq!(line.status, Status::NotVerified, "{id}");
        assert!(
            line.supported_by
                .iter()
                .any(|c| c.check_id == "secrets.scan"),
            "{id}: {:?}",
            line.supported_by
        );
    }
}

#[test]
fn end_to_end_a_committed_secret_is_against_no_secrets_in_code() {
    // Both routes: a key in a known shape, and a value assigned to a name that says password. The
    // key is put together at run time, as the credential scanner's own tests do: a literal that looks
    // like a real key is one GitHub's push protection blocks, and it blocked this test once.
    let stripe = format!(
        "stripe.api_key = '{}'\n",
        ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_")
    );
    for (name, contents) in [
        ("billing.py", stripe.as_str()),
        ("db.py", "DB_PASSWORD = 'q8#Vz!pL2@xR9$mK4&tW'\n"),
    ] {
        let report = report_for_folder(&[(name, contents)]);
        let line = report
            .requirements
            .iter()
            .find(|l| l.id == "SBD-AC-05")
            .unwrap();
        assert_eq!(
            line.status,
            Status::NeedsAttention,
            "{name}: {:?}",
            line.findings
        );
    }
}

fn frameworks_with_crosswalk() -> Frameworks {
    let mut f = frameworks();
    f.apply_crosswalk(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/sbd-asvs-crosswalk.json"),
    )
    .expect("the crosswalk applies");
    f
}

#[test]
fn a_checklist_control_above_the_target_says_where_its_level_came_from() {
    // "Above the ASVS level this app targets" was said of checklist controls whose level ASVS never
    // gave. Each is now listed with its basis, in the table and wherever a check lands on one.
    let f = frameworks_with_crosswalk();
    let buckets = Buckets {
        out_of_level: vec!["SBD-DM-01".into(), "V13.3.1".into()],
        ..Default::default()
    };
    let report = build(inputs(
        &f,
        &buckets,
        vec![finding("some.rule", &["SBD-DM-01"])],
        &[],
    ));
    assert_eq!(
        report.checklist_above_level.len(),
        1,
        "ASVS's own are not listed"
    );
    assert_eq!(report.checklist_above_level[0].id, "SBD-DM-01");
    assert_eq!(report.checklist_above_level[0].basis, "level 2, as V14.1.1");
    let landed = &report.out_of_scope[0].landed_in;
    assert!(
        landed.starts_with("above this app's target level") && landed.contains("as V14.1.1"),
        "{landed}"
    );
    for (what, text) in [
        ("markdown", sv_report::markdown::compliance(&report)),
        ("html", sv_report::html::page(&report)),
    ] {
        assert!(!text.contains("Above ASVS level"), "{what} still says it");
        assert!(
            text.contains("level 2, as V14.1.1"),
            "{what} does not show the basis"
        );
    }
}

#[test]
fn evidence_about_an_asvs_counterpart_supports_the_control_and_checks_nothing() {
    // A satisfied check about V16.5.2 (operate securely when a dependency fails) is evidence about
    // part of what SBD-RR-02 asks; it is shown beside it, and the control stays not verified.
    let f = frameworks_with_crosswalk();
    let buckets = Buckets {
        applicable: vec!["SBD-RR-02".into(), "V16.5.2".into()],
        ..Default::default()
    };
    let passed = vec![Verified::new(
        "probe.dependency-down",
        &["V16.5.2"],
        "one probe".into(),
    )];
    let mut i = inputs(&f, &buckets, vec![], &passed);
    i.manual_only = BTreeSet::from(["SBD-RR-02".to_owned()]);
    let report = build(i);
    let line = |id: &str| report.requirements.iter().find(|l| l.id == id).unwrap();
    assert_eq!(
        line("V16.5.2").status,
        Status::Checked,
        "the counterpart itself is checked"
    );
    let control = line("SBD-RR-02");
    assert_eq!(control.status, Status::NotVerified);
    assert!(control.checked_by.is_empty());
    assert_eq!(control.supported_by.len(), 1);
    assert!(
        control.supported_by[0]
            .scope
            .ends_with("as evidence about V16.5.2"),
        "{}",
        control.supported_by[0].scope
    );
}

#[test]
fn a_satisfied_check_on_a_checklist_control_above_the_target_names_the_basis_too() {
    // Second witness for the basis, through the other place a requirement's fate is reported: a
    // satisfied check whose requirement is not in the tables.
    let f = frameworks_with_crosswalk();
    let buckets = Buckets {
        out_of_level: vec!["SBD-DM-01".into()],
        ..Default::default()
    };
    let passed = vec![Verified::new("some.check", &["SBD-DM-01"], "x".into())];
    let report = build(inputs(&f, &buckets, vec![], &passed));
    let why = &report.satisfied_elsewhere[0].why;
    assert!(why.contains("as V14.1.1"), "{why}");
}

#[test]
fn counterpart_evidence_supports_a_control_even_when_nothing_marked_it_manual() {
    // Second witness for the crosswalk's evidence, by the other route: the control is not in the
    // manual-only set handed in, and evidence about its counterpart still only supports it.
    let f = frameworks_with_crosswalk();
    let buckets = Buckets {
        applicable: vec!["SBD-AC-01".into()],
        ..Default::default()
    };
    let passed = vec![Verified::new("probe.tls", &["V12.3.1"], "one probe".into())];
    let report = build(inputs(&f, &buckets, vec![], &passed));
    let line = &report.requirements[0];
    assert_eq!(line.status, Status::NotVerified);
    assert_eq!(line.supported_by.len(), 1, "{:?}", line.supported_by);
}

#[test]
fn tests_to_write_are_what_nothing_answered_and_no_test_names_lowest_level_first() {
    let f = frameworks();
    let buckets = Buckets {
        applicable: [
            "V1.3.10", "V1.3.7", "V1.2.2", "V1.3.2", "V1.2.1", "V1.2.4", "V11.1.1", "V2.1.1",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect(),
        ..Default::default()
    };
    let passed = vec![Verified::new(
        "ast.sql-built-by-hand",
        &["V1.2.4"],
        "the code".to_owned(),
    )];
    let mut i = inputs(&f, &buckets, vec![finding("x", &["V1.2.1"])], &passed);
    i.manual_only = BTreeSet::from(["V11.1.1".to_owned()]);
    i.named_in_tests = BTreeSet::from(["V2.1.1".to_owned()]);
    let report = build(i);
    let ids: Vec<(&str, u8)> = report
        .tests_to_write
        .iter()
        .map(|t| (t.id.as_str(), t.level))
        .collect();
    // Found (V1.2.1), checked (V1.2.4), a person's to answer (V11.1.1), and named in a test that
    // did not run (V2.1.1) are all left out; the rest by level, then in the order a reader counts.
    assert_eq!(
        ids,
        [("V1.2.2", 1), ("V1.3.2", 1), ("V1.3.7", 2), ("V1.3.10", 2)]
    );
    assert_eq!(report.named_not_credited, ["V2.1.1"]);
}

#[test]
fn the_tests_to_write_are_in_the_written_report() {
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.2".into(), "V2.1.1".into()],
        ..Default::default()
    };
    let mut i = inputs(&f, &buckets, vec![], &[]);
    i.named_in_tests = BTreeSet::from(["V2.1.1".to_owned()]);
    let report = build(i);
    let md = sv_report::markdown::compliance(&report);
    assert!(md.contains("## Tests worth writing first"), "{md}");
    // V1.2.2 is level 1, so it is one of the ones a person is handed.
    assert!(md.contains("| V1.2.2 |"), "{md}");
    assert!(md.contains("still without evidence") && md.contains("V2.1.1"));
    let html = sv_report::html::page(&report);
    assert!(html.contains("<h2>Tests worth writing first</h2>"));
}

#[test]
fn what_a_test_cannot_show_is_counted_and_not_listed() {
    // A test of the application cannot show a policy was written or a process followed. Listing
    // those as tests to write would send somebody to write tests that prove nothing.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.2".into(), "V2.1.1".into(), "V11.1.1".into()],
        ..Default::default()
    };
    let mut i = inputs(&f, &buckets, vec![], &[]);
    i.not_for_tests = BTreeSet::from(["V2.1.1".to_owned()]);
    i.manual_only = BTreeSet::from(["V11.1.1".to_owned()]);
    let report = build(i);
    let ids: Vec<&str> = report
        .tests_to_write
        .iter()
        .map(|t| t.id.as_str())
        .collect();
    assert_eq!(ids, ["V1.2.2"]);
    assert_eq!(report.not_for_tests, 2);
    let md = sv_report::markdown::compliance(&report);
    assert!(
        md.contains("2 more have no evidence and are not listed"),
        "{md}"
    );
}

/// The security notes tier: the owner's written answer, and everything it must not become.
mod documented {
    use super::*;
    use sv_report::Report;

    fn answered(id: &str) -> Verified {
        Verified::new(
            "notes.documented",
            &[id],
            format!("security-notes.md, under \"{id} — a question\""),
        )
    }

    fn report_with(
        documented: &[Verified],
        verified: &[Verified],
        findings: Vec<Finding>,
    ) -> Report {
        let f = Frameworks::load(&data().join("frameworks")).unwrap();
        let buckets = Buckets {
            applicable: vec!["V6.1.1".into(), "V8.1.1".into()],
            ..Default::default()
        };
        let mut inputs = inputs(&f, &buckets, findings, verified);
        inputs.documented = documented;
        build(inputs)
    }

    fn status_of(report: &Report, id: &str) -> Status {
        report
            .requirements
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} is missing from the report"))
            .status
    }

    #[test]
    fn an_answer_in_the_notes_is_its_own_tier_and_not_checked() {
        let report = report_with(&[answered("V6.1.1")], &[], vec![]);
        assert_eq!(status_of(&report, "V6.1.1"), Status::Documented);
        assert_eq!(status_of(&report, "V8.1.1"), Status::NotVerified);
        assert_eq!(report.counts.documented, 1);
        assert_eq!(
            report.counts.checked, 0,
            "a written answer is never counted as a check that ran"
        );
    }

    #[test]
    fn the_report_says_where_the_answer_is() {
        // "Documented" with nowhere to look is a line a reader has to take on trust.
        let report = report_with(&[answered("V6.1.1")], &[], vec![]);
        let line = report
            .requirements
            .iter()
            .find(|r| r.id == "V6.1.1")
            .unwrap();
        assert!(
            line.documented_by
                .iter()
                .any(|d| d.scope.contains("security-notes.md")),
            "got {:?}",
            line.documented_by
        );
        let markdown = sv_report::markdown::compliance(&report);
        assert!(markdown.contains("security-notes.md"), "{markdown}");
        let html = sv_report::html::page(&report);
        assert!(html.contains("security-notes.md"), "{html}");
    }

    #[test]
    fn a_finding_beats_an_answer_in_the_notes() {
        // The owner writing "we rate limit sign-in" must never bury a check that found otherwise.
        let report = report_with(
            &[answered("V6.1.1")],
            &[],
            vec![finding("some.rule", &["V6.1.1"])],
        );
        assert_eq!(status_of(&report, "V6.1.1"), Status::NeedsAttention);
    }

    #[test]
    fn a_check_that_ran_beats_an_answer_in_the_notes() {
        let report = report_with(
            &[answered("V6.1.1")],
            &[Verified::new("some.check", &["V6.1.1"], "8 files".into())],
            vec![],
        );
        assert_eq!(
            status_of(&report, "V6.1.1"),
            Status::Checked,
            "evidence read from the app outranks the owner's word about it"
        );
    }

    #[test]
    fn a_documented_requirement_is_not_listed_as_a_test_to_write() {
        let report = report_with(&[answered("V6.1.1")], &[], vec![]);
        assert!(
            !report.tests_to_write.iter().any(|t| t.id == "V6.1.1"),
            "got {:?}",
            report.tests_to_write
        );
    }

    #[test]
    fn the_row_calls_it_documented_and_never_a_pass() {
        // Both reports carry a line saying nothing here is a pass, so the whole-document search
        // that first stood here matched its own disclaimer. The claim worth making is narrower:
        // the requirement's own row says documented, and says it in those words.
        let report = report_with(&[answered("V6.1.1")], &[], vec![]);
        let markdown = sv_report::markdown::compliance(&report);
        let row = markdown
            .lines()
            .find(|l| l.starts_with("| `V6.1.1`") || l.starts_with("| V6.1.1"))
            .unwrap_or_else(|| panic!("no row for V6.1.1 in:\n{markdown}"));
        // The status cell alone. The requirement's own wording is in the same row and says
        // "password", which is what a whole-row search for "pass" finds.
        let status = row.split('|').nth(2).unwrap_or_default();
        assert!(status.contains("documented by the owner"), "got {row}");
        assert!(
            !status.to_lowercase().contains("pass") && !status.contains("checked"),
            "got {status}"
        );
    }
}

/// The attested tier: the weakest claim in the report, and what keeps it weak.
mod attested {
    use super::*;
    use sv_report::Report;

    fn said_yes(id: &str) -> Verified {
        Verified::new(
            "design.attested",
            &[id],
            "securevibe.toml: you answered yes. This is your word about the app, not a check of it."
                .to_owned(),
        )
    }

    fn report_with(
        attested: &[Verified],
        documented: &[Verified],
        verified: &[Verified],
    ) -> Report {
        let f = Frameworks::load(&data().join("frameworks")).unwrap();
        let buckets = Buckets {
            applicable: vec!["V8.3.1".into(), "V2.2.2".into()],
            ..Default::default()
        };
        let mut inputs = inputs(&f, &buckets, vec![], verified);
        inputs.attested = attested;
        inputs.documented = documented;
        build(inputs)
    }

    fn status_of(report: &Report, id: &str) -> Status {
        report
            .requirements
            .iter()
            .find(|r| r.id == id)
            .unwrap()
            .status
    }

    #[test]
    fn an_answer_of_yes_is_the_weakest_tier_and_not_documented_or_checked() {
        let report = report_with(&[said_yes("V8.3.1")], &[], &[]);
        assert_eq!(status_of(&report, "V8.3.1"), Status::Attested);
        assert_eq!(report.counts.attested, 1);
        assert_eq!(report.counts.documented, 0);
        assert_eq!(report.counts.checked, 0);
    }

    #[test]
    fn an_attested_requirement_is_still_a_test_to_write() {
        // The honest half of the tier. An attestation is the owner's word that a control exists,
        // and a test naming the requirement is how that word would be made good. If an attestation
        // took the requirement off this list, "attested" would have quietly become "checked"
        // without anyone deciding to make it so.
        let report = report_with(&[said_yes("V8.3.1")], &[], &[]);
        assert!(
            report.tests_to_write.iter().any(|t| t.id == "V8.3.1"),
            "an attested requirement still wants a test: {:?}",
            report.tests_to_write
        );
        // And a checked one does not, which is what makes the line above mean something.
        let checked = report_with(
            &[],
            &[],
            &[Verified::new("some.check", &["V8.3.1"], "8 files".into())],
        );
        assert!(!checked.tests_to_write.iter().any(|t| t.id == "V8.3.1"));
    }

    #[test]
    fn a_document_outranks_an_attestation_and_a_check_outranks_both() {
        let documented = report_with(&[said_yes("V8.3.1")], &[said_yes("V8.3.1")], &[]);
        assert_eq!(status_of(&documented, "V8.3.1"), Status::Documented);
        let checked = report_with(
            &[said_yes("V8.3.1")],
            &[said_yes("V8.3.1")],
            &[Verified::new("some.check", &["V8.3.1"], "8 files".into())],
        );
        assert_eq!(status_of(&checked, "V8.3.1"), Status::Checked);
    }

    #[test]
    fn the_row_says_it_is_the_owners_word_rather_than_a_check() {
        let report = report_with(&[said_yes("V8.3.1")], &[], &[]);
        let markdown = sv_report::markdown::compliance(&report);
        let row = markdown
            .lines()
            .find(|l| l.starts_with("| V8.3.1"))
            .unwrap_or_else(|| panic!("no row for V8.3.1 in:\n{markdown}"));
        let status = row.split('|').nth(2).unwrap_or_default();
        assert!(status.contains("attested by the owner"), "got {row}");
        assert!(
            status.contains("your word") && !status.contains("checked"),
            "a reader must not take this for a check: {status}"
        );
        assert!(sv_report::html::page(&report).contains("attested by the owner"));
    }
}

/// The two renderings of one report, held to the same shape.
mod same_story {
    use super::*;

    /// Section headings in the order each renderer emits them, folded and unfolded alike.
    ///
    /// One pass over the document, taking whichever marker comes next. The first version collected
    /// headings and `<summary>` labels into two separate lists and chained them, which loses the
    /// order *between* an open section and a folded one — so swapping an open section with a
    /// folded one changed nothing either list could see, and was caught by nothing.
    fn order(text: &str, pairs: &[(&str, &str)]) -> Vec<String> {
        let mut out = Vec::new();
        let mut at = 0usize;
        loop {
            let next = pairs
                .iter()
                .filter_map(|(open, close)| text[at..].find(open).map(|i| (at + i, *open, *close)))
                .min_by_key(|(i, _, _)| *i);
            let Some((i, open, close)) = next else { break };
            let from = i + open.len();
            let Some(j) = text[from..].find(close) else {
                break;
            };
            out.push(
                text[from..from + j]
                    .replace("<strong>", "")
                    .replace("</strong>", "")
                    .split('\u{2014}')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
            );
            at = from + j;
        }
        out
    }

    /// A report rich enough that every optional section is emitted.
    ///
    /// The first version of this used a minimal report, so most sections appeared in neither
    /// renderer, the shared list was four headings long, and swapping two of the absent ones was
    /// caught by nothing. A guard over sections that happen to exist is a guard over nothing.
    fn full_report() -> sv_report::Report {
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec![
                "V1.2.2".into(),
                "V2.1.1".into(),
                "V13.3.1".into(),
                "V6.2.1".into(),
            ],
            not_applicable: vec![sv_frameworks::applicability::NotApplicable {
                id: "V17.1.1".into(),
                reason: "no WebRTC".into(),
                condition: sv_frameworks::Condition::Webrtc,
                source: sv_frameworks::Source::Claim,
            }],
            not_assessed: vec![sv_frameworks::applicability::NotAssessed {
                id: "V5.1.1".into(),
                blocked_on: vec![sv_frameworks::Condition::Uploads],
            }],
            out_of_level: vec!["SBD-AC-01".into()],
        };
        // A finding naming a requirement outside the applicable set, so the out-of-scope section
        // exists; and a claim, so the "what the app says about itself" section does.
        let mut i = inputs(&f, &buckets, vec![finding("some.rule", &["V17.1.1"])], &[]);
        // So "What was not examined" is emitted too: it is one of the sections whose order matters
        // most, being the one the reports lead with.
        i.gaps = vec![sv_report::Gap {
            what: "the app while it was running".into(),
            why: "it was not started".into(),
        }];
        i.claims = CLAIMS.get_or_init(|| {
            vec![sv_manifest::ResolvedClaim {
                condition: sv_frameworks::Condition::Uploads,
                claimed: Some(false),
                found_in_code: Some(true),
                effective: Some(true),
                state: sv_manifest::ClaimState::Contradicted,
            }]
        });
        build(i)
    }

    static CLAIMS: std::sync::OnceLock<Vec<sv_manifest::ResolvedClaim>> =
        std::sync::OnceLock::new();

    fn both() -> (Vec<String>, Vec<String>) {
        let report = full_report();
        let md = sv_report::markdown::compliance(&report);
        let html = sv_report::html::page(&report);
        (
            order(&md, &[("\n## ", "\n"), ("<summary>", "</summary>")]),
            order(&html, &[("<h2>", "</h2>"), ("<summary>", "</summary>")]),
        )
    }

    #[test]
    fn the_two_reports_order_their_sections_the_same_way() {
        // They did not. "Requirements that do not apply" came before "Requirements nobody has
        // placed" in the Markdown and last in the HTML, and nothing noticed, because every test
        // asked whether a section was present and none asked where. Two renderings of one report
        // disagreeing about what matters most is the kind of thing a reader half-notices and
        // stops trusting.
        let (md, html) = both();
        let shared: Vec<&String> = md.iter().filter(|h| html.contains(h)).collect();
        let html_shared: Vec<&String> = html.iter().filter(|h| md.contains(h)).collect();
        assert_eq!(
            shared, html_shared,
            "the Markdown and HTML reports list their shared sections in different orders"
        );
        // Enough of them to mean something. With four, swapping two sections the fixture never
        // emitted was caught by nothing.
        assert!(
            shared.len() >= 8,
            "too few shared sections for this to be a real check: {shared:?}"
        );
    }

    #[test]
    fn the_bulk_reference_sections_are_folded_away_in_both() {
        // These are hundreds of rows of reference. Left open they are most of the document, and
        // the reader scrolls past everything that mattered to get out of them.
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec!["V1.2.2".into()],
            not_applicable: vec![sv_frameworks::applicability::NotApplicable {
                id: "V17.1.1".into(),
                reason: "no WebRTC".into(),
                condition: sv_frameworks::Condition::Webrtc,
                source: sv_frameworks::Source::Claim,
            }],
            ..Default::default()
        };
        let report = build(inputs(&f, &buckets, vec![], &[]));
        for text in [
            sv_report::markdown::compliance(&report),
            sv_report::html::page(&report),
        ] {
            let at = text
                .find("Requirements that do not apply")
                .unwrap_or_else(|| panic!("the section is missing:\n{text}"));
            let before = &text[at.saturating_sub(200)..at];
            assert!(
                before.contains("<summary>"),
                "it must be foldable, not a plain heading: {before}"
            );
        }
    }
}

/// The checklist of what only a person can check.
mod only_you {
    use super::*;

    fn catalogs() -> (
        sv_check::notes::Catalog,
        sv_check::design::Questions,
        sv_check::human::HumanChecks,
    ) {
        let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data");
        (
            sv_check::notes::Catalog::load(&data.join("security-notes.json")).unwrap(),
            sv_check::design::Questions::load(&data.join("design-questions.json")).unwrap(),
            sv_check::human::HumanChecks::load(&data.join("human-checks.json")).unwrap(),
        )
    }

    fn report_with_and_without() -> (sv_report::Report, sv_report::Report) {
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec![
                "V6.1.1".into(),
                "V12.2.2".into(),
                "V8.3.1".into(),
                "V1.2.2".into(),
            ],
            ..Default::default()
        };
        // These three ask for a written decision, a design answer, or a look at production, so a
        // test of the application cannot show them — which is what puts them on this list rather
        // than under "tests worth writing". The CLI works this out from the applicability data;
        // here it is stated, and without it every one of them lands in tests_to_write and the list
        // under test is empty.
        let not_for_tests: BTreeSet<String> = ["V6.1.1", "V12.2.2", "V8.3.1"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let mut plain_inputs = inputs(&f, &buckets, vec![], &[]);
        plain_inputs.not_for_tests = not_for_tests.clone();
        let plain = build(plain_inputs);
        let (notes, design, human) = catalogs();
        let mut i = inputs(&f, &buckets, vec![], &[]);
        i.not_for_tests = not_for_tests;
        i.human = Some((&notes, &design, &human));
        (build(i), plain)
    }

    #[test]
    fn nothing_here_credits_a_requirement() {
        // The one thing this section could get wrong. An instruction for how to check something is
        // not the check: every requirement on the list must read exactly as it did before the list
        // existed, and every count must be the same number.
        let (with, without) = report_with_and_without();
        assert_eq!(
            with.counts.checked, without.counts.checked,
            "the checklist changed the checked count"
        );
        assert_eq!(with.counts.documented, without.counts.documented);
        assert_eq!(with.counts.attested, without.counts.attested);
        assert_eq!(
            with.counts.not_verified, without.counts.not_verified,
            "the checklist moved a requirement out of not-verified"
        );
        for (a, b) in with.requirements.iter().zip(&without.requirements) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.status, b.status, "{} changed status", a.id);
        }
        assert!(
            !with.only_you_can_check.is_empty(),
            "and the list is not empty, or this proves nothing"
        );

        // Asserted directly, not by comparing the two reports. The first version of this test did
        // only the comparison above, and a mutation that credited every requirement on the list
        // was caught by four other tests and not by this one — because the crediting happens in
        // code that runs whether or not the catalogs were supplied, so both sides moved together
        // and the comparison stayed equal. A guard that can only see a difference cannot see a
        // change that applies to everything.
        for item in &with.only_you_can_check {
            let line = with
                .requirements
                .iter()
                .find(|r| r.id == item.id)
                .unwrap_or_else(|| panic!("{} is on the list but not in the report", item.id));
            assert_eq!(
                line.status,
                Status::NotVerified,
                "{} is on the checklist and reads as {}: an instruction for how to check \
                 something is not the check",
                item.id,
                line.status.label()
            );
            assert!(
                line.checked_by.is_empty()
                    && line.documented_by.is_empty()
                    && line.attested_by.is_empty(),
                "{} is on the checklist and carries evidence",
                item.id
            );
        }
    }

    #[test]
    fn the_list_is_exactly_what_the_short_version_counts() {
        // The number at the top and the list below it come from one set. If they drifted, the
        // report would say "answer these 40" above a table of some other size.
        let (with, _) = report_with_and_without();
        assert_eq!(
            with.only_you_can_check.len() + with.no_instructions_yet,
            sv_report::bluf::only_a_person_can(&with),
            "the checklist and the short version disagree about how many there are"
        );
    }

    #[test]
    fn a_requirement_a_test_could_settle_is_not_on_it() {
        // V1.2.2 is applicable and unverified, and a test could settle it, so it belongs under
        // "tests worth writing" and not here. Listing it in both sends somebody to do it twice.
        let (with, _) = report_with_and_without();
        assert!(
            !with.only_you_can_check.iter().any(|i| i.id == "V1.2.2"),
            "{:?}",
            with.only_you_can_check
                .iter()
                .map(|i| &i.id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn each_row_says_what_to_do_and_how() {
        let (with, _) = report_with_and_without();
        for item in &with.only_you_can_check {
            assert!(
                !item.route.what_to_do().is_empty() && item.how.len() > 30,
                "{} does not say what to do: {:?}",
                item.id,
                item.how
            );
        }
        let md = sv_report::markdown::compliance(&with);
        assert!(md.contains("## What only you can check"), "{md}");
        assert!(sv_report::html::page(&with).contains("What only you can check"));
    }
}
