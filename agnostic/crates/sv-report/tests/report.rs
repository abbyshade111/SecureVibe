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
        frameworks,
        buckets,
        claims: &[],
        findings,
        verified,
        gaps: vec![],
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
        // The contested one is shown as needing attention, not as checked.
        let at = rendered.find("V1.2.1").expect("it is there");
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
    assert!(trace.why.contains("above the level"), "{}", trace.why);
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
    assert!(why.contains("above the level"), "{why}");
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
fn a_checklist_control_is_never_said_to_be_above_an_asvs_level() {
    // The checklist has no levels. `sv` derives one from whether a control is critical and what its
    // absence costs, so calling a control "above the ASVS level this app targets" attributes to
    // OWASP a judgement this tool made — and a reader has no way to tell which it is.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec![],
        not_applicable: vec![],
        not_assessed: vec![],
        out_of_level: vec!["SBD-AS-02".to_owned(), "V16.5.1".to_owned()],
    };
    let verified = vec![Verified::new(
        "app-tests",
        &["SBD-AS-02", "V16.5.1"],
        "a test".to_owned(),
    )];
    let report = build(inputs(&f, &buckets, vec![], &verified));

    assert_eq!(report.counts.out_of_level, 2);
    assert_eq!(
        report.counts.out_of_level_derived, 1,
        "only the checklist control's level is one `sv` worked out"
    );

    let why = &report.satisfied_elsewhere[0].why;
    assert!(
        !why.contains("ASVS level"),
        "a checklist control's level is not an ASVS level: {why}"
    );
    assert!(why.contains("derives"), "{why}");

    // And the rendered reports must not put it back.
    for rendered in [
        sv_report::markdown::compliance(&report),
        sv_report::html::page(&report),
    ] {
        assert!(
            !rendered.contains("Above ASVS level"),
            "the summary still attributes the level to ASVS"
        );
        assert!(
            rendered.contains("not OWASP's"),
            "the summary has to say whose judgement the derived level is"
        );
    }
}
