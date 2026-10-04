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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data")
}

fn frameworks() -> Frameworks {
    Frameworks::load(&data().join("frameworks")).expect("the OWASP data loads")
}

fn finding(rule_id: &str, requirement_ids: &[&str]) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        marked_test_code: false,
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
        set_aside: Vec::new(),
        reviews_not_counted: Vec::new(),
        app_name: "Test",
        target_level: 1,
        generated: None,
        made_by: Default::default(),
        run_note: None,
        run_steps: Vec::new(),
        test_output: None,
        run_status: None,
        coding_rules_cited: Default::default(),
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
        stated: &[],
        by_hand: &[],
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
fn a_finding_set_aside_as_a_false_alarm_never_leaves_its_requirement_checked() {
    // A rule saw something on the line and a person says it was wrong. That word takes the finding
    // off the list; it does not show the protection is there, so another check's clean run cannot
    // turn the requirement into "checked". An accepted risk is still a finding, and still counts.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into(), "V1.3.1".into()],
        ..Default::default()
    };
    let passed = vec![Verified::new(
        "config.something",
        &["V1.2.1", "V1.3.1"],
        "the files this check reads".to_owned(),
    )];
    let set_aside = |verdict: &str, id: &str| sv_check::review::SetAside {
        finding: finding("ast.sql", &[id]),
        verdict: verdict.to_owned(),
        why: "looked at it".to_owned(),
        by: "owner".to_owned(),
        on: "2026-09-27".to_owned(),
        sealed: sv_check::seal::Sealed::Here,
    };
    let mut i = inputs(&f, &buckets, vec![], &passed);
    i.set_aside = vec![set_aside(sv_check::review::FALSE_ALARM, "V1.2.1")];
    let report = build(i);
    let status = |id: &str| {
        report
            .requirements
            .iter()
            .find(|r| r.id == id)
            .unwrap()
            .status
    };
    assert_eq!(status("V1.2.1"), Status::NotVerified);
    // The control: the same clean run still checks a requirement nothing was set aside for.
    assert_eq!(status("V1.3.1"), Status::Checked);
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
fn each_chapter_counts_what_applies_and_what_does_not_in_its_own_columns() {
    // The end-to-end test holds the sums on the Flask example. This one holds each count in the
    // chapter it belongs to, on a report small enough that every number is known: a sum can come
    // out right with two chapters' counts swapped, and this cannot.
    let f = frameworks();
    let excluded = |id: &str| NotApplicable {
        id: id.into(),
        reason: "ruled out for the test".into(),
        condition: Condition::Auth,
        source: Source::Claim,
    };
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into(), "V1.2.4".into(), "V2.2.2".into()],
        not_applicable: vec![excluded("V1.3.1"), excluded("V2.1.1")],
        not_assessed: vec![NotAssessed {
            id: "V16.5.1".into(),
            blocked_on: vec![Condition::Auth],
        }],
        out_of_level: vec![],
    };
    let verified = [Verified::new("some.check", &["V1.2.1"], "8 files".into())];
    // The AI coding tool's yes about V2.2.2: its own column, below the owner's word, never checked.
    let stated = [Verified::new(
        "design.stated-by-ai",
        &["V2.2.2"],
        "securevibe.toml: your AI coding tool answered yes.".to_owned(),
    )];
    let mut given = inputs(&f, &buckets, vec![], &verified);
    given.stated = &stated;
    let report = build(given);
    // Setup, asserted: each requirement landed where this test put it, and knows its chapter.
    assert_eq!(
        (
            report.counts.applicable,
            report.counts.checked,
            report.counts.stated,
            report.counts.not_applicable,
            report.counts.not_assessed
        ),
        (3, 1, 1, 2, 1)
    );
    assert!(report.excluded.iter().all(|e| !e.chapter.is_empty()));
    assert!(report.undecided.iter().all(|u| !u.chapter.is_empty()));

    let chapters = sv_report::chapters::by_chapter(&report);
    let keys: Vec<&str> = chapters.iter().map(|c| c.key.as_str()).collect();
    assert_eq!(keys, ["V1", "V2", "V16"], "by number, not by spelling");
    let counts = |c: &sv_report::chapters::Chapter| {
        (
            c.applies(),
            c.checked,
            c.your_word,
            c.tool_word,
            c.not_verified,
            c.does_not_apply,
            c.not_placed,
        )
    };
    assert_eq!(counts(&chapters[0]), (2, 1, 0, 0, 1, 1, 0), "V1");
    assert_eq!(counts(&chapters[1]), (1, 0, 0, 1, 0, 1, 0), "V2");
    assert_eq!(counts(&chapters[2]), (0, 0, 0, 0, 0, 0, 1), "V16");

    let page = sv_report::markdown::compliance(&report);
    let v1 = chapters[0].title();
    // Apply, a problem found, checked, the AI tool's word, not verified, does not apply, not placed
    // yet. The owner's-word column is not drawn: nobody here gave theirs.
    assert!(
        page.contains("| checked | your AI tool's word | not verified |"),
        "{page}"
    );
    assert!(!page.contains("your word, not a check"), "{page}");
    assert!(
        page.contains(&format!("| {v1} | **2** | 0 | 1 | 0 | 1 | 1 | 0 |")),
        "{page}"
    );
    let v2 = chapters[1].title();
    assert!(
        page.contains(&format!("| {v2} | **1** | 0 | 0 | 1 | 0 | 1 | 0 |")),
        "{page}"
    );
    assert!(
        page.contains(&format!("### {v1} — **2 apply**, 1 do not")),
        "{page}"
    );
    // V16 has a row in the table and no list: nothing in it applies.
    assert!(
        page.contains(&format!("| {} |", chapters[2].title())),
        "{page}"
    );
    assert!(
        !page.contains(&format!("### {}", chapters[2].title())),
        "{page}"
    );
    // Every requirement that applies has its words in the appendix, and the chapter lists do not.
    // (The tests worth writing still show a level 1 requirement's words beside it, on purpose.)
    let appendix = &page[page
        .find("## Appendix: what each requirement asks for")
        .expect("the appendix")..];
    let lists = &page[page.find("## Requirements that apply").unwrap()..];
    let lists = &lists[..lists[3..].find("\n## ").map_or(lists.len(), |i| i + 3)];
    for line in &report.requirements {
        let words: String = line.description.chars().take(30).collect();
        assert!(
            appendix.contains(&format!("| {} | {words}", line.id)),
            "{appendix}"
        );
        assert!(
            !lists.contains(&words),
            "{}'s words are in the chapter lists",
            line.id
        );
    }
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
        set_aside: Vec::new(),
        reviews_not_counted: Vec::new(),
        app_name: "Chain",
        target_level: 3,
        generated: None,
        made_by: Default::default(),
        run_note: None,
        run_steps: Vec::new(),
        test_output: None,
        run_status: None,
        coding_rules_cited: Default::default(),
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
        stated: &[],
        by_hand: &[],
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

    fn tool_said_yes(id: &str) -> Verified {
        Verified::new(
            "design.stated-by-ai",
            &[id],
            "securevibe.toml: your AI coding tool answered yes. This is the word of the tool that \
             wrote the code, not a check of it."
                .to_owned(),
        )
    }

    fn report_with_stated(stated: &[Verified], attested: &[Verified]) -> Report {
        let f = Frameworks::load(&data().join("frameworks")).unwrap();
        let buckets = Buckets {
            applicable: vec!["V8.3.1".into(), "V2.2.2".into()],
            ..Default::default()
        };
        let mut inputs = inputs(&f, &buckets, vec![], &[]);
        inputs.attested = attested;
        inputs.stated = stated;
        build(inputs)
    }

    #[test]
    fn the_chapter_table_keeps_the_owners_word_and_the_tools_word_apart_from_checked() {
        // The Flask example has neither, so the end-to-end test never sees these two columns. Each
        // is its own column and neither is ever counted as checked: the owner's yes and the AI
        // tool's yes are words, not checks, and at different ranks.
        let report = report_with_stated(&[tool_said_yes("V8.3.1")], &[said_yes("V2.2.2")]);
        assert_eq!(status_of(&report, "V8.3.1"), Status::Stated);
        assert_eq!(status_of(&report, "V2.2.2"), Status::Attested);
        let chapters = sv_report::chapters::by_chapter(&report);
        let v8 = chapters
            .iter()
            .find(|c| c.key == "V8")
            .expect("a V8 chapter");
        let v2 = chapters
            .iter()
            .find(|c| c.key == "V2")
            .expect("a V2 chapter");
        assert_eq!((v8.tool_word, v8.your_word, v8.checked), (1, 0, 0));
        assert_eq!((v2.your_word, v2.tool_word, v2.checked), (1, 0, 0));
        let page = sv_report::markdown::compliance(&report);
        assert!(page.contains("| your word, not a check |"), "{page}");
        assert!(page.contains("| your AI tool's word |"), "{page}");
        // With neither, neither column is drawn: a column of zeros is noise.
        let plain = sv_report::markdown::compliance(&report_with_stated(&[], &[]));
        assert!(plain.contains("| chapter | apply |"), "the table is drawn");
        assert!(!plain.contains("your word, not a check"), "{plain}");
        assert!(!plain.contains("your AI tool's word"), "{plain}");
    }

    #[test]
    fn the_ai_tools_yes_is_its_own_tier_below_the_owners() {
        let report = report_with_stated(&[tool_said_yes("V8.3.1")], &[]);
        assert_eq!(status_of(&report, "V8.3.1"), Status::Stated);
        assert_eq!(report.counts.stated, 1);
        assert_eq!(
            report.counts.attested, 0,
            "the tool's word is not the owner's"
        );
        assert!(Status::Stated < Status::Attested && Status::NotVerified < Status::Stated);
        // Both answering: the owner's word is the stronger one and is what the row shows.
        let both = report_with_stated(&[tool_said_yes("V8.3.1")], &[said_yes("V8.3.1")]);
        assert_eq!(status_of(&both, "V8.3.1"), Status::Attested);
    }

    #[test]
    fn a_requirement_the_ai_tool_answered_is_still_a_test_to_write() {
        let report = report_with_stated(&[tool_said_yes("V8.3.1")], &[]);
        assert!(
            report.tests_to_write.iter().any(|t| t.id == "V8.3.1"),
            "{:?}",
            report.tests_to_write
        );
    }

    fn checked_by_hand(id: &str) -> Verified {
        Verified::new(
            "hand.checked",
            &[id],
            "securevibe.toml: checked by hand by you on 2026-09-26: \"The padlock shows a trusted \
             certificate.\" Nothing here repeated it."
                .to_owned(),
        )
    }

    fn report_by_hand(
        by_hand: &[Verified],
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
        inputs.by_hand = by_hand;
        inputs.attested = attested;
        inputs.documented = documented;
        build(inputs)
    }

    #[test]
    fn a_check_by_hand_ranks_just_above_the_owners_answer_and_below_a_document() {
        let hand = [checked_by_hand("V8.3.1")];
        let report = report_by_hand(&hand, &[said_yes("V8.3.1")], &[], &[]);
        assert_eq!(status_of(&report, "V8.3.1"), Status::ByHand);
        assert_eq!(report.counts.by_hand, 1);
        assert_eq!(
            report.counts.checked, 0,
            "never checked: nothing automated looked"
        );
        assert!(Status::Attested < Status::ByHand && Status::ByHand < Status::Documented);
        let documented = report_by_hand(&hand, &[], &[said_yes("V8.3.1")], &[]);
        assert_eq!(status_of(&documented, "V8.3.1"), Status::Documented);
        // An automated check, or a finding, always wins over what somebody saw.
        let checked = report_by_hand(
            &hand,
            &[],
            &[],
            &[Verified::new("some.check", &["V8.3.1"], "8 files".into())],
        );
        assert_eq!(status_of(&checked, "V8.3.1"), Status::Checked);
    }

    #[test]
    fn a_check_by_hand_is_still_a_test_to_write_and_shows_what_was_seen() {
        let report = report_by_hand(&[checked_by_hand("V8.3.1")], &[], &[], &[]);
        assert!(report.tests_to_write.iter().any(|t| t.id == "V8.3.1"));
        let markdown = sv_report::markdown::compliance(&report);
        let row = markdown
            .lines()
            .find(|l| l.starts_with("| V8.3.1"))
            .unwrap_or_else(|| panic!("no row for V8.3.1 in:\n{markdown}"));
        assert!(
            row.contains("checked by hand by the owner") && row.contains("The padlock shows"),
            "{row}"
        );
        assert!(sv_report::html::page(&report).contains("checked by hand by the owner"));
    }

    #[test]
    fn the_row_says_it_is_the_ai_tools_word_rather_than_a_check() {
        let report = report_with_stated(&[tool_said_yes("V8.3.1")], &[]);
        let markdown = sv_report::markdown::compliance(&report);
        let row = markdown
            .lines()
            .find(|l| l.starts_with("| V8.3.1"))
            .unwrap_or_else(|| panic!("no row for V8.3.1 in:\n{markdown}"));
        let status = row.split('|').nth(2).unwrap_or_default();
        assert!(status.contains("stated by the AI coding tool"), "got {row}");
        assert!(
            status.contains("your AI coding tool's word")
                && !status.contains("attested by the owner"),
            "{status}"
        );
        let html = sv_report::html::page(&report);
        assert!(html.contains("stated by the AI coding tool"));
        assert!(
            !html.contains("attested by the owner"),
            "nothing here is the owner's word"
        );
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

    /// The questions the AI coding tool is given to ask the owner.
    fn interview_report(stated: &[Verified], attested: &[Verified]) -> sv_report::Report {
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec![
                "V6.1.1".into(),
                "V12.2.2".into(),
                "V8.3.1".into(),
                "V2.2.2".into(),
            ],
            ..Default::default()
        };
        let (notes, design, human) = catalogs();
        let mut i = inputs(&f, &buckets, vec![], &[]);
        i.human = Some((&notes, &design, &human));
        i.stated = stated;
        i.attested = attested;
        build(i)
    }

    fn by(check: &str, id: &str) -> Verified {
        Verified::new(check, &[id], "securevibe.toml".to_owned())
    }

    #[test]
    fn every_open_question_is_given_to_the_tool_and_none_the_owner_answered() {
        let report = interview_report(
            &[by("design.stated-by-ai", "V2.2.2")],
            &[by("design.attested", "V8.3.1")],
        );
        let asked: Vec<&str> = report
            .questions_for_you
            .iter()
            .map(|i| i.id.as_str())
            .collect();
        // All three routes, and a design question a test could also settle: the interview is wider
        // than the checklist, which leaves those out.
        assert!(asked.contains(&"V6.1.1"), "a written decision: {asked:?}");
        assert!(asked.contains(&"V12.2.2"), "a check by hand: {asked:?}");
        assert!(
            asked.contains(&"V2.2.2"),
            "only the tool has answered this, so the owner is asked to confirm: {asked:?}"
        );
        assert!(
            !asked.contains(&"V8.3.1"),
            "the owner has answered this; asking again is noise: {asked:?}"
        );
        // Nor a check the owner made by hand and recorded, while it is current.
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec!["V12.2.2".into()],
            ..Default::default()
        };
        let (notes, design, human) = catalogs();
        let hand = [Verified::new("hand.checked", &["V12.2.2"], "seen".into())];
        let mut i = inputs(&f, &buckets, vec![], &[]);
        i.human = Some((&notes, &design, &human));
        i.by_hand = &hand;
        let checked = build(i);
        assert!(
            !checked.questions_for_you.iter().any(|q| q.id == "V12.2.2"),
            "{:?}",
            checked.questions_for_you
        );
        let text = sv_report::interview::text(&report);
        assert!(
            text.contains("Only you, the AI coding tool, have answered this so far"),
            "{text}"
        );
    }

    #[test]
    fn the_questions_most_at_stake_come_first() {
        // The person may stop at any point, and on the Flask example there were fifty-five
        // questions, in the order the catalogs happened to list them.
        let f = frameworks();
        let (notes, design, human) = catalogs();
        let every: Vec<String> = notes
            .sections
            .iter()
            .map(|s| s.id.clone())
            .chain(design.questions.iter().map(|q| q.id.clone()))
            .chain(human.checks.iter().map(|c| c.id.clone()))
            .filter(|id| f.get(id).is_some())
            .collect();
        let level = |id: &str| f.get(id).map_or(0, |r| r.level);
        // Two level-1 design questions, the first of them answered by the tool alone, so it has
        // to move behind the second.
        let ones: Vec<&str> = design
            .questions
            .iter()
            .map(|q| q.id.as_str())
            .filter(|id| level(id) == 1)
            .collect();
        assert!(
            ones.len() >= 2,
            "the setup needs two level-1 design questions"
        );
        let buckets = Buckets {
            applicable: every.clone(),
            ..Default::default()
        };
        let stated = [Verified::new(
            "design.stated-by-ai",
            &[ones[0]],
            "securevibe.toml".to_owned(),
        )];
        let mut i = inputs(&f, &buckets, vec![], &[]);
        i.human = Some((&notes, &design, &human));
        i.stated = &stated;
        let report = build(i);
        let asked: Vec<&str> = report
            .questions_for_you
            .iter()
            .map(|q| q.id.as_str())
            .collect();
        let first: Vec<bool> = asked.iter().map(|id| level(id) == 1).collect();
        assert!(
            first.contains(&true) && first.contains(&false),
            "the setup must hold level-1 questions and others to show an order: {asked:?}"
        );
        assert!(
            first.windows(2).all(|w| w[0] || !w[1]),
            "every level-1 question comes before every other one: {asked:?}"
        );
        let at = |id: &str| asked.iter().position(|a| *a == id).unwrap();
        assert!(
            at(ones[0]) > at(ones[1]),
            "a question only the tool has answered comes after an unanswered one at its level"
        );
    }

    #[test]
    fn asking_credits_nothing() {
        // Writing the questions down is not an answer to any of them.
        let with = interview_report(&[], &[]);
        assert!(!with.questions_for_you.is_empty());
        for item in &with.questions_for_you {
            let line = with.requirements.iter().find(|r| r.id == item.id).unwrap();
            assert_eq!(line.status, Status::NotVerified, "{} moved", item.id);
        }
    }

    #[test]
    fn with_nothing_left_to_ask_the_tool_is_told_so_and_not_that_the_app_is_fine() {
        let f = frameworks();
        let buckets = Buckets::default();
        let (notes, design, human) = catalogs();
        let mut i = inputs(&f, &buckets, vec![], &[]);
        i.human = Some((&notes, &design, &human));
        let text = sv_report::interview::text(&build(i));
        assert!(
            text.contains("0 to ask") && text.contains("does not make the answers right"),
            "{text}"
        );
        assert!(!text.contains("How to ask them"), "{text}");
    }

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
    fn report_json_names_the_checks_only_you_can_make_by_id_and_loses_none() {
        // report.json keeps these as ids into questions_for_you, never the entries twice. Built
        // from the real catalogs, so the list is what an owner would get, not a hand-made one.
        let (with, _) = report_with_and_without();
        assert!(
            !with.only_you_can_check.is_empty(),
            "and the list is not empty, or this proves nothing"
        );
        let json = sv_report::json::to_value(&with);
        assert!(json.get("only_you_can_check").is_none(), "written twice");
        let ids: Vec<&str> = json["only_you_can_check_ids"]
            .as_array()
            .expect("the ids are in report.json")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let want: Vec<&str> = with
            .only_you_can_check
            .iter()
            .map(|i| i.id.as_str())
            .collect();
        assert_eq!(ids, want, "every one, in the list's own order");
        for item in &with.only_you_can_check {
            let asked = json["questions_for_you"]
                .as_array()
                .unwrap()
                .iter()
                .find(|q| q["id"] == item.id.as_str())
                .unwrap_or_else(|| panic!("{} is not among the questions", item.id));
            assert_eq!(*asked, serde_json::to_value(item).unwrap(), "{}", item.id);
        }
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
        let html = sv_report::html::page(&with);
        assert!(html.contains("What only you can check"));
        // And the where-to-look line is printed, not merely carried. V6.1.1 comes from the security
        // notes, whose question says what to write down; the line that says where to find it out is
        // the half a reader who does not already know needs.
        assert!(
            md.contains("Where to look:") && html.contains("Where to look:"),
            "the where-to-look lines never reach the page"
        );
    }
}

#[test]
fn a_failing_suite_shows_its_last_lines_in_every_format() {
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into()],
        ..Default::default()
    };
    let mut i = inputs(&f, &buckets, vec![], &[]);
    i.test_output = Some(sv_check::suite::FailingOutput {
        exit_code: 1,
        // Markup, and a fence of its own, which must reach the reader as text.
        text: "<script>x</script>\n```\nnot ok 3 - refuses a stranger".to_owned(),
        lines_kept: 3,
        lines_total: 212,
        redacted: 1,
        stopped_after: None,
    });
    let report = build(i);
    let html = sv_report::html::page(&report);
    let compliance = sv_report::markdown::compliance(&report);
    for rendered in [&html, &compliance] {
        assert!(
            rendered.contains("The app's own tests failed when `sv` ran them (exit 1)")
                || rendered.contains("The app&#39;s own tests failed")
                || rendered.contains("The app&#x27;s own tests failed"),
            "{rendered}"
        );
        assert!(rendered.contains("last 3 of the 212 lines"), "{rendered}");
        assert!(rendered.contains("One value that looked like a credential is cut short."));
        assert!(rendered.contains("not ok 3 - refuses a stranger"));
    }
    assert!(
        html.contains("<pre>&lt;script&gt;x&lt;/script&gt;"),
        "{html}"
    );
    assert!(!html.contains("<script>x</script>"));
    // The output's own three backticks do not close the block around it.
    assert!(
        compliance.contains("````text\n<script>x</script>\n```\nnot ok 3"),
        "{compliance}"
    );
    // And in the JSON, for a tool reading the report.
    let json = serde_json::to_value(&report).expect("serializes");
    assert_eq!(json["test_output"]["lines_total"], 212);
}

#[test]
fn a_passing_or_unrun_suite_adds_nothing_to_the_pages() {
    let f = frameworks();
    let buckets = Buckets::default();
    let report = build(inputs(&f, &buckets, vec![], &[]));
    assert!(!sv_report::markdown::compliance(&report).contains("own tests failed"));
    assert!(!sv_report::html::page(&report).contains("own tests failed"));
}

fn failing(
    text: &str,
    lines_kept: usize,
    lines_total: usize,
    redacted: usize,
) -> sv_check::suite::FailingOutput {
    sv_check::suite::FailingOutput {
        exit_code: 1,
        text: text.to_owned(),
        lines_kept,
        lines_total,
        redacted,
        stopped_after: None,
    }
}

#[test]
fn the_sentence_before_the_output_says_how_much_of_it_there_is() {
    let intro = |t| sv_report::test_output_intro(&t);
    assert!(intro(failing("", 0, 0, 0)).ends_with("It printed nothing."));
    assert!(intro(failing("a\nb", 2, 2, 0)).ends_with("This is everything it printed (2 lines)."));
    assert!(intro(failing("a", 1, 1, 0)).ends_with("(1 line)."));
    assert!(intro(failing("x", 30, 90, 0)).contains("the last 30 of the 90 lines"));
    assert!(
        intro(failing("x", 1, 1, 1))
            .ends_with("One value that looked like a credential is cut short.")
    );
    assert!(
        intro(failing("x", 1, 1, 3))
            .ends_with("3 values that looked like credentials are cut short.")
    );
}

#[test]
fn the_output_is_text_in_both_pages_whatever_it_holds() {
    let f = frameworks();
    let buckets = Buckets::default();
    let mut i = inputs(&f, &buckets, vec![], &[]);
    i.test_output = Some(failing("expected a < b && c\n````\ndone", 3, 3, 0));
    let report = build(i);
    let html = sv_report::html::page(&report);
    assert!(
        html.contains("<pre>expected a &lt; b &amp;&amp; c"),
        "{html}"
    );
    let compliance = sv_report::markdown::compliance(&report);
    assert!(
        compliance.contains("`````text\nexpected a < b && c\n````\ndone\n`````"),
        "{compliance}"
    );
}

#[test]
fn whether_the_app_was_started_is_one_plain_line() {
    use sv_report::RunStatus;
    let started = |asked, signed_in, tests: &str| RunStatus::Started {
        image: "python:3.12-slim".into(),
        asked,
        answered: 27,
        signed_in,
        tests: tests.into(),
    };
    assert_eq!(
        started(29, true, "passed").line(),
        "The app was started with python:3.12-slim and answered 27 of the 29 requests sent to it \
         without signing in, and was then asked more as test users signed in to it. Its own tests \
         passed."
    );
    let line = started(1, false, "failed").line();
    assert!(
        line.contains("27 of the 1 request sent to it without signing in."),
        "{line}"
    );
    assert!(line.ends_with("Its own tests failed; the report shows the last lines they printed."));
    assert!(
        started(29, false, "not-declared")
            .line()
            .ends_with("so its own tests were not run.")
    );
    assert_eq!(
        RunStatus::CouldNotStart {
            why: "No container backend.".into()
        }
        .line(),
        "--run was given, and the app could not be started. No container backend."
    );
    assert_eq!(
        RunStatus::NotAsked {
            why: "Pass --run.".into()
        }
        .line(),
        "The app was not started. Pass --run."
    );
    // The same fact for a tool reading report.json, by name rather than by sentence.
    let json = serde_json::to_value(started(29, true, "passed")).unwrap();
    assert_eq!(json["state"], "started");
    assert_eq!(
        (json["asked"].as_u64(), json["answered"].as_u64()),
        (Some(29), Some(27))
    );
    assert_eq!(
        serde_json::to_value(RunStatus::NotAsked { why: String::new() }).unwrap()["state"],
        "not-asked"
    );
}

#[test]
fn a_suite_that_exited_zero_passed() {
    assert_eq!(sv_report::RunStatus::tests_state(Some(0)), "passed");
    assert_eq!(sv_report::RunStatus::tests_state(None), "not-declared");
}

#[test]
fn a_suite_that_exited_otherwise_failed() {
    for code in [1, 2, 127, -1] {
        assert_eq!(
            sv_report::RunStatus::tests_state(Some(code)),
            "failed",
            "{code}"
        );
    }
}

#[test]
fn the_line_follows_the_suite_exit_code() {
    use sv_report::RunStatus;
    let line = |exit| {
        RunStatus::Started {
            image: "node:22-alpine".into(),
            asked: 3,
            answered: 3,
            signed_in: false,
            tests: RunStatus::tests_state(exit).into(),
        }
        .line()
    };
    assert!(
        line(Some(0)).ends_with("Its own tests passed."),
        "{}",
        line(Some(0))
    );
    assert!(
        line(Some(1)).contains("Its own tests failed"),
        "{}",
        line(Some(1))
    );
    assert!(
        line(None).contains("declares no test command"),
        "{}",
        line(None)
    );
}

#[test]
fn the_signed_in_questions_are_mentioned_only_when_they_were_asked() {
    use sv_report::RunStatus;
    let line = |signed_in| {
        RunStatus::Started {
            image: "node:22-alpine".into(),
            asked: 3,
            answered: 2,
            signed_in,
            tests: "passed".into(),
        }
        .line()
    };
    assert!(line(true).contains("as test users signed in to it"));
    assert!(!line(false).contains("signed in to it"), "{}", line(false));
    assert!(line(false).contains("answered 2 of the 3 requests sent to it without signing in."));
}

/// OWASP AISVS Appendix C, apart from the app's own requirements.
mod appendix_c {
    use super::*;

    fn report_with(findings: Vec<Finding>) -> sv_report::Report {
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec![
                "V1.2.1".into(),
                "AC.4.1".into(),
                "AC.3.1".into(),
                "AC.12.5".into(),
                "AC.8.1".into(),
            ],
            not_applicable: vec![NotApplicable {
                id: "AC.9.1".into(),
                reason: "no deployment pipeline".into(),
                condition: Condition::from_name("ci-cd").unwrap(),
                source: Source::Claim,
            }],
            ..Default::default()
        };
        let notes = sv_check::notes::Catalog::load(&data().join("security-notes.json")).unwrap();
        let design =
            sv_check::design::Questions::load(&data().join("design-questions.json")).unwrap();
        let human = sv_check::human::HumanChecks::load(&data().join("human-checks.json")).unwrap();
        let mut i = inputs(&f, &buckets, findings, &[]);
        i.human = Some((&notes, &design, &human));
        // AC.4.1 is both: a rule cites it, and it is among the owner's questions.
        i.coding_rules_cited = [
            "AC.3.1".to_owned(),
            "AC.8.1".to_owned(),
            "AC.4.1".to_owned(),
        ]
        .into();
        build(i)
    }

    fn route(report: &sv_report::Report, id: &str) -> &'static str {
        report
            .ai_process
            .lines
            .iter()
            .find(|l| l.id == id)
            .unwrap_or_else(|| panic!("{id} is not in the section"))
            .route
    }

    #[test]
    fn appendix_c_nothing_reached_leaves_the_counts_for_its_own_section() {
        let report = report_with(vec![]);
        let ids: Vec<&str> = report.requirements.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["V1.2.1"], "only the app's own requirement stays");
        assert_eq!(report.counts.applicable, 1);
        assert_eq!(report.counts.not_verified, 1);
        assert_eq!(report.counts.ai_process, 4);
        assert_eq!(report.ai_process.lines.len(), 4);
        assert_eq!(report.ai_process.not_applicable, 1);
    }

    #[test]
    fn each_is_listed_by_what_happens_to_it() {
        let report = report_with(vec![]);
        // A question for the owner outranks a rule: the owner's answer is what would settle it.
        assert_eq!(route(&report, "AC.4.1"), "your-decision");
        assert_eq!(route(&report, "AC.3.1"), "rules-given");
        assert_eq!(route(&report, "AC.8.1"), "rules-given");
        assert_eq!(route(&report, "AC.12.5"), "nothing-reaches-it");
        // Still asked: moving it out of the counts does not take it out of the questions.
        assert!(report.questions_for_you.iter().any(|q| q.id == "AC.4.1"));
    }

    #[test]
    fn one_with_a_finding_stays_among_the_apps_requirements() {
        let report = report_with(vec![finding("agent.merged-its-own-work", &["AC.8.1"])]);
        let line = report
            .requirements
            .iter()
            .find(|r| r.id == "AC.8.1")
            .expect("a finding keeps it in the counts");
        assert_eq!(line.status, Status::NeedsAttention);
        assert!(!report.ai_process.lines.iter().any(|l| l.id == "AC.8.1"));
        assert_eq!(report.counts.applicable, 2);
        assert_eq!(report.counts.ai_process, 3);
    }

    #[test]
    fn the_section_says_the_rules_are_not_evidence_in_every_format() {
        let report = report_with(vec![]);
        let summary = report.ai_process.summary();
        assert!(summary.contains("not evidence"), "{summary}");
        assert!(summary.contains("1 is your decision"), "{summary}");
        assert!(
            summary.contains("Nothing in `sv` reaches the other 1"),
            "{summary}"
        );
        assert!(summary.contains("1 more does not apply"), "{summary}");
        let html = sv_report::html::page(&report);
        let compliance = sv_report::markdown::compliance(&report);
        for rendered in [&html, &compliance] {
            assert!(rendered.contains("How the app is built with AI (OWASP AISVS Appendix C)"));
            assert!(
                rendered.contains("A further 4 about how the app is built"),
                "headline"
            );
            for id in ["AC.4.1", "AC.3.1", "AC.12.5", "AC.8.1"] {
                assert!(rendered.contains(id), "{id} must still be listed");
            }
        }
        // And for a tool reading report.json.
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["ai_process"]["lines"].as_array().unwrap().len(), 4);
        assert_eq!(json["counts"]["ai_process"], 4);
    }

    #[test]
    fn with_no_appendix_c_there_is_no_section() {
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec!["V1.2.1".into()],
            ..Default::default()
        };
        let report = build(inputs(&f, &buckets, vec![], &[]));
        assert!(report.ai_process.lines.is_empty());
        assert!(!sv_report::markdown::compliance(&report).contains("How the app is built with AI"));
        assert!(!sv_report::html::page(&report).contains("How the app is built with AI"));
    }
}

#[test]
fn findings_in_test_code_are_listed_after_the_apps_own_and_still_count() {
    // On `sv`'s own code, three findings in four were in its tests. They are listed apart, after
    // the app's own, in every report; they are never dropped, and a requirement only a test-code
    // finding is about still needs attention.
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into(), "V1.3.1".into()],
        ..Default::default()
    };
    let mut in_app = finding("ast.app", &["V1.3.1"]);
    in_app.title = "Found in the app".into();
    in_app.severity = Severity::Low;
    let mut by_path = finding("ast.path", &["V1.2.1"]);
    by_path.title = "Found in a test file".into();
    by_path.severity = Severity::Critical;
    by_path.location.file = "tests/test_app.py".into();
    let mut by_module = finding("ast.module", &["V1.2.1"]);
    by_module.title = "Found in a Rust test module".into();
    by_module.location.file = "src/lib.rs".into();
    by_module.marked_test_code = true;
    let report = build(inputs(&f, &buckets, vec![by_path, in_app, by_module], &[]));

    let status = |id: &str| {
        report
            .requirements
            .iter()
            .find(|r| r.id == id)
            .unwrap()
            .status
    };
    assert_eq!(
        status("V1.2.1"),
        Status::NeedsAttention,
        "test code still counts"
    );
    assert_eq!(status("V1.3.1"), Status::NeedsAttention);

    let (app, tests) = sv_report::app_then_tests(&report);
    assert_eq!(app.len(), 1);
    assert_eq!(tests.len(), 2);

    let markdown = sv_report::markdown::security(&report);
    let html = sv_report::html::page(&report);
    for (name, page, fix, apart) in [
        (
            "markdown",
            &markdown,
            "## 1 thing to fix",
            "## 2 in test or sample code",
        ),
        (
            "html",
            &html,
            "<h2>1 thing to fix</h2>",
            "<h2>2 in test or sample code</h2>",
        ),
    ] {
        // Read from the list on: the short version above it names the worst findings too.
        let list = &page[page
            .find(fix)
            .unwrap_or_else(|| panic!("{name} has {fix:?}"))..];
        let at = |needle: &str| {
            list.find(needle)
                .unwrap_or_else(|| panic!("{name} has {needle:?}"))
        };
        assert!(at(fix) < at("Found in the app"), "{name}");
        assert!(
            at("Found in the app") < at(apart),
            "{name}: the app's own first"
        );
        assert!(at(apart) < at("Found in a test file"), "{name}");
        assert!(at(apart) < at("Found in a Rust test module"), "{name}");
    }

    // The short version names the app's own first, even below a critical in a test, and says how
    // many are in test code.
    let (worst, _) = sv_report::bluf::worst_findings(&report);
    assert_eq!(worst[0].title, "Found in the app");
    let headline = sv_report::bluf::headline(&report);
    assert!(
        headline.contains("2 of them are in test or sample code"),
        "{headline}"
    );
}

#[test]
fn when_every_finding_is_in_test_code_the_report_does_not_read_as_clean() {
    let f = frameworks();
    let buckets = Buckets {
        applicable: vec!["V1.2.1".into()],
        ..Default::default()
    };
    let mut only = finding("ast.path", &["V1.2.1"]);
    only.location.file = "tests/test_app.py".into();
    let report = build(inputs(&f, &buckets, vec![only], &[]));
    let markdown = sv_report::markdown::security(&report);
    assert!(
        markdown.contains("## Nothing was found in the app itself"),
        "{markdown}"
    );
    assert!(
        markdown.contains("not that the app is secure"),
        "{markdown}"
    );
    assert!(
        markdown.contains("## 1 in test or sample code"),
        "{markdown}"
    );
    assert!(!markdown.contains("## Nothing was found\n"), "{markdown}");
    assert!(
        sv_report::bluf::headline(&report).contains("It is in test or sample code"),
        "{}",
        sv_report::bluf::headline(&report)
    );
}

/// False alarms, part 3: each one a report against the rule.
mod false_alarm_reports {
    use super::*;

    fn form() -> String {
        std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../.github/ISSUE_TEMPLATE/false_alarm.yml"),
        )
        .expect("the issue form is in the repository")
    }

    /// The field names a link fills in, other than `template` and the issue's own `title`.
    fn filled(url: &str) -> Vec<String> {
        url.split_once('?')
            .unwrap()
            .1
            .split('&')
            .filter_map(|p| p.split_once('=').map(|(k, _)| k.to_owned()))
            .filter(|k| k != "template" && k != "title")
            .collect()
    }

    #[test]
    fn the_link_fills_in_the_rule_and_nothing_of_the_owners() {
        let url = sv_report::false_alarm_issue_url(
            "ast.sql-built-by-hand",
            "SQL built by hand & run as \"text\" #1",
        );
        assert!(url.starts_with(sv_report::FALSE_ALARM_FORM), "{url}");
        assert!(url.contains("&rule=ast.sql-built-by-hand"), "{url}");
        assert!(
            url.contains("&title=False%20alarm%3A%20ast.sql-built-by-hand"),
            "{url}"
        );
        // Characters that would end or break a query string are encoded.
        assert!(url.contains("%26%20run%20as%20%22text%22%20%231"), "{url}");
        assert_eq!(url.matches('#').count(), 0, "{url}");
        assert_eq!(filled(&url), ["rule", "finding"]);
    }

    #[test]
    fn every_field_the_link_fills_is_a_field_of_the_form() {
        // GitHub fills a form's field from the address only when the names match its `id`s; a field
        // renamed in one place and not the other would quietly arrive empty.
        let form = form();
        for field in filled(&sv_report::false_alarm_issue_url("r", "t")) {
            assert!(
                form.contains(&format!("id: {field}\n")),
                "the form has no field `{field}`"
            );
        }
        let (_, template) = sv_report::FALSE_ALARM_FORM.split_once("template=").unwrap();
        assert!(template.ends_with(".yml"));
        // What the rule will be narrowed from is required, in words; the code is asked for only
        // behind a choice the reporter makes, and a key is never to be pasted.
        for needed in [
            "id: matched",
            "id: why",
            "id: show-code",
            "Never paste a real key",
            "only if you choose",
        ] {
            assert!(form.contains(needed), "the form lacks {needed:?}");
        }
    }

    fn report_with_a_false_alarm(path: &str) -> sv_report::Report {
        let f = frameworks();
        let buckets = Buckets {
            applicable: vec!["V1.2.1".into()],
            ..Default::default()
        };
        let mut flagged = finding("ast.sql-built-by-hand", &["V1.2.1"]);
        flagged.location.file = path.to_owned();
        let mut i = inputs(&f, &buckets, vec![], &[]);
        i.set_aside = vec![
            sv_check::review::SetAside {
                finding: flagged.clone(),
                verdict: sv_check::review::FALSE_ALARM.to_owned(),
                why: "the id is an integer from the route, internal detail".to_owned(),
                by: "owner".to_owned(),
                on: "2026-09-27".to_owned(),
                sealed: sv_check::seal::Sealed::Here,
            },
            sv_check::review::SetAside {
                finding: finding("ast.weak-hash-function", &["V1.2.1"]),
                verdict: sv_check::review::ACCEPTED_RISK.to_owned(),
                why: "a real problem, for now".to_owned(),
                by: "owner".to_owned(),
                on: "2026-09-27".to_owned(),
                sealed: sv_check::seal::Sealed::Here,
            },
        ];
        build(i)
    }

    #[test]
    fn each_false_alarm_in_the_report_links_to_a_report_against_its_rule() {
        let report = report_with_a_false_alarm("secret-project/billing.py");
        let entries = sv_report::false_alarm_entries(&report);
        assert_eq!(
            entries.len(),
            1,
            "only the false alarm, never the accepted risk"
        );
        let (_, url) = &entries[0];
        assert!(url.contains("rule=ast.sql-built-by-hand"));
        // Neither the file nor the owner's reason leaves in the link.
        assert!(
            !url.contains("billing") && !url.contains("secret-project"),
            "{url}"
        );
        assert!(!url.contains("integer"), "{url}");
        let html = sv_report::html::page(&report);
        let security = sv_report::markdown::security(&report);
        assert!(html.contains("Report it against the rule</a>"), "{html}");
        assert!(html.contains(&format!("href=\"{}\"", sv_report::html::escape(url))));
        assert!(security.contains(&format!("[Report it against the rule]({url})")));
        for page in [&html, &security] {
            assert!(
                page.contains("usually a rule that will misfire"),
                "the why is said"
            );
        }
    }

    #[test]
    fn the_tool_is_told_to_offer_the_link_and_never_file_it() {
        let note = sv_report::FALSE_ALARM_TOOL_NOTE;
        for needed in [
            "offer the person the link",
            "never file it yourself",
            "never paste their code or a key",
        ] {
            assert!(note.contains(needed), "{note}");
        }
    }

    #[test]
    fn the_form_has_the_fields_sv_fills() {
        // The same promise from the form's side: a field renamed there is caught here too.
        let form = form();
        assert!(
            form.contains("    id: rule\n") && form.contains("    id: finding\n"),
            "{form}"
        );
        assert!(form.contains("name: A false alarm"));
    }

    #[test]
    fn an_accepted_risk_is_not_offered_as_a_false_alarm() {
        let report = report_with_a_false_alarm("app.py");
        let security = sv_report::markdown::security(&report);
        assert_eq!(security.matches("Report it against the rule").count(), 1);
        assert!(!security.contains("rule=ast.weak-hash-function"));
    }
}

#[test]
fn a_suite_stopped_for_time_is_said_to_have_been_stopped_not_to_have_failed() {
    use sv_report::RunStatus;
    let stopped = sv_check::suite::FailingOutput {
        stopped_after: Some("10 minutes".to_owned()),
        ..failing("still waiting for the database", 1, 1, 0)
    };
    let intro = sv_report::test_output_intro(&stopped);
    assert!(
        intro.contains("had not finished after 10 minutes") && !intro.contains("failed"),
        "{intro}"
    );
    // The control: the same output, not stopped, is a failure.
    let failed = sv_report::test_output_intro(&failing("still waiting for the database", 1, 1, 0));
    assert!(failed.contains("failed"), "{failed}");

    let line = RunStatus::Started {
        image: "node:22-alpine".into(),
        asked: 3,
        answered: 3,
        signed_in: false,
        tests: "stopped".into(),
    }
    .line();
    assert!(
        line.contains("were stopped") && line.contains("credit nothing"),
        "{line}"
    );
}
