//! The report's timings: the stages, then each outside tool, then each suite of questions to the
//! running app, each named so the total counts it once (backlog 226, part 2, item 13).

use super::*;

#[test]
fn each_suite_follows_the_stages_named_as_the_running_app_s() {
    let start = std::time::Instant::now();
    let later = start + std::time::Duration::from_millis(40);
    let began = [
        ("Reading the app's files", start),
        ("Putting the report together", later),
    ];
    let suites = [
        ("the questions asked as somebody not signed in", 1_200),
        ("the app's own tests", 3_400),
    ];
    let got = timings(&began, later, &[], &suites);
    let named: Vec<(&str, u64)> = got.iter().map(|t| (t.what.as_str(), t.took_ms)).collect();
    assert_eq!(
        named,
        [
            ("Reading the app's files", 40),
            ("Putting the report together", 0),
            (
                "the running app, the questions asked as somebody not signed in",
                1_200
            ),
            ("the running app, the app's own tests", 3_400),
        ]
    );
}
