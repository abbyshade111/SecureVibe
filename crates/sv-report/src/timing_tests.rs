//! The slowest parts of a run name a suite of questions to the running app, and the total counts
//! its time once, inside the stage that ran the app (backlog 226, part 2, item 13).

use super::*;

fn timing(what: &str, took_ms: u64) -> Timing {
    Timing {
        what: what.to_owned(),
        took_ms,
    }
}

#[test]
fn a_suite_is_named_among_the_slowest_and_not_counted_twice_in_the_total() {
    let timings = [
        timing("Reading the app's files", 500),
        timing("Running the app, when asked with --run", 9_000),
        timing(
            &format!("{SUITE_TIMING}the questions asked as the test users"),
            7_000,
        ),
        timing(&format!("{TOOL_TIMING}Bandit"), 1_000),
    ];
    let line = slowest_of(&timings).unwrap();
    // The total is the stages': the suite and the tool ran inside them.
    assert!(line.starts_with("This run took 9.5 s."), "{line}");
    assert!(
        line.contains("the running app, the questions asked as the test users (7.0 s)"),
        "{line}"
    );
}

#[test]
fn no_timings_says_nothing() {
    assert_eq!(slowest_of(&[]), None);
}
