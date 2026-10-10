//! The lines a log check reads its conclusions from are kept, each with what it was read for, and
//! the last lines of the output with them (ADR-082, backlog 0229, part 3).

use super::*;

fn markers() -> Markers {
    Markers {
        failed_sign_in: Some("sv-log-nobody-4a91@example.test".into()),
        successful_sign_in: Some("sv-log-ok-4a91@example.test".into()),
        refused_requests: vec![("sv-log-refused-4a91".into(), 403)],
        ..Default::default()
    }
}

const LOG: &str = "\
starting on :8000
time=2026-09-26T10:00:01Z level=warn event=sign-in-failed account=sv-log-nobody-4a91@example.test from=10.0.0.7
2026-09-26T10:00:02Z auth: sign-in ok for sv-log-ok-4a91@example.test
2026-09-26T10:00:03Z GET /account?sv-log-refused-4a91=1 403 anonymous
";

#[test]
fn each_line_a_conclusion_rests_on_is_kept_with_what_it_was_read_for() {
    let o = evaluate(&markers(), LOG);
    let kept: Vec<(&str, &str)> = o
        .lines
        .iter()
        .map(|k| (k.read_for.as_str(), k.line.as_str()))
        .collect();
    assert_eq!(kept.len(), 3, "{kept:#?}");
    assert!(kept[0].0.starts_with("the failed sign-in") && kept[0].1.contains("sign-in-failed"));
    assert!(kept[1].0.starts_with("the successful sign-in") && kept[1].1.contains("sign-in ok"));
    assert!(kept[2].0.contains("answered 403 (V16.3.2)") && kept[2].1.contains("GET /account"));
    // A line no conclusion rests on is not among them.
    assert!(kept.iter().all(|(_, l)| !l.contains("starting on")));
}

#[test]
fn a_line_is_kept_when_the_check_it_was_read_for_withholds_credit() {
    // The refused request reached the log without its status: not credited, and the line is what
    // a person needs to see why.
    let o = evaluate(&markers(), "GET /account?sv-log-refused-4a91=1\n");
    assert!(o.verified.is_empty(), "{o:?}");
    assert_eq!(o.lines.len(), 1, "{o:?}");
    assert_eq!(o.lines[0].line, "GET /account?sv-log-refused-4a91=1");
}

#[test]
fn the_tail_is_the_last_lines_and_no_more() {
    let log: String = (0..TAIL + 5).map(|i| format!("line {i}\n")).collect();
    let t = tail(&log);
    assert_eq!(t.len(), TAIL);
    assert_eq!(t[0], "line 5");
    assert_eq!(t.last().unwrap(), &format!("line {}", TAIL + 4));
    assert_eq!(tail("one\ntwo\n"), ["one", "two"]);
}
