//! The page says when kept runs could not be read (backlog 226, part 1, item 8).

use super::*;

#[test]
fn the_page_says_how_many_kept_runs_it_could_not_read() {
    assert_eq!(over_time(&[], 0), "");
    let only_unread = over_time(&[], 2);
    assert!(only_unread.contains("<h3>Over time</h3>"), "{only_unread}");
    assert!(
        only_unread.contains("2 files in this app's history could not be read as runs"),
        "{only_unread}"
    );
    let run = Run {
        format: 1,
        started: "2026-10-09T10:00:00Z".to_owned(),
        ..Run::default()
    };
    let one = over_time(std::slice::from_ref(&run), 1);
    assert!(
        one.contains("One file in this app's history could not be read"),
        "{one}"
    );
    assert!(!over_time(&[run], 0).contains("could not be read"));
}
