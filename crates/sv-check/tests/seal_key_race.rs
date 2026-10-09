//! Two runs making the report key at once (found 9 October 2026, when the MCP server's resource tests
//! failed one run in six): every run comes away with the same key, one of them made it, and nothing
//! of the attempt is left beside it. Before the fix the second `create_new` failed, so that run's
//! report was left unsealed and was not offered as `sv`'s.

use std::sync::{Arc, Barrier};
use sv_check::seal::Key;

const RUNS: usize = 16;
const ROUNDS: usize = 20;

#[test]
fn runs_that_make_the_key_at_once_all_get_the_one_that_was_made() {
    for round in 0..ROUNDS {
        let folder =
            std::env::temp_dir().join(format!("sv-key-race-{}-{round}", std::process::id()));
        std::fs::remove_dir_all(&folder).ok();
        let start = Arc::new(Barrier::new(RUNS));
        let runs: Vec<_> = (0..RUNS)
            .map(|_| {
                let (folder, start) = (folder.clone(), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    Key::load_or_make_named(&folder, "report-key")
                })
            })
            .collect();
        let got: Vec<_> = runs.into_iter().map(|r| r.join().unwrap()).collect();
        let on_disk = Key::load_named(&folder, "report-key")
            .unwrap()
            .expect("a key was made");
        let left: Vec<_> = std::fs::read_dir(&folder)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        std::fs::remove_dir_all(&folder).ok();
        let mut made = 0;
        for result in got {
            let (key, new) =
                result.unwrap_or_else(|why| panic!("round {round}: a run failed: {why}"));
            assert_eq!(
                key.id(),
                on_disk.id(),
                "round {round}: a run got a key that is not the one kept"
            );
            made += usize::from(new);
        }
        assert_eq!(made, 1, "round {round}: exactly one run made the key");
        assert_eq!(
            left,
            vec!["report-key".to_owned()],
            "round {round}: the attempt left files behind"
        );
    }
}

#[test]
fn a_key_already_there_is_used_and_not_made_again() {
    // The control: with no race, the first call makes it and the second reads it.
    let folder = std::env::temp_dir().join(format!("sv-key-once-{}", std::process::id()));
    std::fs::remove_dir_all(&folder).ok();
    let (first, made) = Key::load_or_make_named(&folder, "report-key").unwrap();
    let (second, again) = Key::load_or_make_named(&folder, "report-key").unwrap();
    std::fs::remove_dir_all(&folder).ok();
    assert!(made && !again);
    assert_eq!(first.id(), second.id());
}
