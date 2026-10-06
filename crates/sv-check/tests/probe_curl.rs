//! `sv probe`'s requests as curl receives them, through a stand-in `curl` first on the PATH that
//! writes down its arguments and answers with a redirect. A binary of its own, so the PATH it sets
//! is read by nothing else.

use sv_check::production::{Curl, Fetch, MOST_REQUESTS_WITH_API, read_target};

#[cfg(unix)]
#[test]
fn the_api_question_asks_as_a_program_and_the_cap_holds_at_five() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("sv-probe-curl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("args.log");
    let curl = dir.join("curl");
    std::fs::write(
        &curl,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '{}'; done\necho '--' >> '{}'\n\
             printf 'HTTP/1.1 301 Moved\\r\\nlocation: https://example.test/api/health\\r\\n\\r\\n'\n",
            log.display(),
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // SAFETY: the only test in this binary, and no thread of its own has started.
    unsafe { std::env::set_var("PATH", path) };

    let target = read_target("https://example.test")
        .unwrap()
        .with_api("/api/health")
        .unwrap();
    let api = target.api.clone().unwrap();
    let mut http = Curl::held_to(&target, &["203.0.113.7".parse().unwrap()]);
    let answer = http.get_as_program(&api);
    assert_eq!(answer.status, 301, "{answer:?}");
    let first = std::fs::read_to_string(&log).unwrap();
    let args: Vec<&str> = first.lines().take_while(|l| *l != "--").collect();
    let at = args
        .iter()
        .position(|a| *a == "--header")
        .unwrap_or_else(|| panic!("{args:?}"));
    assert_eq!(args[at + 1], "Accept: application/json");
    assert_eq!(args.last(), Some(&"http://example.test/api/health"));
    assert!(args.contains(&"--head"), "{args:?}");
    // The plain question of a browser carries no such header.
    std::fs::remove_file(&log).unwrap();
    http.get("http://example.test/", true);
    let second = std::fs::read_to_string(&log).unwrap();
    assert!(!second.contains("Accept: application/json"), "{second}");

    // Two made; three more reach curl, and the sixth is refused before it does.
    for _ in 0..3 {
        assert!(http.get("https://example.test/", true).failure.is_none());
    }
    let sixth = http.get("https://example.test/", true);
    assert!(
        sixth
            .failure
            .as_deref()
            .is_some_and(|f| f.contains(&format!("at most {MOST_REQUESTS_WITH_API}"))),
        "{sixth:?}"
    );
    let made = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .filter(|l| *l == "--")
        .count();
    assert_eq!(
        made, 4,
        "one browser question and three more after the log was cleared"
    );
    std::fs::remove_dir_all(&dir).ok();
}
