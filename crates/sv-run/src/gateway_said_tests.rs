//! A fence check that could not run says why, in Docker's own words (backlog 0226). Until 9 October
//! 2026 it said only "the check did not run", and `main` stayed red for hours with the cause hidden.

use super::*;

fn why(out: &str, code: i32) -> String {
    match gateway_verdict(out, code) {
        GatewayVerdict::Unknown(why) => why,
        other => panic!("a check that never reported was read as {other:?}"),
    }
}

#[test]
fn a_knock_that_never_started_says_what_docker_said_and_how_it_ended() {
    let pulled = "Unable to find image 'busybox:1.36' locally\n\
                  docker: Error response from daemon: toomanyrequests: You have reached your \
                  unauthenticated pull rate limit.\n\
                  See 'docker run --help'.\n";
    let said = why(pulled, 125);
    assert!(said.starts_with("the check did not run"), "{said}");
    assert!(said.contains("toomanyrequests"), "{said}");
    assert!(said.contains("exit 125"), "{said}");
}

#[test]
fn a_knock_that_printed_nothing_says_so() {
    let said = why("", 1);
    assert!(said.contains("it printed nothing"), "{said}");
    assert!(said.contains("exit 1"), "{said}");
}

#[test]
fn what_it_printed_is_kept_short() {
    let long = format!("docker: Error response from daemon: {}\n", "x".repeat(2000));
    let said = why(&long, 125);
    assert!(
        said.chars().count() < 400,
        "{} characters",
        said.chars().count()
    );
    assert!(said.contains('…'), "{said}");
}
