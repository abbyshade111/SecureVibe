//! When the fence's gateway check does not run, the report says what Docker said (backlog 0120).

use super::*;

#[test]
fn a_check_that_did_not_run_says_what_docker_said() {
    let out = "Unable to find image 'busybox:1.36' locally\n\
               docker: Error response from daemon: toomanyrequests: You have reached your pull rate limit.\n\
               \n";
    let GatewayVerdict::Unknown(why) = gateway_verdict(out) else {
        panic!("a check that never ran was given a verdict");
    };
    assert!(
        why.starts_with("the check did not run; Docker said: "),
        "{why}"
    );
    assert!(
        why.ends_with("You have reached your pull rate limit."),
        "{why}"
    );
    assert!(
        !why.contains("Unable to find image"),
        "only the last line: {why}"
    );
}

#[test]
fn silence_is_said_as_no_detail() {
    assert_eq!(
        gateway_verdict("\n  \n"),
        GatewayVerdict::Unknown("the check did not run; Docker said: no detail".to_owned())
    );
}
