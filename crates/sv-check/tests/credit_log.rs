//! The census of credits (`tools/coverage.py --credits`) is only as good as the line each credit
//! writes. This test is a binary of its own, so the one variable it sets is read by nothing else.

/// A credit names its check, its requirements, and the place that gave it: here, this file, which is
/// a test and so left out of the census. The check named is one that only ever raises a finding, so a
/// census that counted credits built by tests would fail on this one in CI.
#[test]
fn a_credit_is_written_down_with_the_place_that_gave_it() {
    let dir = std::env::temp_dir().join(format!("sv-credit-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mine = dir.join("credits.log");
    let ci = std::env::var_os("SV_CREDIT_LOG");
    // SAFETY: the only test in this binary, and no thread of its own has started.
    unsafe { std::env::set_var("SV_CREDIT_LOG", &mine) };
    let line = line!() + 1;
    sv_check::Verified::new(
        "probe.password-hints",
        &["V6.4.2"],
        "a test's own".to_owned(),
    );
    let written = std::fs::read_to_string(&mine).unwrap();
    assert_eq!(
        written,
        format!("probe.password-hints\tV6.4.2\t{}:{line}\n", file!())
    );
    // And into the suite's own log, when there is one, for the census to leave out.
    if let Some(ci) = ci {
        unsafe { std::env::set_var("SV_CREDIT_LOG", ci) };
        sv_check::Verified::new(
            "probe.password-hints",
            &["V6.4.2"],
            "a test's own".to_owned(),
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
