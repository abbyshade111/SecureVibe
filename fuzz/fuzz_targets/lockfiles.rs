//! A lockfile an app ships, read as every format `sv` reads one in, and the app's own test report
//! (JUnit XML, TAP, or JSON).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        sv_check::sbom::read_as_every_lockfile(text);
        let _ = sv_check::test_report::parse(text);
        let _ = sv_check::junit::parse(text);
    }
});
